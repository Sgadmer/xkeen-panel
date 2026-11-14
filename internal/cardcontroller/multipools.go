package cardcontroller

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

const poolsKey = "x-xkeen-panel-multipools"

type PoolSpec struct {
	Name            string       `json:"name" yaml:"name"`
	SourceIDs       []string     `json:"source_ids" yaml:"source_ids"`
	Countries       []string     `json:"countries" yaml:"countries"`
	IncludeFiltered *bool        `json:"include_filtered,omitempty" yaml:"include_filtered,omitempty"`
	Members         []PoolMember `json:"members,omitempty" yaml:"members,omitempty"`
}

type PoolMember struct {
	SourceID string `json:"source_id" yaml:"source_id"`
	TargetID string `json:"target_id" yaml:"target_id"`
}

type MultiPool struct {
	ID            string `json:"id" yaml:"id"`
	PoolSpec      `yaml:",inline"`
	MemberCount   int `json:"member_count" yaml:"-"`
	EligibleCount int `json:"eligible_count" yaml:"-"`
	limit         int
}

func readPools(doc map[string]interface{}) ([]MultiPool, error) {
	pools := []MultiPool{}
	value, present := doc[poolsKey]
	if !present {
		return pools, nil
	}
	raw, err := json.Marshal(value)
	if err != nil || json.Unmarshal(raw, &pools) != nil || pools == nil || len(pools) > 32 {
		return nil, errors.New("повреждён список мультипулов")
	}
	seen := map[string]bool{}
	for _, pool := range pools {
		// A missing selector would turn a damaged fixed pool into "all".
		// Store empty lists explicitly when that is the user's choice.
		if !validHash(pool.ID) || seen[pool.ID] || pool.Name == "" || pool.SourceIDs == nil || pool.Countries == nil {
			return nil, errors.New("повреждён мультипул")
		}
		seen[pool.ID] = true
	}
	return pools, nil
}

// Group eligibility by the complete outbound identity. A blocked alias must
// never reintroduce the same VPN endpoint under a different country or name.
type poolNode struct {
	id      string
	server  models.Server
	allowed bool
}

func (c *Controller) poolNodes(servers []models.Server) []poolNode {
	filter := c.avoidCountries != nil && len(c.avoidCountries()) > 0
	denied := map[string]bool{}
	nodes := make([]poolNode, 0, len(servers))
	for _, s := range servers {
		if len(s.RawProfile) != 0 {
			continue
		}
		id := xkeen.ServiceTargetID(s)
		if id != "" && filter && (c.autoAllowed == nil || !c.autoAllowed(s)) {
			denied[id] = true
		}
		// Keep unsupported subscription entries for the country catalogue only.
		nodes = append(nodes, poolNode{id: id, server: s})
	}
	for i := range nodes {
		nodes[i].allowed = nodes[i].id != "" && !denied[nodes[i].id]
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		a, b := nodes[i], nodes[j]
		ai, bi := probeRank(a.server), probeRank(b.server)
		if ai != bi {
			return ai < bi
		}
		if ai == 0 && a.server.Latency != b.server.Latency {
			return a.server.Latency < b.server.Latency
		}
		if a.id != b.id {
			return a.id < b.id
		}
		return a.server.ID < b.server.ID
	})
	return nodes
}

func probeRank(s models.Server) int {
	if s.ProbeKind == "https" && s.Latency < 0 {
		return 2
	}
	if s.Latency > 0 || s.ProbeKind == "https" {
		return 0
	}
	return 1
}

func memberKey(n poolNode) PoolMember {
	source := n.server.SourceID
	if source == "" {
		source = "legacy"
	}
	return PoolMember{SourceID: source, TargetID: n.id}
}

func (pool *MultiPool) members(nodes []poolNode) []models.Server {
	result := []models.Server{}
	pool.EligibleCount = 0
	seen := map[string]bool{}
	explicit := map[PoolMember]bool{}
	for _, ref := range pool.Members {
		explicit[ref] = true
	}
	limit := xkeen.MaxMultiPoolMembers
	if pool.ID == allPoolID {
		limit = normalizeAutoLimit(pool.limit)
	}
	for _, n := range nodes {
		if !n.allowed || seen[n.id] || probeRank(n.server) == 2 && pool.ID == allPoolID {
			continue
		}
		member := memberKey(n)
		include := pool.IncludeFiltered == nil || *pool.IncludeFiltered
		if !explicit[member] && (!include || len(pool.SourceIDs) > 0 && !slices.Contains(pool.SourceIDs, member.SourceID) ||
			len(pool.Countries) > 0 && !slices.Contains(pool.Countries, strings.ToUpper(xkeen.ServerCountry(n.server)))) {
			continue
		}
		seen[n.id] = true
		pool.EligibleCount++
		if len(result) < limit {
			result = append(result, n.server)
		}
	}
	pool.MemberCount = len(result)
	return result
}

func (c *Controller) MultiPools() ([]MultiPool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return nil, err
	}
	if len(p.pools) != 0 {
		nodes := c.poolNodes(c.catalog())
		for i := range p.pools {
			p.pools[i].members(nodes)
		}
	}
	return p.pools, nil
}

func (p profile) pool(id string) *MultiPool {
	for i := range p.pools {
		if p.pools[i].ID == id {
			return &p.pools[i]
		}
	}
	pool := builtinPool(id)
	if id == allPoolID {
		pool.limit = normalizeAutoLimit(p.autoLimit)
	}
	return pool
}

func (p profile) endpointName(id, name string) bool {
	if p.pool(id) == nil {
		return name == nodePrefix+id
	}
	generation, ok := strings.CutPrefix(name, nodePrefix+id+"-")
	if !ok || !validHash(generation) {
		return false
	}
	for _, raw := range list(p.doc["proxies"]) {
		if str(object(raw)["name"]) == name {
			return true
		}
	}
	return false
}

func normalizeSpec(spec PoolSpec, knownIDs, previous []string) (PoolSpec, error) {
	spec.Name = strings.TrimSpace(spec.Name)
	if spec.Name == "" || utf8.RuneCountInString(spec.Name) > 64 || strings.IndexFunc(spec.Name, unicode.IsControl) != -1 {
		return spec, errors.New("укажите название мультипула длиной до 64 символов")
	}
	if spec.SourceIDs == nil {
		spec.SourceIDs = []string{}
	}
	if spec.Countries == nil {
		spec.Countries = []string{}
	}
	for _, source := range spec.SourceIDs {
		if source == "" || !slices.Contains(knownIDs, source) && !slices.Contains(previous, source) {
			return spec, errors.New("выбранная подписка отсутствует")
		}
	}
	for i, country := range spec.Countries {
		country = strings.ToUpper(strings.TrimSpace(country))
		if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
			return spec, errors.New("ожидался двухбуквенный код страны")
		}
		spec.Countries[i] = country
	}
	sort.Strings(spec.SourceIDs)
	sort.Strings(spec.Countries)
	spec.SourceIDs = slices.Compact(spec.SourceIDs)
	spec.Countries = slices.Compact(spec.Countries)
	return spec, nil
}

// EditMultiPool keeps the definition and routes in a single atomic profile.
// Editing an inactive pool only writes metadata. An active change takes the
// same tested reload/rollback path as changing a service assignment.
func (c *Controller) EditMultiPool(ctx context.Context, id string, spec *PoolSpec, sources []string) (MultiPool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return MultiPool{}, err
	}
	if builtinPool(id) != nil {
		return MultiPool{}, errors.New("встроенный пул нельзя изменить")
	}
	pool := p.pool(id)
	if id != "" && pool == nil {
		return MultiPool{}, errors.New("мультипул не найден")
	}
	if id == "" {
		if spec == nil || len(p.pools) >= 32 {
			return MultiPool{}, errors.New("достигнут предел в 32 мультипула")
		}
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			return MultiPool{}, err
		}
		id = hex.EncodeToString(key[:])
		p.pools = append(p.pools, MultiPool{ID: id})
		pool = &p.pools[len(p.pools)-1]
	}
	used := false
	for _, assigned := range p.assigned {
		if assigned == id {
			used = true
			break
		}
	}
	var result MultiPool
	if spec == nil {
		if used {
			return result, errors.New("сначала смените этот мультипул в маршрутах сервисов или в основном маршруте")
		}
		p.pools = slices.DeleteFunc(p.pools, func(item MultiPool) bool { return item.ID == id })
	} else {
		clean, err := normalizeSpec(*spec, sources, pool.SourceIDs)
		if err != nil {
			return result, err
		}
		nodes := c.poolNodes(c.catalog())
		known := make(map[PoolMember]bool)
		for _, ref := range pool.Members {
			known[ref] = true
		}
		for _, n := range nodes {
			known[memberKey(n)] = true
		}
		if len(clean.Members) > xkeen.MaxMultiPoolMembers {
			return result, errors.New("слишком много отдельных конфигураций в мультипуле")
		}
		seen := make(map[PoolMember]bool)
		unique := make([]PoolMember, 0, len(clean.Members))
		for _, member := range clean.Members {
			if !validHash(member.TargetID) || member.SourceID == "" || !known[member] {
				return result, errors.New("одна из выбранных конфигураций отсутствует в подписке")
			}
			if !seen[member] {
				unique = append(unique, member)
				seen[member] = true
			}
		}
		clean.Members = unique
		if clean.IncludeFiltered != nil && !*clean.IncludeFiltered && len(clean.Members) == 0 {
			return result, errors.New("выберите хотя бы одну конфигурацию")
		}
		for _, other := range p.pools {
			if other.ID != id && strings.EqualFold(other.Name, clean.Name) {
				return result, errors.New("мультипул с таким названием уже существует")
			}
		}
		pool.PoolSpec = clean
		result = *pool
		result.members(nodes)
	}
	write := func(next *profile) error {
		if !bytes.Equal(next.raw, p.raw) {
			return errors.New("конфигурация изменилась параллельно")
		}
		next.pools = p.pools
		if spec == nil && str(next.doc[autoScopeKey]) == id {
			delete(next.doc, autoScopeKey)
		}
		if len(next.pools) == 0 {
			delete(next.doc, poolsKey)
		} else {
			next.doc[poolsKey] = next.pools
		}
		return nil
	}
	if used {
		_, err = c.apply(ctx, "", "", write)
		return result, err
	}
	if err = write(&p); err != nil {
		return result, err
	}
	return result, c.savePoolMetadata(p)
}

// Inactive pool edits only change private panel metadata. Keep the current
// kernel and selectors in place and compare the original file before replacing it.
func (c *Controller) savePoolMetadata(p profile) error {
	raw, err := yaml.Marshal(p.doc)
	if err != nil {
		return err
	}
	path, err := stage(filepath.Dir(c.path), raw)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	current, err := os.ReadFile(c.path)
	if err != nil || !bytes.Equal(current, p.raw) {
		return errors.New("конфигурация изменилась параллельно")
	}
	return os.Rename(path, c.path)
}
