package cardcontroller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

const autoScopeKey = "x-xkeen-panel-auto-scope"
const autoLimitKey = "x-xkeen-panel-auto-limit"

func scopeHash(key string) string {
	sum := sha256.Sum256([]byte("xkeen-panel-scope-v1:" + key))
	return hex.EncodeToString(sum[:])
}

var allPoolID = scopeHash("all")

// Keep the identity of an assigned country pool even after its last server
// disappears. Rendering an empty pool then produces the existing REJECT guard.
var countryPoolCodes = func() map[string]string {
	result := make(map[string]string, 26*26)
	for a := 'A'; a <= 'Z'; a++ {
		for b := 'A'; b <= 'Z'; b++ {
			code := string([]rune{a, b})
			result[scopeHash("country:"+code)] = code
		}
	}
	return result
}()

func builtinPool(id string) *MultiPool {
	if id == allPoolID {
		return &MultiPool{ID: id, PoolSpec: PoolSpec{Name: "Все локации"}}
	}
	if code, ok := countryPoolCodes[id]; ok {
		return &MultiPool{ID: id, PoolSpec: PoolSpec{Name: code, Countries: []string{code}}}
	}
	return nil
}

type AutoScope struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Kind              string `json:"kind"`
	Country           string `json:"country,omitempty"`
	MemberCount       int    `json:"member_count"`
	EligibleCount     int    `json:"eligible_count"`
	Limit             int    `json:"limit,omitempty"`
	CatalogCount      *int   `json:"catalog_count,omitempty"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

func scopes(p profile, nodes []poolNode) []AutoScope {
	byCountry := make(map[string][]poolNode)
	for _, node := range nodes {
		code := strings.ToUpper(xkeen.AutoPoolCountry(node.server))
		if len(code) == 2 {
			byCountry[code] = append(byCountry[code], node)
		}
	}
	keepAssigned := func(id string) {
		if code := countryPoolCodes[id]; code != "" && byCountry[code] == nil {
			byCountry[code] = nil
		}
	}
	for _, id := range p.assigned {
		keepAssigned(id)
	}
	keepAssigned(p.scopeID())
	countries := make([]string, 0, len(byCountry))
	for code := range byCountry {
		if countryPoolCodes[scopeHash("country:"+code)] == code {
			countries = append(countries, code)
		}
	}
	sort.Strings(countries)
	all := p.pool(allPoolID)
	all.members(nodes)
	result := []AutoScope{{ID: all.ID, Name: all.Name, Kind: "all", MemberCount: all.MemberCount, EligibleCount: all.EligibleCount, Limit: all.limit}}
	for _, code := range countries {
		result = append(result, countryScope(code, byCountry[code]))
	}
	for _, pool := range p.pools {
		pool.members(nodes)
		result = append(result, AutoScope{ID: pool.ID, Name: pool.Name, Kind: "custom", MemberCount: pool.MemberCount, EligibleCount: pool.EligibleCount})
	}
	return result
}

func countryScope(code string, nodes []poolNode) AutoScope {
	pool := builtinPool(scopeHash("country:" + code))
	pool.members(nodes)
	configs := make(map[string]bool)
	unsupported := 0
	for _, node := range nodes {
		if node.id == "" {
			unsupported++
		} else {
			configs[node.id] = true
		}
	}
	count := len(configs) + unsupported
	scope := AutoScope{ID: pool.ID, Name: pool.Name, Kind: "country", Country: code,
		MemberCount: pool.MemberCount, EligibleCount: pool.EligibleCount, CatalogCount: &count}
	if scope.MemberCount == 0 {
		switch {
		case len(configs) > 0:
			scope.UnavailableReason = "country_filter"
		case unsupported > 0:
			scope.UnavailableReason = "unsupported"
		default:
			scope.UnavailableReason = "no_servers"
		}
	}
	return scope
}

func (p profile) scopeID() string {
	if id := str(p.doc[autoScopeKey]); id != "" {
		return id
	}
	// Older panels could already use an explicitly selected custom multipool.
	if id := p.assigned[defaultID]; p.pool(id) != nil {
		return id
	}
	return allPoolID
}

func (c *Controller) PoolCatalog() ([]MultiPool, []AutoScope, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return nil, nil, err
	}
	nodes := c.poolNodes(c.catalog())
	for i := range p.pools {
		p.pools[i].members(nodes)
	}
	return p.pools, scopes(p, nodes), nil
}

func (c *Controller) SetScope(ctx context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.setScope(ctx, id)
}

func validAutoLimit(n int) bool { return n >= 1 && n <= xkeen.MaxMultiPoolMembers }

func normalizeAutoLimit(n int) int {
	if n <= 0 {
		return xkeen.DefaultPoolMaxNodes
	}
	return min(n, xkeen.MaxMultiPoolMembers)
}

func (c *Controller) ChangeAutoPoolLimit(ctx context.Context, n int) error {
	if !validAutoLimit(n) {
		return errors.New("недопустимый размер пула")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return err
	}
	if p.autoLimit == n {
		return nil
	}
	previous := p.pool(allPoolID)
	p.doc[autoLimitKey], p.autoLimit = n, n
	for _, id := range p.assigned {
		if id != allPoolID {
			continue
		}
		nodes := c.poolNodes(c.catalog())
		// Both selections are prefixes of the same ranking. Equal sizes mean
		// that only the setting changed and the existing worker can stay live.
		if len(previous.members(nodes)) != len(p.pool(allPoolID).members(nodes)) {
			// Setting a required target without a service changes no assignments
			// and makes preparation of the replacement worker mandatory.
			_, err = c.apply(ctx, "", allPoolID, func(next *profile) error {
				if !bytes.Equal(next.raw, p.raw) {
					return errors.New("конфигурация изменилась параллельно")
				}
				next.doc[autoLimitKey], next.autoLimit = n, n
				return nil
			})
			return err
		}
		break
	}
	return c.savePoolMetadata(p)
}

func (c *Controller) setScope(ctx context.Context, id string) error {
	p, err := c.read()
	if err != nil {
		return err
	}
	if id == "" {
		id = p.scopeID()
	}
	pool := p.pool(id)
	if pool == nil {
		return errors.New("пул не найден")
	}
	if len(pool.members(c.poolNodes(c.catalog()))) == 0 {
		return errors.New("в выбранном пуле нет доступных узлов")
	}
	result, err := c.apply(ctx, defaultID, id, func(next *profile) error {
		next.doc[autoScopeKey] = id
		delete(next.doc, defaultSourceKey)
		delete(next.doc, replacementKey)
		return nil
	})
	if err != nil {
		return err
	}
	if !result.Active || c.pending[defaultID] {
		return errors.New("маршрут применён, завершение прежних соединений ещё не подтверждено")
	}
	return nil
}

func poolViews(servers []models.Server) []xkeen.PoolNodeView {
	result := make([]xkeen.PoolNodeView, 0, len(servers))
	for _, s := range servers {
		result = append(result, xkeen.PoolNodeView{Tag: xkeen.ServiceTargetID(s), ServerID: s.ID, Name: s.Name, Address: s.Address, Port: s.Port, Country: xkeen.AutoPoolCountry(s), Latency: s.Latency})
	}
	return result
}
