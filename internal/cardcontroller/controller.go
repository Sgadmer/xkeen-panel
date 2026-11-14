// Package cardcontroller manages the named service routes in an already
// running Mihomo instance using its authenticated loopback controller.
package cardcontroller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

type View struct {
	xkeen.ServiceRoutesView
	Scope                    string `json:"scope"`
	ControllerReady          bool   `json:"controller_ready"`
	ActiveConnectionsPending bool   `json:"active_connections_pending,omitempty"`
}

type Controller struct {
	mu                 sync.Mutex
	path               string
	stateDir           string
	rt                 xkeen.Runtime
	catalog            func() []models.Server
	http               *http.Client
	validate           func(context.Context, string) error
	prepare            func(xkeen.Runtime, string, models.Server) (xkeen.CardProxy, error)
	pending            map[string]bool
	avoidCountries     func() []string
	autoAllowed        func(models.Server) bool
	sourceProviderURLs func() map[string]string
	autoPoolLimit      int
}

// SetAutoPoolLimit uses the panel's existing router-wide capacity setting.
// Called once during setup before HTTP and monitoring start.
func (c *Controller) SetAutoPoolLimit(n int) { c.autoPoolLimit = n }

func New(configPath, stateDir string, rt xkeen.Runtime, catalog func() []models.Server) *Controller {
	// PrepareCardProxy owns its isolated runtime namespace and still has
	// access to the existing Xray asset directory and sibling executable.
	rt.MihomoConf = configPath
	c := &Controller{path: configPath, stateDir: stateDir, rt: rt, catalog: catalog, prepare: xkeen.PrepareCardProxy, pending: map[string]bool{}}
	c.http = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	c.validate = func(ctx context.Context, path string) error {
		cmd := exec.CommandContext(ctx, "/opt/sbin/mihomo", "-t", "-d", filepath.Dir(configPath), "-f", path)
		if cmd.Run() != nil {
			return errors.New("Mihomo отклонил конфигурацию карточек")
		}
		return nil
	}
	return c
}

type coreAPI struct {
	base, secret string
	client       *http.Client
}

func (a coreAPI) request(ctx context.Context, method, path string, body, result interface{}) error {
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.secret)
	req.Header.Set("Content-Type", "application/json")
	res, err := a.client.Do(req)
	if err != nil {
		return errors.New("локальный API Mihomo недоступен")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("локальный API Mihomo ответил HTTP %d", res.StatusCode)
	}
	if result != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 20<<20)).Decode(result)
	}
	return nil
}

type selector struct {
	Type string
	Now  string
	All  []string
}

func (a coreAPI) selectors(ctx context.Context) (map[string]selector, error) {
	var resp struct{ Proxies map[string]selector }
	if err := a.request(ctx, "GET", "/proxies", nil, &resp); err != nil {
		return nil, err
	}
	if resp.Proxies == nil {
		return nil, errors.New("контроллер не вернул маршруты")
	}
	return resp.Proxies, nil
}
func (a coreAPI) ruleMode(ctx context.Context) bool {
	var status struct{ Mode string }
	return a.request(ctx, "GET", "/configs", nil, &status) == nil && strings.EqualFold(status.Mode, "rule")
}
func (a coreAPI) reload(ctx context.Context, path string) error {
	return a.request(ctx, "PUT", "/configs?force=true", map[string]string{"path": path}, nil)
}

const stateKey = "x-xkeen-panel-routes"
const cardPrefix = "XKP-card-"
const nodePrefix = "XKP-endpoint-"
const directTarget = "direct"

func validAssignment(service, target string) bool {
	return validHash(target) || service != "claude" && target == directTarget
}

type profile struct {
	raw       []byte
	doc       map[string]interface{}
	assigned  map[string]string
	pools     []MultiPool
	autoLimit int
	api       coreAPI
}

func (c *Controller) read() (profile, error) {
	p := profile{assigned: map[string]string{}}
	st, err := os.Lstat(c.path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 32<<20 {
		return p, errors.New("обычный файл конфигурации Mihomo недоступен")
	}
	p.raw, err = os.ReadFile(c.path)
	if err != nil {
		return p, err
	}
	if err = yaml.Unmarshal(p.raw, &p.doc); err != nil || p.doc == nil {
		return p, errors.New("не удалось прочитать YAML Mihomo")
	}
	p.autoLimit = normalizeAutoLimit(c.autoPoolLimit)
	if value, present := p.doc[autoLimitKey]; present {
		n, ok := value.(int)
		if !ok || !validAutoLimit(n) {
			return p, errors.New("повреждён лимит пула «Все локации»")
		}
		p.autoLimit = n
	}
	addr, _ := p.doc["external-controller"].(string)
	host, port, err := net.SplitHostPort(addr)
	ip, e := netip.ParseAddr(host)
	secret, _ := p.doc["secret"].(string)
	if err != nil || e != nil || !ip.IsLoopback() || port == "" || secret == "" {
		return p, errors.New("нужен защищённый паролем локальный контроллер Mihomo")
	}
	if mode, _ := p.doc["mode"].(string); !strings.EqualFold(mode, "rule") {
		return p, errors.New("Mihomo должен работать в режиме правил")
	}
	p.pools, err = readPools(p.doc)
	if err != nil {
		return p, err
	}
	if raw, ok := p.doc[stateKey]; ok {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return p, errors.New("повреждены назначения карточек")
		}
		for id, v := range m {
			val, ok := v.(string)
			if !ok || !validAssignment(id, val) || groupNames[id] == "" && !(id == defaultID && validHash(val)) {
				return p, errors.New("повреждено назначение карточки")
			}
			p.assigned[id] = val
		}
	}
	p.api = coreAPI{"http://" + net.JoinHostPort(host, port), secret, c.http}
	return p, nil
}
func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, v := range s {
		if !(v >= 'a' && v <= 'f' || v >= '0' && v <= '9') {
			return false
		}
	}
	return true
}
func list(v interface{}) []interface{}            { a, _ := v.([]interface{}); return a }
func str(v interface{}) string                    { s, _ := v.(string); return s }
func object(v interface{}) map[string]interface{} { m, _ := v.(map[string]interface{}); return m }

func (c *Controller) View(ctx context.Context) (View, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.view(ctx)
}
func (c *Controller) view(ctx context.Context) (View, error) {
	p, err := c.read()
	if err != nil {
		return View{}, err
	}
	servers := c.catalog()
	view, err := xkeen.ReadServiceRoutes(c.rt, servers)
	if err != nil {
		return View{}, err
	}
	result := View{ServiceRoutesView: view, Scope: "mihomo", ActiveConnectionsPending: len(c.pending) > 0}
	for _, pool := range scopes(p, c.poolNodes(servers)) {
		result.Targets = append(result.Targets, xkeen.ServiceTarget{ID: pool.ID, Name: pool.Name, Kind: "pool", Country: pool.Country})
	}
	result.GuardReady = false // packet-level fail-closed is independently verified.
	live, err := p.api.selectors(ctx)
	result.ControllerReady = err == nil && p.api.ruleMode(ctx)
	var rules []liveRule
	if result.ControllerReady {
		rules, _ = p.api.rules(ctx)
	}
	_, managed := p.doc[stateKey]
	result.Active = managed && result.ControllerReady && activeRulesMatch(rules, p.doc)
	groupRoutes := inheritedGroups(rules)
	names := make(map[string]string, len(result.Targets))
	for _, t := range result.Targets {
		names[nodePrefix+t.ID] = t.Name
	}
	for _, value := range list(p.doc["proxies"]) {
		name := str(object(value)["name"])
		id, generation, found := strings.Cut(strings.TrimPrefix(name, nodePrefix), "-")
		if found && validHash(generation) {
			if pool := p.pool(id); pool != nil {
				names[name] = pool.Name
			}
		}
	}
	var providerNodes map[string]selector
	for i := range result.Services {
		s := &result.Services[i]
		s.Target = p.assigned[s.ID]
		s.Blocked = false
		if !managed || s.ID != "claude" && s.Target == "" {
			group := groupNames[s.ID]
			if !groupRoutes[group] && !(groupRoutes[cardPrefix+s.ID+"-inherited"] && live[cardPrefix+s.ID+"-inherited"].Now == group) {
				group = ""
			}
			s.InheritedRoute = inheritedRoute(group, live, names, func(name string) selector {
				if providerNodes == nil {
					providerNodes = p.api.providerNodes(ctx)
				}
				return providerNodes[name]
			})
			if group != "" {
				s.RouteName = publicRouteName(live[group].Now, names)
			}
			continue
		}
		group := live[cardPrefix+s.ID]
		s.Blocked = result.ControllerReady && len(group.All) == 1 && group.Now == "REJECT"
		target := nodePrefix + s.Target
		if s.Target == directTarget {
			target = "DIRECT"
		}
		matches := group.Now == target
		if s.Target != directTarget {
			matches = p.endpointName(s.Target, group.Now)
		}
		if len(group.All) != 1 || group.All[0] != group.Now || (!matches && !s.Blocked) {
			result.Active = false
		}
		if s.Blocked {
			s.RouteName = "REJECT"
		} else if target == "DIRECT" && group.Now == target {
			s.RouteName = "DIRECT"
		} else if matches {
			for _, t := range result.Targets {
				if t.ID == s.Target {
					s.RouteName = t.Name
					break
				}
			}
		}
	}
	return result, nil
}

// A dispatcher stop (including the stop phase of restart) removes the
// transparent interception rules. The managed profile always protects Claude,
// including when it has no selected endpoint and resolves to REJECT.
func (c *Controller) CheckCoreInterruption() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return err
	}
	if _, managed := p.doc[stateKey]; managed {
		return errors.New("остановка или перезапуск XKeen снимет перехват защищённых сервисов. Назначения серверов применяются без остановки ядра")
	}
	return nil
}

func (c *Controller) Set(ctx context.Context, id, target string) (View, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if groupNames[id] == "" || target != "" && !validAssignment(id, target) || id == "claude" && target == "" {
		return View{}, errors.New("недопустимый сервис или сервер")
	}
	return c.apply(ctx, id, target, nil)
}
func (c *Controller) Reconcile(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return err
	}
	// An existing manual or provider-specific choice stays owned by its
	// selector. Migrate only a positively identified, active automatic group.
	if p.assigned[defaultID] == "" && str(p.doc[autoScopeKey]) == "" && configuredAuto(p) {
		live, err := p.api.selectors(ctx)
		if err != nil {
			return err
		}
		group, auto := nativeDefault(p, live)
		if auto != "" && (group == auto || live[group].Now == auto) && len(p.pool(allPoolID).members(c.poolNodes(c.catalog()))) > 0 {
			return c.setScope(ctx, allPoolID)
		}
	}
	if _, enabled := p.doc[stateKey]; !enabled {
		return c.reconcileCountryGroups(ctx, p)
	}
	_, err = c.apply(ctx, "", "", nil)
	return err
}

func (c *Controller) apply(ctx context.Context, id, target string, withListener func(*profile) error) (View, error) {
	p, err := c.read()
	if err != nil {
		return View{}, err
	}
	if withListener != nil {
		if err = withListener(&p); err != nil {
			return View{}, err
		}
	}
	if !p.api.ruleMode(ctx) {
		return View{}, errors.New("локальный контроллер не подтверждает режим правил")
	}
	selections, err := p.api.selectors(ctx)
	if err != nil {
		return View{}, err
	}
	if id != "" {
		if target == "" {
			delete(p.assigned, id)
		} else {
			p.assigned[id] = target
		}
	}
	servers := c.catalog()
	catalog := map[string]models.Server{}
	requiredSource := str(p.doc[defaultSourceKey])
	defaultSourceAvailable := requiredSource == ""
	for _, s := range servers {
		if key := xkeen.ServiceTargetID(s); key != "" {
			catalog[key] = s
			if key == p.assigned[defaultID] && s.SourceID == requiredSource {
				defaultSourceAvailable = true
			}
		}
	}
	if target != "" && target != directTarget {
		if _, ok := catalog[target]; !ok && p.pool(target) == nil {
			return View{}, errors.New("сервер исчез из подписки")
		}
	}
	peers := map[string]cardEndpoint{}
	workers := map[string]xkeen.CardProxy{}
	var nodes []poolNode
	keys := []string{}
	for service, key := range p.assigned {
		if service == defaultID && !defaultSourceAvailable {
			continue
		}
		if key != directTarget {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for i, key := range keys {
		if i > 0 && key == keys[i-1] {
			continue
		}
		s, ok := catalog[key]
		workerID := key
		endpoint := nodePrefix + key
		if pool := p.pool(key); pool != nil {
			if nodes == nil {
				nodes = c.poolNodes(servers)
			}
			members := pool.members(nodes)
			if len(members) == 0 {
				continue
			}
			s, err = xkeen.MultiPoolProfile(members)
			if err != nil {
				return View{}, err
			}
			workerID = xkeen.ServiceTargetID(s)
			endpoint += "-" + workerID
			ok = true
		}
		if !ok {
			continue
		}
		peer, started := workers[workerID]
		if !started {
			peer, err = c.prepare(c.rt, workerID, s)
			if err != nil {
				if target == key {
					return View{}, errors.New("не удалось запустить выбранный защищённый маршрут")
				}
				continue
			}
			workers[workerID] = peer
		}
		peers[key] = cardEndpoint{CardProxy: peer, name: endpoint}
	}
	view, err := xkeen.ReadServiceRoutes(c.rt, servers)
	if err != nil {
		return View{}, err
	}
	expected, err := render(&p, view.Services, peers, defaultSourceAvailable)
	if err != nil {
		return View{}, err
	}
	// A metadata edit with a required target must not drop an unrelated,
	// currently working guarded route if its worker cannot be prepared.
	if id == "" && target != "" {
		for service, key := range p.assigned {
			group := cardPrefix + service
			if key != target && expected[group] == "REJECT" && strings.HasPrefix(selections[group].Now, nodePrefix) {
				return View{}, errors.New("не удалось сохранить другой действующий маршрут")
			}
		}
	}
	countryGroups, err := c.renderCountryFilter(&p, servers)
	if err != nil {
		return View{}, err
	}
	body, err := yaml.Marshal(p.doc)
	if err != nil {
		return View{}, errors.New("не удалось сериализовать правила")
	}
	// Compare decoded documents as well: a refresh should not rewrite merely
	// because the owner's indentation or ordering differs from yaml.Marshal.
	var original map[string]interface{}
	_ = yaml.Unmarshal(p.raw, &original)
	var candidate map[string]interface{}
	_ = yaml.Unmarshal(body, &candidate)
	if !reflect.DeepEqual(original, candidate) || !groupsReady(selections, expected) || !countryGroups.ready(selections, nil) || !p.api.rulesReady(ctx, candidate) {
		if err = c.install(ctx, p, body, candidate, selections, expected, countryGroups); err != nil {
			return View{}, err
		}
	}
	result, err := c.view(ctx)
	if err != nil {
		return View{}, err
	}
	for _, service := range view.Services {
		name := cardPrefix + service.ID
		want := expected[name]
		previous, exists := selections[name]
		if c.pending[service.ID] || (want != "" || exists) && (previous.Now != want || service.ID == id) {
			if !c.drain(ctx, p.api, service.ID, want, view.Services) {
				c.pending[service.ID] = true
			} else {
				delete(c.pending, service.ID)
			}
		}
	}
	want := expected[cardPrefix+defaultID]
	before := selections[cardPrefix+defaultID].Now
	if c.pending[defaultID] || before != want || id == defaultID {
		if c.drain(ctx, p.api, defaultID, want, nil) {
			delete(c.pending, defaultID)
		} else {
			c.pending[defaultID] = true
		}
	}
	result.ActiveConnectionsPending = len(c.pending) > 0
	if result.Active && !result.ActiveConnectionsPending {
		keep := map[string]bool{}
		for key := range workers {
			keep[key] = true
		}
		_ = xkeen.PruneCardProxies(c.rt, keep)
	}
	return result, nil
}

func stage(dir string, raw []byte) (string, error) {
	f, err := os.CreateTemp(dir, ".panel-card-*.yaml")
	if err != nil {
		return "", err
	}
	path := f.Name()
	defer f.Close()
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = f.Close()
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func groupsReady(live map[string]selector, expected map[string]string) bool {
	for name, v := range expected {
		g := live[name]
		if !strings.EqualFold(g.Type, "selector") || g.Now != v || len(g.All) != 1 || g.All[0] != v {
			return false
		}
	}
	return true
}
func restoreSelectors(ctx context.Context, a coreAPI, before, after map[string]selector) error {
	for name, g := range before {
		if strings.HasPrefix(name, cardPrefix) || !strings.EqualFold(g.Type, "selector") || g.Now == "" {
			continue
		}
		newGroup, exists := after[name]
		if !exists {
			return errors.New("исчезла исходная группа Mihomo")
		}
		if newGroup.Now != g.Now {
			if err := a.request(ctx, "PUT", "/proxies/"+url.PathEscape(name), map[string]string{"name": g.Now}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Controller) keepOriginal(raw []byte) error {
	if err := os.MkdirAll(c.stateDir, 0700); err != nil {
		return err
	}
	backup := filepath.Join(c.stateDir, "before-mihomo-service-routes.yaml")
	if info, err := os.Lstat(backup); err == nil {
		if info.Mode().IsRegular() {
			return nil
		}
		return errors.New("путь резервной конфигурации занят")
	} else if !os.IsNotExist(err) {
		return err
	}
	file, err := stage(c.stateDir, raw)
	if err != nil {
		return err
	}
	defer os.Remove(file)
	return os.Rename(file, backup)
}

// The controller's live rule list must start with exactly the managed groups
// compiled into this configuration, before any pre-existing direct rule.
func (a coreAPI) rulesReady(ctx context.Context, doc map[string]interface{}) bool {
	rules, err := a.rules(ctx)
	return err == nil && activeRulesMatch(rules, doc)
}

type liveRule struct {
	Type    string
	Proxy   string
	Payload string
	Extra   struct{ Disabled bool }
}

func (a coreAPI) rules(ctx context.Context) ([]liveRule, error) {
	var response struct {
		Rules []liveRule
	}
	err := a.request(ctx, "GET", "/rules", nil, &response)
	return response.Rules, err
}

func activeRulesMatch(rules []liveRule, doc map[string]interface{}) bool {
	count := 0
	entries, _, err := managedExclusions(doc)
	if err != nil {
		return false
	}
	manual := map[string]bool{}
	for _, e := range entries.Entries {
		manual[exclusionRule(e)] = true
	}
	for i, raw := range list(doc["rules"]) {
		parts, end := targetPart(str(raw))
		if end < 1 || !strings.HasPrefix(parts[end], cardPrefix) && !manual[str(raw)] {
			continue
		}
		if i >= len(rules) {
			return false
		}
		actual := rules[i]
		if actual.Proxy != parts[end] || actual.Extra.Disabled {
			return false
		}
		switch parts[0] {
		case "DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6":
			if !strings.EqualFold(actual.Payload, parts[1]) {
				return false
			}
		}
		count++
	}
	return count > 0
}

func (c *Controller) install(ctx context.Context, p profile, body []byte, candidate map[string]interface{}, selections map[string]selector, expected map[string]string, countryGroups autoCountryGroups) error {
	dir := filepath.Dir(c.path)
	next, err := stage(dir, body)
	if err != nil {
		return err
	}
	defer os.Remove(next)
	if err = c.validate(ctx, next); err != nil {
		return err
	}
	if _, managed := p.doc[stateKey]; managed {
		if err = c.keepOriginal(p.raw); err != nil {
			return errors.New("не удалось сохранить исходную конфигурацию Mihomo")
		}
	}
	prior, err := stage(dir, p.raw)
	if err != nil {
		return err
	}
	defer os.Remove(prior)
	disk, err := os.ReadFile(c.path)
	if err != nil || !bytes.Equal(disk, p.raw) {
		return errors.New("конфигурация изменена параллельно")
	}
	if err = os.Rename(next, c.path); err != nil {
		return err
	}
	fail := func() error {
		recovery, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		if os.Rename(prior, c.path) != nil || p.api.reload(recovery, c.path) != nil {
			return errors.New("исходное состояние Mihomo не восстановлено")
		}
		live, e := p.api.selectors(recovery)
		if e != nil || restoreSelectors(recovery, p.api, selections, live) != nil {
			return errors.New("исходные выборы Mihomo не подтверждены")
		}
		return errors.New("проверка маршрутов не прошла; восстановлен прежний профиль")
	}
	if p.api.reload(ctx, c.path) != nil {
		return fail()
	}
	after, err := p.api.selectors(ctx)
	_, managed := candidate[stateKey]
	if err != nil || !groupsReady(after, expected) || !countryGroups.ready(after, selections) || managed && !p.api.rulesReady(ctx, candidate) || restoreSelectors(ctx, p.api, selections, after) != nil || !p.api.ruleMode(ctx) {
		return fail()
	}
	return nil
}
