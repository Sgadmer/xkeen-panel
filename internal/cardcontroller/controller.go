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
	"maps"
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
	"xkeen-panel/installer"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

type View struct {
	xkeen.ServiceRoutesView
	Scope                    string `json:"scope"`
	ControllerReady          bool   `json:"controller_ready"`
	ActiveConnectionsPending bool   `json:"active_connections_pending,omitempty"`
	ServiceAutoDefault       bool   `json:"service_auto_default"`
	DefaultServiceTarget     string `json:"default_service_target"`
}

type Controller struct {
	traffic              *trafficRecorder
	mu                   sync.Mutex
	path                 string
	stateDir             string
	rt                   xkeen.Runtime
	catalog              func() []models.Server
	http                 *http.Client
	validate             func(context.Context, string) error
	prepare              func(xkeen.Runtime, string, models.Server) (xkeen.CardProxy, error)
	pending              map[string]bool
	autoFlowsChecked     bool
	refilterError        string
	serviceListsError    string
	serviceListsAttempt  time.Time
	serviceListsUpdating bool
	avoidCountries       func() []string
	autoAllowed          func(models.Server) bool
	sourceProviderURLs   func() map[string]string
	autoPoolLimit        int
	probeURL             string
	guard                guardJournal
	// Set while a subscription refresh is applied: see soft_swap.go.
	soft        bool
	retired     map[string]retiredWorker
	retireSweep bool
	liveWorkers map[string]bool // workers of the last completed reload
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

type apiResponseError int

func (e apiResponseError) Error() string {
	return fmt.Sprintf("локальный API Mihomo ответил HTTP %d", int(e))
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
		return apiResponseError(res.StatusCode)
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
const serviceAutoKey = "x-xkeen-panel-service-auto-default"
const cardPrefix = "XKP-card-"
const nodePrefix = "XKP-endpoint-"
const directTarget = "direct"

func defaultServiceTarget(id string) string {
	if id == "steam" {
		return directTarget
	}
	return allPoolID
}

func validAssignment(service, target string) bool {
	return validHash(target) || service != "claude" && target == directTarget
}

type profile struct {
	raw       []byte
	doc       map[string]interface{}
	assigned  map[string]string
	pools     []MultiPool
	autoLimit int
	probeURL  string
	api       coreAPI
}

func (c *Controller) read() (profile, error) {
	p := profile{assigned: map[string]string{}, probeURL: c.probeURL}
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
	if _, err = readKillSwitch(p.doc); err != nil {
		return p, err
	}
	if _, err = readServiceLists(p.doc); err != nil {
		return p, err
	}
	if _, err = readDomainPolicy(p.doc); err != nil {
		return p, err
	}
	if value, found := p.doc[serviceAutoKey]; found && value != true {
		return p, errors.New("повреждена настройка автовыбора сервисов")
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
			if ok && val == "" && groupNames[id] != "" {
				continue // Old profiles may store an empty selection explicitly.
			}
			if xkeen.CustomServiceID(id) && !xkeen.IsCustomService(id) {
				continue // The owner's card was removed; its choice goes with the next save.
			}
			if !ok || !validAssignment(id, val) || !knownCard(id) && !(id == defaultID && validHash(val)) {
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
	result := View{ServiceRoutesView: view, Scope: "mihomo", ActiveConnectionsPending: len(c.pending) > 0,
		ServiceAutoDefault: p.doc[serviceAutoKey] == true, DefaultServiceTarget: allPoolID}
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
	managedRulesLive := managed && result.ControllerReady && activeRulesMatch(rules, p.doc)
	result.Active = managedRulesLive
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
	providerNode := func(name string) selector {
		if providerNodes == nil {
			providerNodes = p.api.providerNodes(ctx)
		}
		return providerNodes[name]
	}
	metricsCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	workers := newWorkerSnapshot(metricsCtx, c.rt, p, func() []models.Server { return servers }, xkeen.CardPoolMember)
	currentRoutes := map[string]*xkeen.CurrentServiceRoute{}
	current := func(group string) *xkeen.CurrentServiceRoute {
		if !result.ControllerReady || !groupRoutes[group] || strings.HasPrefix(group, cardPrefix) && !managedRulesLive {
			return nil
		}
		if _, found := currentRoutes[group]; !found {
			currentRoutes[group] = workers.current(group, live, providerNode)
		}
		return currentRoutes[group]
	}
	policy, _ := readKillSwitch(p.doc)
	registry, _ := readRefilter(p.doc)
	for i := range result.Services {
		s := &result.Services[i]
		s.Target = p.assigned[s.ID]
		s.Blocked = false
		if registry.Enabled && s.Target == "" && s.ID != "claude" {
			s.InheritedRoute = &xkeen.InheritedRoute{Kind: "conditional", Via: []string{}}
			branch := cardPrefix + defaultID
			if own := cardPrefix + s.ID + "-inherited"; groupRoutes[own] {
				branch = own
			}
			s.CurrentRoute = current(branch)
			continue
		}
		if !managed || s.ID != "claude" && s.Target == "" {
			group := groupNames[s.ID]
			start := group
			if own := cardPrefix + s.ID + "-inherited"; groupRoutes[own] {
				start = live[own].Now
				s.CurrentRoute = current(own)
			} else if wrap := failoverName("native", group); groupRoutes[wrap] {
				start = wrap
			} else if !groupRoutes[group] {
				group = ""
				start = ""
			}
			if s.CurrentRoute == nil {
				s.CurrentRoute = current(start)
			}
			s.InheritedRoute = inheritedRoute(start, live, names, providerNode)
			if start != group {
				s.InheritedRoute.Group = group
				if len(s.InheritedRoute.Via) > 0 && s.InheritedRoute.Via[0] == group {
					s.InheritedRoute.Via = s.InheritedRoute.Via[1:]
				}
			}
			if group != "" {
				current := fallbackSelection(start, live)
				if current == group {
					current = live[group].Now
				}
				s.RouteName = publicRouteName(current, names)
			}
			continue
		}
		s.CurrentRoute = current(cardPrefix + s.ID)
		group := live[cardPrefix+s.ID]
		oneMember := len(group.All) == 1 && group.All[0] == group.Now
		group.Now = fallbackSelection(group.Now, live)
		s.Blocked = result.ControllerReady && len(group.All) == 1 && group.Now == "REJECT"
		target := nodePrefix + s.Target
		if s.Target == directTarget {
			target = "DIRECT"
		}
		matches := group.Now == target
		if s.Target != directTarget {
			matches = p.endpointName(s.Target, group.Now)
		}
		directFallback := !policy.Protects(s.ID) && group.Now == "DIRECT"
		if !oneMember || (!matches && !s.Blocked && !directFallback) {
			result.Active = false
		}
		if s.Blocked {
			s.RouteName = "REJECT"
		} else if group.Now == "DIRECT" {
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

// A dispatcher stop (including restart) removes transparent interception.
// Only allow this if the user has released every protected VPN route.
func (c *Controller) CheckCoreInterruption() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return err
	}
	if _, managed := p.doc[stateKey]; managed {
		policy, err := readKillSwitch(p.doc)
		if err != nil {
			return err
		}
		if !policy.hasProtectedRoute(p) {
			return nil
		}
		return errors.New("Kill switch включён. Остановка или перезапуск XKeen снимет перехват защищённых маршрутов")
	}
	return nil
}

func (c *Controller) Set(ctx context.Context, id, target string) (View, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if target == "" {
		target = defaultServiceTarget(id)
	}
	if !knownCard(id) || !validAssignment(id, target) {
		return View{}, errors.New("недопустимый сервис или сервер")
	}
	return c.apply(ctx, id, target, func(p *profile) error {
		if _, managed := p.doc[stateKey]; !managed {
			p.doc[serviceAutoKey] = true
		}
		return nil
	})
}

// EnableServiceAutoDefault upgrades all unassigned cards in one validated reload.
// Already assigned services and the router's default route keep their identity.
func (c *Controller) EnableServiceAutoDefault(ctx context.Context) (View, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.apply(ctx, "", allPoolID, func(p *profile) error {
		p.doc[serviceAutoKey] = true
		return nil
	})
}
func (c *Controller) Reconcile(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reconcile(ctx, nil)
}

// follow, when set, adjusts the saved selections inside the same reload.
func (c *Controller) reconcile(ctx context.Context, follow func(*profile) error) error {
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
			if err := c.setScope(ctx, allPoolID); err != nil || follow == nil {
				return err
			}
			_, err = c.apply(ctx, "", "", follow)
			return err
		}
	}
	if _, enabled := p.doc[stateKey]; !enabled {
		return c.reconcileCountryGroups(ctx, p)
	}
	policy, err := readKillSwitch(p.doc)
	if err != nil {
		return err
	}
	if policy.Protects("claude") && installer.ClaudeFirewallNeedsSync(true) {
		if err := installer.SetInstalledClaudeFirewall(ctx, true); err != nil {
			return err
		}
	}
	_, err = c.apply(ctx, "", "", follow)
	if err == nil && !policy.Protects("claude") && installer.ClaudeFirewallNeedsSync(false) {
		err = installer.SetInstalledClaudeFirewall(ctx, false)
	}
	return err
}

func (c *Controller) apply(ctx context.Context, id, target string, withListener func(*profile) error) (View, error) {
	p, err := c.read()
	if err != nil {
		return View{}, err
	}
	chosen := maps.Clone(p.assigned) // the saved choices before a refresh re-points them
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
	if p.doc[serviceAutoKey] == true {
		for service := range groupNames {
			if p.assigned[service] == "" {
				p.assigned[service] = defaultServiceTarget(service)
			}
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
	var nodes []poolNode
	if id != "" && countryPoolCodes[target] != "" {
		nodes = c.poolNodes(servers)
		if len(p.pool(target).members(nodes)) == 0 {
			return View{}, errors.New("в выбранном пуле страны нет доступных серверов")
		}
	}
	if target != "" && target != directTarget {
		if _, ok := catalog[target]; !ok && p.pool(target) == nil {
			return View{}, errors.New("сервер исчез из подписки")
		}
	}
	peers := map[string]cardEndpoint{}
	workers := map[string]xkeen.CardProxy{}
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
	changed := map[string]string{}
	for _, service := range view.Services {
		name := cardPrefix + service.ID
		want := expected[name]
		previous, exists := selections[name]
		if inherited := name + "-inherited"; want == "" && expected[inherited] != "" {
			want = expected[inherited]
			previous, exists = selections[inherited]
		}
		// The new defaults can change which card owns a destination even
		// when both cards keep their pinned targets. Resume after a restart.
		recheckAuto := p.doc[serviceAutoKey] == true && !c.autoFlowsChecked
		if c.soft && !recheckAuto && !c.pending[service.ID] && service.ID != id {
			key := p.assigned[service.ID]
			if worker := replacedWorker(chosen[service.ID], key, previous.Now, want, p.pool(key) != nil); worker != "" {
				c.retire(worker, previous.Now)
				continue
			}
		}
		if recheckAuto || c.pending[service.ID] || (want != "" || exists) && (previous.Now != want || service.ID == id) {
			changed[service.ID] = want
		}
	}
	c.autoFlowsChecked = p.doc[serviceAutoKey] == true
	want := expected[cardPrefix+defaultID]
	before := selections[cardPrefix+defaultID].Now
	reissued := ""
	if c.soft && !c.pending[defaultID] && id != defaultID {
		key := p.assigned[defaultID]
		reissued = replacedWorker(chosen[defaultID], key, before, want, p.pool(key) != nil)
	}
	if reissued != "" {
		c.retire(reissued, before)
	} else if c.pending[defaultID] || before != want || id == defaultID {
		changed[defaultID] = want
	}
	failed := c.drainChanged(ctx, p, changed, view.Services)
	for service := range changed {
		if failed[service] {
			c.pending[service] = true
		} else {
			delete(c.pending, service)
		}
	}
	// The transparent rule may switch back from a native fallback group
	// without having a service assignment. A live CONNECT keeps its old
	// chain across hot reloads, including an established DIRECT socket.
	const obsolete = "obsolete-fallback"
	if c.drainObsoleteFallback(ctx, p.api, expected, p.doc) {
		delete(c.pending, obsolete)
	} else {
		c.pending[obsolete] = true
	}
	result.ActiveConnectionsPending = len(c.pending) > 0
	if result.Active && !result.ActiveConnectionsPending {
		keep := map[string]bool{}
		for key := range workers {
			keep[key] = true
		}
		c.liveWorkers = maps.Clone(keep)
		// A worker replaced by a reissue serves its open connections to the end.
		if len(c.retired) > 0 {
			chains, known := c.openChains(ctx, p.api)
			for _, worker := range c.stillUsed(chains, known, time.Now()) {
				keep[worker] = true
			}
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
		if strings.HasPrefix(name, failoverPrefix) {
			if !strings.EqualFold(g.Type, "fallback") || len(g.All) != 2 || g.All[0] != v || g.All[1] != "DIRECT" || g.Now != v && g.Now != "DIRECT" {
				return false
			}
			continue
		}
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
	return err == nil && activeRulesMatch(rules, doc) && a.refilterReady(ctx, doc) && a.serviceListsReady(ctx, doc)
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
		case "DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6", "RULE-SET":
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
