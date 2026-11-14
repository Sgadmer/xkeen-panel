package cardcontroller

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

const defaultID = "default"
const defaultSourceKey = "x-xkeen-panel-default-source"
const replacementKey = "x-xkeen-panel-replacement"

type DefaultRoute struct {
	Group, Auto, Name, Protocol, Current, Pinned      string
	ScopeID, SelectionKind, SelectionName, SourceName string
	CurrentSource                                     string
	Selective                                         bool
	Nodes                                             []xkeen.PoolNodeView
	probeTarget                                       string
}

func nativeDefault(p profile, live map[string]selector) (group, auto string) {
	for _, raw := range list(p.doc["rules"]) {
		parts, end := targetPart(str(raw))
		if end == 1 && parts[0] == "MATCH" && !strings.HasPrefix(parts[end], cardPrefix) {
			group = parts[end]
			break
		}
	}
	if strings.EqualFold(live[group].Type, "URLTest") || strings.EqualFold(live[group].Type, "Fallback") {
		return group, group
	}
	for _, name := range live[group].All {
		t := live[name].Type
		if strings.EqualFold(t, "URLTest") || strings.EqualFold(t, "Fallback") {
			auto = name
			break
		}
	}
	return
}

// Consult the local configuration before contacting a foreign controller.
// An unmanaged profile with MATCH,DIRECT or MATCH,REJECT has nothing to migrate.
func configuredAuto(p profile) bool {
	match, _ := nativeDefault(p, nil)
	groups := map[string]map[string]interface{}{}
	for _, raw := range list(p.doc["proxy-groups"]) {
		g := object(raw)
		groups[str(g["name"])] = g
	}
	auto := func(g map[string]interface{}) bool {
		return str(g["type"]) == "url-test" || str(g["type"]) == "fallback"
	}
	g := groups[match]
	if auto(g) {
		return true
	}
	if str(g["type"]) != "select" {
		return false
	}
	for _, name := range list(g["proxies"]) {
		if auto(groups[str(name)]) {
			return true
		}
	}
	return false
}

func (c *Controller) defaultRoute(p profile, live map[string]selector) DefaultRoute {
	group, auto := nativeDefault(p, live)
	state := DefaultRoute{Group: group, Auto: auto, Pinned: p.assigned[defaultID], ScopeID: p.scopeID(), SelectionKind: "native", SelectionName: live[group].Now}
	state.Selective = refilterEnabled(p.doc)
	if state.Pinned != "" || state.Selective {
		state.Group = cardPrefix + defaultID
	} else if policy, err := readKillSwitch(p.doc); err == nil && !policy.Enabled {
		// The original MATCH remains in the file for lossless restoration.
		// The running rule above it uses the health-checked direct fallback.
		for _, raw := range list(p.doc["rules"]) {
			parts, end := targetPart(str(raw))
			if end == 1 && parts[0] == "MATCH" {
				if strings.HasPrefix(parts[end], failoverPrefix) {
					state.Group = parts[end]
				}
				break
			}
		}
	}
	name := state.Group
	seen := map[string]bool{}
	for !seen[name] && live[name].Now != "" {
		seen[name] = true
		name = live[name].Now
	}
	state.Name, state.Protocol = name, live[name].Type
	// Test the actual outbound, not a selector that could switch to DIRECT
	// between reading its state and sending the health request.
	if leaf, ok := live[name]; ok && leaf.Now == "" && len(leaf.All) == 0 {
		switch strings.ToLower(leaf.Type) {
		case "", "direct", "reject", "rejectdrop", "pass", "compatible", "selector", "fallback", "urltest", "loadbalance", "relay":
		default:
			state.probeTarget = name
		}
	}
	servers := c.catalog()
	scope := p.pool(state.ScopeID)
	if scope != nil {
		state.Nodes = poolViews(scope.members(c.poolNodes(servers)))
	}
	if pool := p.pool(state.Pinned); pool != nil {
		state.ScopeID, state.SelectionKind, state.SelectionName = pool.ID, "auto", pool.Name
		state.Auto, state.Pinned = pool.ID, ""
		if p.endpointName(pool.ID, name) {
			state.Current, state.Name, state.Protocol = pool.ID, pool.Name, "leastPing"
		}
		return state
	}
	if state.Pinned != "" {
		state.SelectionKind = "manual"
	}
	native := c.nativeServers(p, auto, servers)
	// Names shared by distinct native endpoints cannot identify a member.
	identities := map[string]string{}
	for _, s := range native {
		key := xkeen.ServiceTargetID(s)
		if previous, exists := identities[s.Name]; exists && previous != key {
			identities[s.Name] = ""
		} else if !exists {
			identities[s.Name] = key
		}
	}
	candidates := servers
	if state.Pinned == "" {
		candidates = native
	} else if source := str(p.doc[defaultSourceKey]); source != "" {
		candidates = nil
		for _, s := range servers {
			if s.SourceID == source && xkeen.ServiceTargetID(s) == state.Pinned {
				candidates = []models.Server{s}
				break
			}
		}
	}
	for _, s := range candidates {
		key := xkeen.ServiceTargetID(s)
		if key == "" {
			continue
		}
		matched := identities[s.Name] == key
		if state.Pinned == key {
			state.SelectionName = s.Name
		}
		if name == nodePrefix+key || state.Pinned == "" && matched && name == s.Name {
			state.Current, state.Name, state.Protocol, state.SourceName = key, s.Name, s.Protocol, s.SourceName
			state.CurrentSource = s.SourceID
			if state.Pinned == "" && live[group].Now != auto {
				state.Pinned = key
			}
			if len(s.RawProfile) > 0 {
				state.SelectionKind, state.SelectionName = "profile", s.Name
			} else if state.Pinned != "" && (p.assigned[defaultID] != "" || live[group].Now == s.Name) {
				state.SelectionKind, state.SelectionName = "manual", s.Name
				if str(p.doc[replacementKey]) == key {
					state.SelectionKind = "replacement"
				}
			}
			break
		}
	}
	return state
}

func (c *Controller) currentDefault(ctx context.Context) (profile, DefaultRoute, error) {
	p, err := c.read()
	if err != nil {
		return p, DefaultRoute{}, err
	}
	live, err := p.api.selectors(ctx)
	if err != nil {
		return p, DefaultRoute{}, err
	}
	state := c.defaultRoute(p, live)
	if state.Group == "" || !p.api.ruleMode(ctx) {
		return p, DefaultRoute{}, errors.New("контроллер не подтвердил общий маршрут Mihomo")
	}
	if state.SelectionKind == "auto" && state.Current == state.ScopeID {
		endpoint := fallbackSelection(live[state.Group].Now, live)
		for _, raw := range list(p.doc["proxies"]) {
			proxy := object(raw)
			if str(proxy["name"]) != endpoint {
				continue
			}
			port, _ := proxy["port"].(int)
			id := xkeen.CardPoolMember(ctx, c.rt, strings.TrimPrefix(endpoint, nodePrefix+state.ScopeID+"-"), port)
			if id != "" {
				for _, node := range state.Nodes {
					if node.Tag == id {
						for _, s := range c.catalog() {
							if s.ID == node.ServerID && xkeen.ServiceTargetID(s) == id {
								state.Current, state.Name, state.Protocol, state.SourceName, state.CurrentSource = id, s.Name, s.Protocol, s.SourceName, s.SourceID
								break
							}
						}
						break
					}
				}
			}
			break
		}
	}
	return p, state, nil
}

func (c *Controller) Default(ctx context.Context) (DefaultRoute, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, state, err := c.currentDefault(ctx)
	return state, err
}

func (c *Controller) SetDefault(ctx context.Context, key string) error {
	return c.SetDefaultSource(ctx, key, "")
}

func (c *Controller) SetDefaultSource(ctx context.Context, key, source string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if key == "" {
		return c.setScope(ctx, "")
	}
	if !validHash(key) {
		return errors.New("неверный идентификатор узла")
	}
	p, err := c.read()
	if err != nil {
		return err
	}
	if p.pool(key) != nil {
		return c.setScope(ctx, key)
	}
	return c.setDefault(ctx, key, source, false)
}

func (c *Controller) setDefault(ctx context.Context, key, source string, replacement bool) error {
	view, err := c.apply(ctx, defaultID, key, func(p *profile) error {
		delete(p.doc, defaultSourceKey)
		delete(p.doc, replacementKey)
		if source != "" {
			found := false
			for _, s := range c.catalog() {
				if s.SourceID == source && xkeen.ServiceTargetID(s) == key {
					found = true
					break
				}
			}
			if !found {
				return errors.New("конфигурация отсутствует в выбранной подписке")
			}
			p.doc[defaultSourceKey] = source
		}
		if replacement {
			p.doc[replacementKey] = key
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !view.Active || c.pending[defaultID] {
		return errors.New("маршрут применён, завершение прежних соединений ещё не подтверждено")
	}
	return nil
}

// SyncProviders reloads only a provider that already uses this subscription.
// Another source can always be selected through an isolated card worker.
func (c *Controller) SyncProviders(ctx context.Context, source string) error {
	if err := c.RefreshMatchingProviders(ctx, []string{source}); err != nil {
		return err
	}
	return c.Reconcile(ctx)
}

func (c *Controller) CheckSourceRemoval(source string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return err
	}
	if len(matchingProviders(p, []string{source})) > 0 {
		return errors.New("эту подписку использует встроенный провайдер профиля Mihomo. Сначала отвяжите его в профиле, чтобы после удаления не остались активные серверы")
	}
	return nil
}

func matchingProviders(p profile, sources []string) []string {
	wanted := make(map[string]bool, len(sources))
	for _, source := range sources {
		if source != "" {
			wanted[source] = true
		}
	}
	var matched []string
	for name, value := range object(p.doc["proxy-providers"]) {
		provider := object(value)
		if str(provider["type"]) == "http" && wanted[str(provider["url"])] {
			matched = append(matched, name)
		}
	}
	return matched
}

// NativeSourceLinks returns source IDs only. Credentials in either config
// never leave the controller/API boundary.
func (c *Controller) NativeSourceLinks(sources []models.SubscriptionSource) (map[string]bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return nil, err
	}
	links := map[string]bool{}
	for _, s := range sources {
		links[s.ID] = len(matchingProviders(p, []string{s.URL})) > 0
	}
	return links, nil
}

func (c *Controller) RefreshMatchingProviders(ctx context.Context, sources []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return err
	}
	for _, name := range matchingProviders(p, sources) {
		if err = p.api.request(ctx, "PUT", "/providers/proxies/"+url.PathEscape(name), nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) ProbeDefault(ctx context.Context, checkURL string) (models.RouteProbe, error) {
	c.mu.Lock()
	p, state, err := c.currentDefault(ctx)
	c.mu.Unlock()
	probe := models.RouteProbe{Name: state.Name, Protocol: state.Protocol, Latency: -1, Selective: refilterEnabled(p.doc)}
	if err != nil {
		return probe, err
	}
	if state.probeTarget == "" {
		return probe, errors.New("общий маршрут не использует доступный прокси")
	}
	var result struct{ Delay int }
	path := "/proxies/" + url.PathEscape(state.probeTarget) + "/delay?timeout=8000&url=" + url.QueryEscape(checkURL)
	for attempt := 0; attempt < 2; attempt++ {
		err = p.api.request(ctx, "GET", path, nil, &result)
		if err == nil {
			if result.Delay <= 0 {
				return probe, errors.New("ядро не вернуло результат проверки задержки")
			}
			probe.Latency, probe.Checked = result.Delay, true
			return probe, nil
		}
		// Mihomo returns 503 or 504 when the outbound URL test fails.
		// Authentication, a disappearing group, or a lost controller response
		// do not establish a data-plane failure.
		var status apiResponseError
		if !errors.As(err, &status) || (status != http.StatusServiceUnavailable && status != http.StatusGatewayTimeout) {
			return probe, err
		}
	}
	probe.Checked = true
	return probe, err
}

// A batched probe uses a temporary Xray process, like the workers that serve
// imported complete profiles. It leaves the active Mihomo configuration alone.
func (c *Controller) CheckServers(servers []models.Server, options xkeen.ProbeOptions) ([]models.Server, error) {
	return xkeen.CheckCardServersHTTPS(c.rt, servers, options)
}

// Automatic groups already check their members. Complete provider profiles
// have their own selection rules and must not be flattened to a member node.
func (c *Controller) RecoverDefault(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, state, err := c.currentDefault(ctx)
	if err != nil || state.Pinned == "" {
		return "", err
	}
	servers := c.catalog()
	var country string
	for _, s := range servers {
		if xkeen.ServiceTargetID(s) == state.Pinned {
			if source := str(p.doc[defaultSourceKey]); source != "" && s.SourceID != source {
				continue
			}
			if len(s.RawProfile) > 0 {
				return "", nil
			}
			country = xkeen.ServerCountry(s)
			break
		}
	}
	if country == "" {
		return "", nil
	}
	var candidates []models.Server
	for _, n := range c.poolNodes(servers) {
		if !n.allowed || n.id == state.Pinned || !strings.EqualFold(xkeen.ServerCountry(n.server), country) {
			continue
		}
		candidates = append(candidates, n.server)
	}
	if len(candidates) == 0 {
		return "", errors.New("резерв того же региона отсутствует")
	}
	checked, err := c.CheckServers(candidates, xkeen.ProbeOptions{Context: ctx, Timeout: 8 * time.Second, Concurrency: 3, StateDir: c.stateDir})
	if err != nil {
		return "", err
	}
	for _, n := range c.poolNodes(checked) {
		s := n.server
		if n.allowed && strings.EqualFold(xkeen.ServerCountry(s), country) && s.ProbeKind == "https" && s.Latency >= 0 {
			if err := c.setDefault(ctx, n.id, s.SourceID, true); err != nil {
				return "", err
			}
			return s.Name, nil
		}
	}
	return "", errors.New("резерв того же региона не прошёл HTTPS-проверку")
}
