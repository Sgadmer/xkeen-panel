package cardcontroller

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

const defaultID = "default"

type DefaultRoute struct {
	Group, Auto, Name, Protocol, Current, Pinned string
	Nodes                                        []xkeen.PoolNodeView
}

func nativeDefault(p profile, live map[string]selector) (group, auto string) {
	for _, raw := range list(p.doc["rules"]) {
		parts, end := targetPart(str(raw))
		if end == 1 && parts[0] == "MATCH" && !strings.HasPrefix(parts[end], cardPrefix) {
			group = parts[end]
			break
		}
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

func (c *Controller) defaultRoute(p profile, live map[string]selector) DefaultRoute {
	group, auto := nativeDefault(p, live)
	state := DefaultRoute{Group: group, Auto: auto, Pinned: p.assigned[defaultID], Nodes: []xkeen.PoolNodeView{}}
	if state.Pinned != "" {
		state.Group = cardPrefix + defaultID
	}
	name := state.Group
	seen := map[string]bool{}
	for !seen[name] && live[name].Now != "" {
		seen[name] = true
		name = live[name].Now
	}
	state.Name, state.Protocol = name, live[name].Type
	members := map[string]bool{}
	for _, name := range live[auto].All {
		members[name] = true
	}
	for _, s := range c.catalog() {
		key := xkeen.ServiceTargetID(s)
		if key == "" {
			continue
		}
		if members[s.Name] {
			state.Nodes = append(state.Nodes, xkeen.PoolNodeView{Tag: key, ServerID: s.ID, Name: s.Name, Address: s.Address, Port: s.Port, Country: xkeen.ServerCountry(s), Latency: s.Latency})
		}
		if name == nodePrefix+key || name == s.Name {
			state.Current, state.Name, state.Protocol = key, s.Name, s.Protocol
			if state.Pinned == "" && live[group].Now != auto {
				state.Pinned = key
			}
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
	return p, state, nil
}

func (c *Controller) Default(ctx context.Context) (DefaultRoute, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, state, err := c.currentDefault(ctx)
	return state, err
}

func (c *Controller) SetDefault(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if key != "" {
		if !validHash(key) {
			return errors.New("неверный идентификатор узла")
		}
		return c.setDefault(ctx, key)
	}
	p, err := c.read()
	if err != nil {
		return err
	}
	live, err := p.api.selectors(ctx)
	if err != nil {
		return err
	}
	group, auto := nativeDefault(p, live)
	if auto == "" || !p.api.ruleMode(ctx) {
		return errors.New("автоматическая группа общего маршрута недоступна")
	}
	if live[group].Now != auto {
		if err = p.api.request(ctx, "PUT", "/proxies/"+url.PathEscape(group), map[string]string{"name": auto}, nil); err != nil {
			return err
		}
		live, err = p.api.selectors(ctx)
		if err != nil || live[group].Now != auto {
			return errors.New("Mihomo не подтвердил автовыбор")
		}
	}
	if p.assigned[defaultID] != "" {
		err = c.setDefault(ctx, "")
	}
	return err
}

func (c *Controller) setDefault(ctx context.Context, key string) error {
	view, err := c.apply(ctx, defaultID, key, nil)
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
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return err
	}
	if source != "" {
		for name, v := range object(p.doc["proxy-providers"]) {
			provider := object(v)
			if str(provider["type"]) == "http" && str(provider["url"]) == source {
				if err = p.api.request(ctx, "PUT", "/providers/proxies/"+url.PathEscape(name), nil, nil); err != nil {
					return err
				}
			}
		}
	}
	_, err = c.apply(ctx, "", "", nil)
	return err
}

func (c *Controller) ProbeDefault(ctx context.Context, checkURL string) (string, string, int, error) {
	c.mu.Lock()
	p, state, err := c.currentDefault(ctx)
	c.mu.Unlock()
	if err != nil {
		return "", "", -1, err
	}
	if state.Name == "" || state.Name == "DIRECT" || state.Name == "REJECT" || state.Name == "PASS" {
		return state.Name, state.Protocol, -1, errors.New("общий маршрут не использует доступный прокси")
	}
	var result struct{ Delay int }
	path := "/proxies/" + url.PathEscape(state.Group) + "/delay?timeout=8000&url=" + url.QueryEscape(checkURL)
	if err := p.api.request(ctx, "GET", path, nil, &result); err != nil {
		return state.Name, state.Protocol, -1, err
	}
	if result.Delay <= 0 {
		return state.Name, state.Protocol, -1, errors.New("ядро не подтвердило прохождение пробы")
	}
	return state.Name, state.Protocol, result.Delay, nil
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
	_, state, err := c.currentDefault(ctx)
	if err != nil || state.Pinned == "" {
		return "", err
	}
	servers := c.catalog()
	var country string
	for _, s := range servers {
		if xkeen.ServiceTargetID(s) == state.Pinned {
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
	for _, s := range servers {
		if len(s.RawProfile) != 0 || !strings.EqualFold(xkeen.ServerCountry(s), country) {
			continue
		}
		if c.avoidCountries != nil && len(c.avoidCountries()) > 0 && !c.autoAllowed(s) {
			continue
		}
		if key := xkeen.ServiceTargetID(s); key != "" && key != state.Pinned {
			candidates = append(candidates, s)
		}
	}
	if len(candidates) == 0 {
		return "", errors.New("резерв того же региона отсутствует")
	}
	checked, err := c.CheckServers(candidates, xkeen.ProbeOptions{Context: ctx, Timeout: 8 * time.Second, Concurrency: 3, StateDir: c.stateDir})
	if err != nil {
		return "", err
	}
	best := -1
	for i, s := range checked {
		if s.ProbeKind == "https" && s.Latency >= 0 && (best < 0 || s.Latency < checked[best].Latency) {
			best = i
		}
	}
	if best < 0 {
		return "", errors.New("резерв того же региона не прошёл HTTPS-проверку")
	}
	err = c.setDefault(ctx, xkeen.ServiceTargetID(checked[best]))
	if err != nil {
		return "", err
	}
	return checked[best].Name, nil
}
