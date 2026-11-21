package cardcontroller

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"xkeen-panel/internal/xkeen"
)

const protectedRoutingKey = "x-xkeen-panel-protected-routing"

type protectedRoutingState struct {
	Version    int    `json:"version"`
	DrainToken string `json:"drain_token"`
}

func readProtectedRouting(doc map[string]interface{}) (protectedRoutingState, bool, error) {
	var state protectedRoutingState
	raw, found := doc[protectedRoutingKey]
	if !found {
		return state, false, nil
	}
	data, err := json.Marshal(raw)
	if err != nil || json.Unmarshal(data, &state) != nil || state.Version != 1 {
		return state, false, errors.New("повреждены настройки защищённого режима")
	}
	if _, err := time.Parse(time.RFC3339Nano, state.DrainToken); err != nil {
		return state, false, errors.New("повреждено состояние переподключения защищённого режима")
	}
	return state, true, nil
}

// Only explicit, bounded bypasses survive the canonical protected fallback.
// An arbitrary provider RULE-SET, broad selector alias or regex cannot establish
// that a DIRECT match is a deliberate exception rather than a catch-all.
func protectedDirectRule(fields []string, target int) bool {
	if target < 2 {
		return false
	}
	switch fields[0] {
	case "DOMAIN", "DOMAIN-SUFFIX":
		return validServiceDomain(fields[1])
	case "DOMAIN-REGEX":
		// The one expression accepted here is the panel's own rendering of a
		// pattern exclusion, which is checked for breadth when it is added.
		_, pattern := xkeen.PatternFromRegex(fields[1])
		return pattern && target == 2
	case "IP-CIDR", "IP-CIDR6":
		prefix, err := netip.ParsePrefix(fields[1])
		return err == nil && prefix.Bits() > 0
	case "GEOSITE":
		return fields[1] == "category-ru" || fields[1] == "private"
	case "GEOIP":
		return strings.EqualFold(fields[1], "ru") || strings.EqualFold(fields[1], "private")
	}
	return false
}

func validateProtectedExclusions(doc map[string]interface{}) error {
	entries, _, err := managedExclusions(doc)
	if err != nil {
		return err
	}
	for _, entry := range entries.Entries {
		if prefix, err := netip.ParsePrefix(entry.Value); err == nil && prefix.Bits() == 0 && !entry.Disabled {
			return errors.New("исключение для всех IP несовместимо с защищённым режимом; сначала удалите это исключение")
		}
	}
	return nil
}

func routeCanDirect(doc map[string]interface{}, name string, seen map[string]bool) bool {
	if name == "DIRECT" {
		return true
	}
	if seen[name] {
		return false
	}
	seen[name] = true
	for _, raw := range list(doc["proxies"]) {
		node := object(raw)
		if str(node["name"]) == name {
			switch strings.ToLower(str(node["type"])) {
			case "direct", "pass", "compatible":
				return true
			}
		}
	}
	for _, raw := range list(doc["proxy-groups"]) {
		group := object(raw)
		if str(group["name"]) != name {
			continue
		}
		for _, child := range namesOf(group["proxies"]) {
			if routeCanDirect(doc, child, seen) {
				return true
			}
		}
	}
	return false
}

func routingStatus(p profile, status RefilterStatus) RefilterStatus {
	status.Mode = "custom"
	if status.Enabled {
		status.Mode = "blocklist"
		return status
	}
	policy, err := readKillSwitch(p.doc)
	if err != nil || !policy.Enabled || !validHash(p.assigned[defaultID]) {
		return status
	}
	_, canonical, err := readProtectedRouting(p.doc)
	if err != nil {
		return status
	}
	if !canonical {
		// An older panel can already have a protected managed MATCH. Avoid
		// claiming that for a foreign profile whose earlier DIRECT rule
		// catches arbitrary names/IPs before that fallback is reached.
		managedFallback := false
		for _, raw := range list(p.doc["rules"]) {
			fields, end := targetPart(str(raw))
			if end < 1 {
				return status
			}
			if fields[0] == "MATCH" {
				managedFallback = fields[end] == cardPrefix+defaultID
				break
			}
			if routeCanDirect(p.doc, fields[end], map[string]bool{}) && !protectedDirectRule(fields, end) {
				return status
			}
		}
		if !managedFallback {
			return status
		}
	}
	status.Mode, status.ProtectedFallback = "protected", true
	return status
}

func (c *Controller) routingModeStatus(p profile, status RefilterStatus) RefilterStatus {
	status = routingStatus(p, status)
	if state, active, err := readProtectedRouting(p.doc); err == nil && active && !status.Enabled {
		ack, _ := os.ReadFile(filepath.Join(c.stateDir, "protected-routing-connections.applied"))
		status.ActiveConnectionsPending = string(ack) != state.DrainToken
	}
	return status
}

// SetProtectedRouting makes the choice in the panel authoritative instead of
// merely restoring a provider's old MATCH,DIRECT. All edits and selector changes
// are validated and published by one ordinary controller transaction.
func (c *Controller) SetProtectedRouting(ctx context.Context) (RefilterStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return RefilterStatus{}, err
	}
	old, err := readRefilter(p.doc)
	if err != nil {
		return RefilterStatus{}, err
	}
	if err := validateProtectedExclusions(p.doc); err != nil {
		return c.routingModeStatus(p, old.status(c.refilterError)), err
	}
	state := protectedRoutingState{Version: 1, DrainToken: time.Now().UTC().Format(time.RFC3339Nano)}
	_, err = c.apply(ctx, "", "", func(candidate *profile) error {
		if candidate.assigned[defaultID] == "" {
			pool := candidate.scopeID()
			if candidate.pool(pool) == nil {
				pool = allPoolID
			}
			candidate.assigned[defaultID] = pool
			candidate.doc[autoScopeKey] = pool
			delete(candidate.doc, defaultSourceKey)
			delete(candidate.doc, replacementKey)
		}
		policy, err := readKillSwitch(candidate.doc)
		if err != nil {
			return err
		}
		values := map[string]interface{}{}
		for id, mode := range policy.Services {
			values[id] = mode
		}
		candidate.doc[killSwitchKey] = map[string]interface{}{"enabled": true, "services": values}
		if value, found := candidate.doc[refilterKey]; found {
			object(value)["enabled"] = false
		}
		data, _ := json.Marshal(state)
		var value map[string]interface{}
		_ = json.Unmarshal(data, &value)
		candidate.doc[protectedRoutingKey] = value
		return nil
	})
	if err != nil {
		return c.routingModeStatus(p, old.status(c.refilterError)), err
	}
	current, err := c.read()
	if err != nil {
		return RefilterStatus{}, err
	}
	info, err := readRefilter(current.doc)
	if err == nil {
		err = c.finishProtectedDrain(ctx, current, state)
	}
	if err != nil {
		c.refilterError = "Защищённый режим: " + err.Error()
		return c.routingModeStatus(current, info.status(c.refilterError)), err
	}
	c.refilterError = ""
	return c.routingModeStatus(current, info.status("")), nil
}

// FinishRoutingTransition only resumes a previously requested transition. It
// does not enable a different mode as a side effect of background maintenance.
func (c *Controller) FinishRoutingTransition(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return err
	}
	state, active, err := readProtectedRouting(p.doc)
	if err != nil || !active || refilterEnabled(p.doc) {
		return err
	}
	policy, err := readKillSwitch(p.doc)
	if err != nil || !policy.Enabled {
		return err
	}
	err = c.finishProtectedDrain(ctx, p, state)
	if err != nil {
		c.refilterError = "Защищённый режим: " + err.Error()
	} else if strings.HasPrefix(c.refilterError, "Защищённый режим: ") {
		c.refilterError = ""
	}
	return err
}

func protectedFlowStable(flow refilterFlow, p profile) bool {
	for id, target := range p.assigned {
		if id != defaultID && target != "" && (slices.Contains(flow.Chains, cardPrefix+id) || slices.Contains(flow.Chains, dedicatedGroup(id))) {
			return true
		}
	}
	host := flow.Metadata.SniffHost
	if host == "" {
		host = flow.Metadata.Host
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ip, _ := netip.ParseAddr(flow.Metadata.DestinationIP)
	if ip.IsValid() && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast()) {
		return true
	}
	for _, raw := range list(p.doc["rules"]) {
		fields, end := targetPart(str(raw))
		if fields[0] == "MATCH" {
			break // The saved provider tail after the managed MATCH is inactive.
		}
		if end < 2 || (fields[end] != "DIRECT" && fields[end] != cardPrefix+"direct") || !protectedDirectRule(fields, end) {
			continue
		}
		if strings.EqualFold(strings.ReplaceAll(flow.Rule, "-", ""), strings.ReplaceAll(fields[0], "-", "")) && strings.EqualFold(flow.RulePayload, fields[1]) {
			return true
		}
		switch fields[0] {
		case "DOMAIN":
			if host == strings.ToLower(fields[1]) {
				return true
			}
		case "DOMAIN-SUFFIX":
			if host == strings.ToLower(fields[1]) || strings.HasSuffix(host, "."+strings.ToLower(fields[1])) {
				return true
			}
		case "IP-CIDR", "IP-CIDR6":
			if prefix, err := netip.ParsePrefix(fields[1]); err == nil && prefix.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (c *Controller) finishProtectedDrain(ctx context.Context, p profile, state protectedRoutingState) error {
	ack := filepath.Join(c.stateDir, "protected-routing-connections.applied")
	previous, err := os.ReadFile(ack)
	if err != nil && !os.IsNotExist(err) {
		return errors.New("не удалось прочитать состояние переподключения защищённого режима")
	}
	if string(previous) == state.DrainToken {
		return nil
	}
	if err := os.MkdirAll(c.stateDir, 0700); err != nil {
		return err
	}
	persist := func(path, data string) error {
		tmp, err := stage(c.stateDir, []byte(data))
		if err != nil {
			return err
		}
		defer os.Remove(tmp)
		return os.Rename(tmp, path)
	}
	pending := ack + ".pending"
	body, err := os.ReadFile(pending)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	token, at, _ := strings.Cut(string(body), "\n")
	cutoff, parsed := time.Parse(time.RFC3339Nano, at)
	if token != state.DrainToken || parsed != nil {
		if !p.api.ruleMode(ctx) || !p.api.rulesReady(ctx, p.doc) {
			return errors.New("ожидаем подтверждения защищённого режима работающим ядром")
		}
		cutoff = time.Now().UTC()
		if err := persist(pending, state.DrainToken+"\n"+cutoff.Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	var snapshot struct{ Connections []refilterFlow }
	if err := p.api.request(ctx, "GET", "/connections", nil, &snapshot); err != nil {
		return errors.New("защищённый режим включён; проверка прежних прямых соединений будет повторена")
	}
	for _, flow := range snapshot.Connections {
		if !slices.Contains(flow.Chains, "DIRECT") || !flow.Start.IsZero() && flow.Start.After(cutoff) || protectedFlowStable(flow, p) {
			continue
		}
		if flow.ID == "" || strings.ContainsAny(flow.ID, "/?#") {
			return errors.New("не удалось определить прежнее прямое соединение")
		}
		if err := p.api.request(ctx, "DELETE", "/connections/"+url.PathEscape(flow.ID), nil, nil); err != nil && !errors.Is(err, apiResponseError(404)) {
			return errors.New("защищённый режим включён; переподключение прежних запросов будет повторено")
		}
	}
	if err := persist(ack, state.DrainToken); err != nil {
		return err
	}
	_ = os.Remove(pending)
	return nil
}
