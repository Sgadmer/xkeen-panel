package cardcontroller

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"xkeen-panel/internal/xkeen"
)

var groupNames = map[string]string{
	"claude": "Claude", "openai": "ChatGPT", "youtube": "YouTube", "telegram": "Telegram",
	"discord": "Discord", "spotify": "Spotify", "github": "GitHub", "steam": "Steam",
	"playstation": "PlayStation", "xbox": "Xbox", "instagram": "Instagram", "whatsapp": "WhatsApp",
	"facebook": "Facebook", "netflix": "Netflix", "twitch": "Twitch", "disney": "Disney+",
	"primevideo": "Prime Video", "amazon": "Amazon", "twitter": "X (Twitter)", "hulu": "Hulu",
	"hbo": "HBO", "line": "LINE", "google": "Google", "ai": "AI",
}

func targetPart(rule string) ([]string, int) {
	fields := strings.Split(rule, ",")
	last := len(fields) - 1
	if last > 1 && strings.EqualFold(fields[last], "no-resolve") {
		last--
	}
	return fields, last
}

// A broad Google classifier can include YouTube's GeoSite and API names.
// Excluding the child from the parent lets an unassigned YouTube connection
// continue through the owner's rules or Re:filter, including explicit blocks.
func youtubeCondition(services []xkeen.ServiceRouteView, original []string) string {
	conditions := []string{}
	seen := map[string]bool{}
	add := func(condition string) {
		if !seen[condition] {
			conditions = append(conditions, "("+condition+")")
			seen[condition] = true
		}
	}
	for _, service := range services {
		if service.ID != "youtube" {
			continue
		}
		for _, domain := range service.Domains {
			if suffix, ok := strings.CutPrefix(domain, "domain:"); ok {
				add("DOMAIN-SUFFIX," + suffix)
			}
		}
	}
	for _, rule := range original {
		parts, end := targetPart(rule)
		if parts[end] != groupNames["youtube"] || end != 2 {
			continue
		}
		switch parts[0] {
		case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD", "DOMAIN-REGEX", "DOMAIN-KEYWORD", "GEOSITE", "RULE-SET":
			add(ruleCondition(parts, end))
		}
	}
	if len(conditions) == 0 {
		return ""
	}
	return "NOT,((OR,(" + strings.Join(conditions, ",") + ")))"
}

func ruleCondition(fields []string, target int) string {
	condition := strings.Join(fields[:target], ",")
	if target+1 < len(fields) {
		condition += "," + strings.Join(fields[target+1:], ",")
	}
	return condition
}

type cardEndpoint struct {
	xkeen.CardProxy
	name string
}

func failoverName(scope, route string) string {
	sum := sha256.Sum256([]byte(scope + "\x00" + route))
	return fmt.Sprintf("%s%x", failoverPrefix, sum[:16])
}

func render(p *profile, services []xkeen.ServiceRouteView, peers map[string]cardEndpoint, defaultSourceAvailable bool) (map[string]string, error) {
	policy, err := readKillSwitch(p.doc)
	if err != nil {
		return nil, err
	}
	registry, err := readRefilter(p.doc)
	if err != nil {
		return nil, err
	}
	if _, ownedProvider := p.doc[refilterKey]; ownedProvider {
		if err := refilterProviders(p.doc, registry); err != nil {
			return nil, err
		}
	}
	_, owned := p.doc[stateKey]
	original := []string{}
	for _, item := range list(p.doc["rules"]) {
		r, ok := item.(string)
		if !ok {
			return nil, errors.New("неподдерживаемое правило Mihomo")
		}
		parts, end := targetPart(r)
		if end < 1 {
			return nil, errors.New("неполное правило Mihomo")
		}
		if strings.HasPrefix(parts[end], cardPrefix) {
			if !owned {
				return nil, errors.New("конфликт существующих правил карточек")
			}
			continue
		}
		original = append(original, r)
	}
	if len(original) == 0 {
		return nil, errors.New("исходные правила Mihomo отсутствуют")
	}
	clean := func(field, prefix string) ([]interface{}, error) {
		out := []interface{}{}
		for _, item := range list(p.doc[field]) {
			name := str(object(item)["name"])
			if name == "" {
				return nil, errors.New("неподдерживаемая группа или узел Mihomo")
			}
			if strings.HasPrefix(name, cardPrefix) || strings.HasPrefix(name, nodePrefix) {
				if !owned || !strings.HasPrefix(name, prefix) {
					return nil, errors.New("конфликт имён карточек")
				}
				continue
			}
			out = append(out, item)
		}
		return out, nil
	}
	groups, err := clean("proxy-groups", cardPrefix)
	if err != nil {
		return nil, err
	}
	nodes, err := clean("proxies", nodePrefix)
	if err != nil {
		return nil, err
	}
	if err := protectNativeGroups(groups, nodes, policy.hasProtectedRoute(*p)); err != nil {
		return nil, err
	}
	native := map[string]bool{}
	manualBlocks := map[string]bool{"REJECT": true, "REJECT-DROP": true}
	for _, value := range append(append([]interface{}{}, groups...), nodes...) {
		native[str(object(value)["name"])] = true
	}
	// A named direct, reject or DNS adapter is the owner's explicit policy.
	// Wrapping it in a health-tested VPN fallback would turn a deliberate
	// block into DIRECT when the kill switch is disabled.
	for _, value := range nodes {
		node := object(value)
		switch strings.ToLower(str(node["type"])) {
		case "direct", "reject", "reject-drop", "rejectdrop", "pass", "compatible", "dns", "rematch":
			delete(native, str(node["name"]))
		}
		if kind := strings.ToLower(str(node["type"])); kind == "reject" || kind == "reject-drop" || kind == "rejectdrop" {
			manualBlocks[str(node["name"])] = true
		}
	}
	// A selector's deliberate REJECT must remain effective even with failover
	// allowed. Such groups keep their native behavior. The panel cannot
	// distinguish healthy intentional rejection from a tunnel outage by probe.
	for changed := true; changed; {
		changed = false
		for _, value := range groups {
			group := object(value)
			name := str(group["name"])
			if manualBlocks[name] || str(group["type"]) != "select" {
				continue
			}
			for _, child := range namesOf(group["proxies"]) {
				if manualBlocks[child] {
					manualBlocks[name], changed = true, true
					break
				}
			}
		}
	}
	used := map[string]bool{}
	adapter := func(key string) string {
		if key == directTarget {
			return "DIRECT"
		}
		peer, ok := peers[key]
		if !ok {
			return "REJECT"
		}
		name := peer.name
		if !used[key] {
			nodes = append(nodes, map[string]interface{}{"name": name, "type": "vless", "server": "127.0.0.1", "port": peer.Port, "uuid": peer.UUID, "network": "tcp", "tls": true, "servername": peer.ServerName, "fingerprint": peer.Fingerprint, "udp": true})
			used[key] = true
		}
		return name
	}
	expected := map[string]string{}
	rejectGroup := cardPrefix + "reject"
	groups = append(groups, map[string]interface{}{"name": rejectGroup, "type": "select", "proxies": []string{"REJECT"}})
	expected[rejectGroup] = "REJECT"
	directGroup := cardPrefix + "direct"
	terminal := func(protected bool) string {
		if protected {
			return rejectGroup
		}
		if _, exists := expected[directGroup]; !exists {
			groups = append(groups, map[string]interface{}{"name": directGroup, "type": "select", "proxies": []string{"DIRECT"}})
			expected[directGroup] = "DIRECT"
		}
		return directGroup
	}
	probeURL := p.probeURL
	if probeURL == "" {
		probeURL = "https://www.gstatic.com/generate_204"
	}
	routeFor := func(scope, route string, protected bool) string {
		if protected || route == "DIRECT" {
			return route
		}
		if route == "REJECT" {
			return "DIRECT"
		}
		if manualBlocks[route] {
			return route
		}
		name := failoverName(scope, route)
		if _, exists := expected[name]; !exists {
			groups = append(groups, map[string]interface{}{"name": name, "type": "fallback", "proxies": []string{route, "DIRECT"}, "url": probeURL, "interval": 60, "timeout": 5000, "lazy": false})
			expected[name] = route
		}
		return name
	}
	defaultTarget, _ := nativeDefault(*p, nil)
	if key := p.assigned[defaultID]; key != "" {
		defaultTarget = "REJECT"
		if defaultSourceAvailable {
			defaultTarget = adapter(key)
		}
	}
	// On unassign/direct remove the private listener at the same reload as the
	// strict-only group. A connection accepted on an obsolete listener still
	// names the removed private group and cannot select the public DIRECT card.
	forced := map[string]bool{}
	if rawListeners, exists := p.doc["listeners"]; exists {
		items, ok := rawListeners.([]interface{})
		if !ok {
			return nil, errors.New("неподдерживаемая конфигурация входов Mihomo")
		}
		kept := []interface{}{}
		for _, item := range items {
			in := object(item)
			ownedID := ""
			for id := range groupNames {
				if str(in["name"]) == serviceInbound(id) {
					ownedID = id
					break
				}
			}
			if ownedID != "" {
				name := dedicatedGroup(ownedID)
				current := str(in["proxy"])
				if current != name && !(ownedID == "claude" && current == cardPrefix+"claude") {
					return nil, errors.New("занят зарезервированный вход карточки")
				}
				if !validHash(p.assigned[ownedID]) {
					continue
				}
				if forced[ownedID] {
					return nil, errors.New("повторяющийся вход карточки")
				}
				in["proxy"] = name
				forced[ownedID] = true
			}
			kept = append(kept, item)
		}
		p.doc["listeners"] = kept
	}
	priority := []string{}
	var registryDomainOverrides, registryIPOverrides []string
	claudeRuleCount := 0
	for _, service := range services {
		id := service.ID
		key := p.assigned[id]
		// A broad assigned GEOSITE (e.g. Google or AI) must not silently
		// take over a more specific existing group. Keep the original group
		// for those destination matches in the same specific-first order.
		protectChild := key == "" && (id == "youtube" && p.assigned["google"] != "" || id == "primevideo" && p.assigned["amazon"] != "" || id == "openai" && p.assigned["ai"] != "")
		hasOverride := (policy.Services[id] == "off" || policy.Services[id] == "on") && (registry.Enabled || policy.Enabled)
		// A kill-switch override controls failure handling, not whether an
		// otherwise unassigned service should be sent through the VPN.
		registryOverride := registry.Enabled && id != "claude" && key == "" && (hasOverride || policy.Protects(id) != policy.Enabled)
		if registry.Enabled && id != "claude" && key == "" && !registryOverride {
			continue
		}
		if key == "" && id != "claude" && !protectChild && !hasOverride && !registryOverride {
			continue
		}
		name := cardPrefix + id
		route := adapter(key)
		if key == "" && id != "claude" {
			name += "-inherited"
			route = groupNames[id]
			classified := false
			if native[route] {
				for _, r := range original {
					fields, end := targetPart(r)
					if fields[end] == route && fields[0] != "MATCH" {
						classified = true
						break
					}
				}
			}
			if !classified {
				if !hasOverride && !registryOverride {
					continue
				}
				route = defaultTarget
				if p.assigned[defaultID] == "" && (route == "DIRECT" || route == "REJECT" || route == "REJECT-DROP") && !registryOverride {
					continue
				}
			}
			if registryOverride {
				route = defaultTarget
			}
		}
		protected := policy.Protects(id)
		route = routeFor(id, route, protected)
		groups = append(groups, map[string]interface{}{"name": name, "type": "select", "proxies": []string{route}})
		expected[name] = route
		if forced[id] {
			strict := dedicatedGroup(id)
			groups = append(groups, map[string]interface{}{"name": strict, "type": "select", "proxies": []string{route}})
			expected[strict] = route
		}
		seen := map[string]bool{}
		withoutYouTube := ""
		if id == "google" && p.assigned["youtube"] == "" {
			withoutYouTube = youtubeCondition(services, original)
		}
		add := func(r string) {
			if withoutYouTube != "" && !strings.HasPrefix(r, "IN-NAME,") {
				fields, end := targetPart(r)
				r = "AND,((" + ruleCondition(fields, end) + "),(" + withoutYouTube + "))," + fields[end]
			}
			if !seen[r] {
				if registryOverride {
					// The policy override changes failover only for VPN matches.
					// Other addresses of the same service still follow DIRECT.
					fields, end := targetPart(r)
					condition := ruleCondition(fields, end)
					combine := func(set string) []string {
						predicate := "AND,((" + condition + "),(RULE-SET," + set + ")),"
						return []string{predicate + name, predicate + terminal(protected)}
					}
					registryDomainOverrides = append(registryDomainOverrides, combine(refilterSites)...)
					registryIPOverrides = append(registryIPOverrides, combine(refilterIPs)...)
					seen[r] = true
					return
				}
				priority = append(priority, r)
				// Mihomo continues to the next rule if a matched adapter lacks
				// UDP, is missing or is PASS. A second identical predicate
				// terminates that path in REJECT before any owner DIRECT.
				if key != directTarget {
					fields, end := targetPart(r)
					fields[end] = terminal(protected)
					priority = append(priority, strings.Join(fields, ","))
				}
				seen[r] = true
			}
		}
		if forced[id] {
			add("IN-NAME," + serviceInbound(id) + "," + dedicatedGroup(id))
		}
		if id == "claude" {
			for _, cidr := range []string{"160.79.104.0/23", "153.61.224.0/22", "2607:6bc0::/48"} {
				add("IP-CIDR," + cidr + "," + name + ",no-resolve")
			}
		}
		for _, domain := range service.Domains {
			if suffix, ok := strings.CutPrefix(domain, "domain:"); ok {
				add("DOMAIN-SUFFIX," + suffix + "," + name)
			}
		}
		// Reuse the classifier from this installation (including GeoSite
		// categories and IP ranges compiled from its local databases).
		for _, r := range original {
			parts, end := targetPart(r)
			if parts[end] == groupNames[id] && parts[0] != "MATCH" {
				parts[end] = name
				add(strings.Join(parts, ","))
			}
		}
		if id == "claude" {
			claudeRuleCount = len(priority)
		}
	}
	// The owner's leading direct exceptions retain their original priority
	// over ordinary service cards. Claude has an explicit no-direct policy.
	// A catch-all DIRECT remains at its original default boundary.
	head := 0
	for _, rule := range original {
		fields, target := targetPart(rule)
		if fields[target] != "DIRECT" || fields[0] == "MATCH" {
			break
		}
		head++
	}
	rules := make([]string, 0, len(priority)+len(original))
	rules = append(rules, priority[:claudeRuleCount]...)
	rules = append(rules, original[:head]...)
	rules = append(rules, priority[claudeRuleCount:]...)
	defaultKey := p.assigned[defaultID]
	if defaultKey != "" || registry.Enabled {
		if registry.Enabled && defaultKey == "" && !native[defaultTarget] {
			return nil, errors.New("для совпадений Re:filter сначала выберите основной VPN-сервер или пул")
		}
		name := cardPrefix + defaultID
		route := routeFor(defaultID, defaultTarget, policy.Enabled)
		groups = append(groups, map[string]interface{}{"name": name, "type": "select", "proxies": []string{route}})
		expected[name] = route
	}
	if registry.Enabled {
		// Keep the owner's base rules after a managed terminal MATCH. They
		// remain available to service classifiers, nativeDefault and undo,
		// while inherited broad VPN groups cannot capture unlisted sites.
		direct := terminal(false)
		for _, r := range original[head:] {
			f, end := targetPart(r)
			if f[0] == "MATCH" {
				continue
			}
			switch f[end] {
			case "DIRECT":
				f[end] = direct
			case "REJECT", "REJECT-DROP":
				if f[end] == "REJECT-DROP" {
					drop := cardPrefix + "refilter-drop"
					if expected[drop] == "" {
						groups = append(groups, map[string]interface{}{"name": drop, "type": "select", "proxies": []string{"REJECT-DROP"}})
						expected[drop] = "REJECT-DROP"
					}
					f[end] = drop
				} else {
					f[end] = rejectGroup
				}
			default:
				continue
			}
			rules = append(rules, strings.Join(f, ","))
		}
		for _, cidr := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"} {
			rules = append(rules, "IP-CIDR,"+cidr+","+direct+",no-resolve")
		}
		route := cardPrefix + defaultID
		rules = append(rules, registryDomainOverrides...)
		rules = append(rules, "RULE-SET,"+refilterSites+","+route, "RULE-SET,"+refilterSites+","+terminal(policy.Enabled))
		// Explicitly known names have already matched the domain database.
		// An IP-only prefix on a shared CDN should not take over another host.
		rules = append(rules, "DOMAIN-REGEX,.+,"+direct)
		rules = append(rules, registryIPOverrides...)
		rules = append(rules,
			"RULE-SET,"+refilterIPs+","+route+",no-resolve", "RULE-SET,"+refilterIPs+","+terminal(policy.Enabled)+",no-resolve",
			"MATCH,"+direct)
	}
	found := false
	guard, err := prepareServiceGuard(p.doc, services, policy, p.assigned, !registry.Enabled && !policy.Enabled)
	if err != nil {
		return nil, err
	}
	for _, r := range original[head:] {
		parts, end := targetPart(r)
		dst := parts[end]
		selectedDefault := parts[0] == "MATCH" && defaultKey != ""
		if !selectedDefault && native[dst] || selectedDefault && defaultKey != directTarget {
			if predicate := guard.predicate(parts, end); predicate != "" {
				route := dst
				if selectedDefault {
					route = defaultTarget
				}
				sum := sha256.Sum256([]byte(route))
				name := fmt.Sprintf("%sstrict-%x", cardPrefix, sum[:16])
				if expected[name] == "" {
					groups = append(groups, map[string]interface{}{"name": name, "type": "select", "proxies": []string{route}})
					expected[name] = route
				}
				rules = append(rules, predicate+","+name, predicate+","+rejectGroup)
			}
		}
		if parts[0] == "MATCH" && defaultKey != "" {
			parts[end] = cardPrefix + defaultID
			rules = append(rules, strings.Join(parts, ","))
			parts[end] = terminal(policy.Enabled)
			rules = append(rules, strings.Join(parts, ","))
			found = true
		} else if native[dst] && !policy.Enabled {
			parts[end] = routeFor("native", dst, false)
			rules = append(rules, strings.Join(parts, ","))
			parts[end] = terminal(false)
			rules = append(rules, strings.Join(parts, ","))
		}
		rules = append(rules, r)
		if native[dst] && policy.Enabled {
			// Unsupported UDP and PASS adapters otherwise continue into the
			// owner's next (potentially DIRECT) rule.
			parts[end] = rejectGroup
			rules = append(rules, strings.Join(parts, ","))
		}
	}
	if defaultKey != "" && !found {
		return nil, errors.New("в профиле отсутствует правило MATCH для общего маршрута")
	}
	p.doc[stateKey] = p.assigned
	p.doc["proxies"], p.doc["proxy-groups"], p.doc["rules"] = nodes, groups, rules
	return expected, nil
}

func (c *Controller) drain(ctx context.Context, a coreAPI, id, want string, services []xkeen.ServiceRouteView) bool {
	var snapshot struct {
		Connections []struct {
			ID       string
			Chains   []string
			Rule     string
			Metadata struct {
				Host          string
				SniffHost     string
				DestinationIP string
				InboundName   string
			}
		}
	}
	if a.request(ctx, "GET", "/connections", nil, &snapshot) != nil {
		return false
	}
	var suffixes []string
	for _, s := range services {
		if s.ID == id {
			suffixes = s.Domains
			break
		}
	}
	for _, flow := range snapshot.Connections {
		relevant, current := false, false
		if id == defaultID && strings.EqualFold(flow.Rule, "Match") {
			relevant = true
		}
		for _, chain := range flow.Chains {
			if chain == cardPrefix+id || chain == cardPrefix+id+"-inherited" || chain != "" && chain == groupNames[id] || chain == dedicatedGroup(id) {
				relevant = true
			}
			if chain == want {
				current = true
			}
		}
		for _, name := range []string{flow.Metadata.Host, flow.Metadata.SniffHost} {
			name = strings.TrimSuffix(strings.ToLower(name), ".")
			for _, d := range suffixes {
				if suffix, ok := strings.CutPrefix(d, "domain:"); ok && (name == suffix || strings.HasSuffix(name, "."+suffix)) {
					relevant = true
				}
			}
		}
		if flow.Metadata.InboundName == serviceInbound(id) {
			relevant = true
		}
		if id == "claude" {
			if ip, err := netip.ParseAddr(flow.Metadata.DestinationIP); err == nil {
				for _, cidr := range []string{"160.79.104.0/23", "153.61.224.0/22", "2607:6bc0::/48"} {
					if netip.MustParsePrefix(cidr).Contains(ip) {
						relevant = true
					}
				}
			}
		}
		// On removal, terminate only traffic previously using the protected
		// group, not all connections sharing today's ordinary classifier.
		if want == "" {
			relevant = flow.Metadata.InboundName == serviceInbound(id)
			for _, chain := range flow.Chains {
				if chain == cardPrefix+id || chain == dedicatedGroup(id) {
					relevant = true
				}
			}
		}
		if relevant && !current {
			if flow.ID == "" || a.request(ctx, "DELETE", "/connections/"+url.PathEscape(flow.ID), nil, nil) != nil {
				return false
			}
		}
	}
	return true
}

func (c *Controller) drainObsoleteFallback(ctx context.Context, api coreAPI, expected map[string]string, doc map[string]interface{}) bool {
	var snapshot struct {
		Connections []connectionTracker
	}
	if api.request(ctx, "GET", "/connections", nil, &snapshot) != nil {
		return false
	}
	policy, err := readKillSwitch(doc)
	if err != nil {
		return false
	}
	protectedAuto := map[string]bool{}
	direct := map[string]bool{"DIRECT": true, "COMPATIBLE": true}
	for _, value := range list(doc["proxies"]) {
		proxy := object(value)
		if strings.EqualFold(str(proxy["type"]), "direct") {
			direct[str(proxy["name"])] = true
		}
	}
	for _, value := range list(doc["proxy-groups"]) {
		group := object(value)
		if group[nativeGuardKey] != nil && str(group["type"]) != "select" {
			protectedAuto[str(group["name"])] = true
		}
	}
	registry := refilterEnabled(doc)
	registryDirect := map[string]bool{}
	ownerService := map[string]string{}
	for _, rule := range namesOf(doc["rules"]) {
		f, end := targetPart(rule)
		if end != 2 || strings.HasPrefix(f[end], cardPrefix) {
			continue
		}
		if f[0] == "RULE-SET" && f[end] == "DIRECT" {
			registryDirect[f[1]] = true
		}
		// A terminal rule hides the preceding VPN adapter from the chain.
		// For IP/port matches without a host, identify the owner's original
		// service classifier from the predicate reported by the tracker.
		key := strings.ToLower(strings.ReplaceAll(f[0], "-", "")) + "," + f[1]
		if _, earlier := ownerService[key]; !earlier {
			ownerService[key] = diagnosticServiceTags[f[end]]
		}
	}
	for _, flow := range snapshot.Connections {
		stale, fromAuto, wentDirect := false, false, false
		// A general fallback remains available for other destinations after
		// a card becomes strict. Drain established direct fallback sockets for
		// this service without touching traffic explicitly routed to DIRECT.
		if len(flow.Chains) >= 2 && direct[flow.Chains[0]] {
			adapter := flow.Chains[1]
			id := xkeen.ServiceForHost(flow.Metadata.Host)
			if id == "" {
				id = xkeen.ServiceForHost(flow.Metadata.SniffHost)
			}
			switch {
			case strings.HasPrefix(adapter, failoverPrefix):
				if id == "" {
					id = diagnosticServiceTags[expected[adapter]]
				}
				stale = id != "" && policy.Protects(id)
			case adapter == cardPrefix+"direct":
				// In an ordinary profile this terminal belongs only to VPN
				// failover (e.g. unsupported UDP). Re:filter also uses it
				// for explicitly direct names, private ranges and its catch-all.
				registryFallback := strings.EqualFold(flow.Rule, "RuleSet") && (flow.RulePayload == refilterSites || flow.RulePayload == refilterIPs) && !registryDirect[flow.RulePayload]
				if !registry || registryFallback {
					if id == "" {
						id = ownerService[strings.ToLower(flow.Rule)+","+flow.RulePayload]
					}
					stale = id != "" && policy.Protects(id)
				}
			}
		}
		for _, chain := range flow.Chains {
			fromAuto = fromAuto || protectedAuto[chain]
			wentDirect = wentDirect || direct[chain]
			// A connection opened before the YouTube split can outlive the
			// hot reload. The managed transparent Google card no longer owns it.
			if (chain == cardPrefix+"google" || chain == cardPrefix+"google-inherited") &&
				(xkeen.ServiceForHost(flow.Metadata.Host) == "youtube" || xkeen.ServiceForHost(flow.Metadata.SniffHost) == "youtube") {
				stale = true
			}
			if strings.HasPrefix(chain, failoverPrefix) && expected[chain] == "" || chain == cardPrefix+"direct" && expected[chain] == "" {
				stale = true
			}
		}
		if (stale || fromAuto && wentDirect) && (flow.ID == "" || api.request(ctx, "DELETE", "/connections/"+url.PathEscape(flow.ID), nil, nil) != nil) {
			return false
		}
	}
	return true
}
