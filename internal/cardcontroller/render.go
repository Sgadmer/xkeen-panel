package cardcontroller

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"xkeen-panel/internal/xkeen"
)

var groupNames = map[string]string{
	"claude": "Claude", "openai": "ChatGPT", "youtube": "YouTube", "telegram": "Telegram",
	"analytics": "Аналитика и диагностика",
	"discord":   "Discord", "spotify": "Spotify", "github": "GitHub", "steam": "Steam",
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
	serviceLists, err := readServiceLists(p.doc)
	if err != nil {
		return nil, err
	}
	if _, owned := p.doc[serviceListsKey]; owned {
		if err := serviceListProviders(p.doc, serviceLists); err != nil {
			return nil, err
		}
	}
	if serviceLists.Enabled {
		services = serviceListOrder(services)
	}
	policy, err := readKillSwitch(p.doc)
	if err != nil {
		return nil, err
	}
	registry, err := readRefilter(p.doc)
	if err != nil {
		return nil, err
	}
	_, protectedRouting, err := readProtectedRouting(p.doc)
	if err != nil {
		return nil, err
	}
	protectedRouting = protectedRouting && !registry.Enabled
	if protectedRouting {
		if err := validateProtectedExclusions(p.doc); err != nil {
			return nil, err
		}
		if !validHash(p.assigned[defaultID]) {
			return nil, errors.New("в защищённом режиме отсутствует общий VPN-маршрут")
		}
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
		if serviceLists.Enabled {
			r = scopeDiscordRule(r)
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
			// A REJECT added because the chosen server was removed with its
			// subscription is not the owner's block: the group's rules stay
			// as dormant or as live as they were before the removal.
			for _, child := range blockAfterRemoval(group) {
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
	serviceTerminal := func(id string, protected bool) string {
		if !protected || !serviceLists.Enabled && !protectedRouting {
			return terminal(protected)
		}
		name := serviceGuardName(id)
		if _, exists := expected[name]; !exists {
			groups = append(groups, map[string]interface{}{"name": name, "type": "select", "proxies": []string{"REJECT"}})
			expected[name] = "REJECT"
		}
		return name
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
	// Explicit direct exceptions keep their priority for telemetry. Claude's
	// protected classifiers still run before the original exceptions below.
	head := 0
	var analyticsBypasses []string
	// Pattern exclusions are wide by nature. They keep their place among the
	// owner's leading rules on disk, but are evaluated below every service card:
	// a pattern can not take an address away from a card, telemetry included.
	var leading, patterns []string
	for _, rule := range original {
		fields, target := targetPart(rule)
		if fields[target] != "DIRECT" || fields[0] == "MATCH" || protectedRouting && !protectedDirectRule(fields, target) {
			break
		}
		head++
		if fields[0] == "DOMAIN-REGEX" && target == 2 {
			if _, pattern := xkeen.PatternFromRegex(fields[1]); pattern {
				patterns = append(patterns, rule)
				continue
			}
		}
		leading = append(leading, rule)
		analyticsBypasses = append(analyticsBypasses, "("+ruleCondition(fields, target)+")")
	}
	priority := []string{}
	var analyticsRules, dedicatedRules []string
	var specific []string
	earlierDomains := map[string]bool{}
	autoDefaults := p.doc[serviceAutoKey] == true
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
		baseDestination := &priority
		if id == "analytics" {
			baseDestination = &analyticsRules
		}
		destination := baseDestination
		add := func(r string) {
			if id == "analytics" && !strings.HasPrefix(r, "IN-NAME,") && len(analyticsBypasses) > 0 {
				fields, end := targetPart(r)
				exclusions := "NOT,((OR,(" + strings.Join(analyticsBypasses, ",") + ")))"
				r = "AND,((" + ruleCondition(fields, end) + "),(" + exclusions + "))," + fields[end]
			}
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
						return []string{predicate + name, predicate + serviceTerminal(id, protected)}
					}
					registryDomainOverrides = append(registryDomainOverrides, combine(refilterSites)...)
					registryIPOverrides = append(registryIPOverrides, combine(refilterIPs)...)
					seen[r] = true
					return
				}
				*destination = append(*destination, r)
				// Mihomo continues to the next rule if a matched adapter lacks
				// UDP, is missing or is PASS. A second identical predicate
				// terminates that path in REJECT before any owner DIRECT.
				if key != directTarget {
					fields, end := targetPart(r)
					fields[end] = serviceTerminal(id, protected)
					*destination = append(*destination, strings.Join(fields, ","))
				}
				seen[r] = true
			}
		}
		if forced[id] {
			destination = &dedicatedRules
			add("IN-NAME," + serviceInbound(id) + "," + dedicatedGroup(id))
			destination = baseDestination
		}
		if id == "claude" || autoDefaults {
			for _, cidr := range xkeen.ServiceNetworks(id) {
				add("IP-CIDR," + cidr + "," + name + ",no-resolve")
			}
		}
		for _, domain := range service.Domains {
			if suffix, ok := strings.CutPrefix(domain, "domain:"); ok {
				// A specific app such as Gemini can share its parent domain
				// with a card that comes earlier (Google). Promote only that
				// suffix, leaving broad GeoSite categories in their original order.
				if autoDefaults {
					for _, parent, found := strings.Cut(suffix, "."); found; _, parent, found = strings.Cut(parent, ".") {
						if earlierDomains[parent] {
							destination = &specific
							break
						}
					}
				}
				add("DOMAIN-SUFFIX," + suffix + "," + name)
				destination = baseDestination
			} else if host, ok := strings.CutPrefix(domain, "full:"); ok {
				add("DOMAIN," + host + "," + name)
			}
		}
		if serviceLists.Enabled {
			if _, available := serviceLists.Files[id]; available {
				add("RULE-SET," + serviceProviderName(id) + "," + name)
			}
			if id == "openai" {
				if _, available := serviceLists.Files[openAIVoiceListID]; available {
					add("RULE-SET," + serviceProviderName(openAIVoiceListID) + "," + name + ",no-resolve")
				}
				for _, host := range openAISharedDomains {
					add("DOMAIN," + host + "," + name)
				}
			}
			if id == "discord" {
				for _, prefix := range []string{"5.200.14.128/25", "66.22.192.0/18", "138.128.136.0/21"} {
					add(discordVoicePredicate("IP-CIDR,"+prefix+",no-resolve") + "," + name)
				}
			}
		}
		if autoDefaults {
			for _, domain := range service.Domains {
				if suffix, ok := strings.CutPrefix(domain, "domain:"); ok {
					earlierDomains[suffix] = true
				}
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
	rules := make([]string, 0, len(priority)+len(original))
	if domainRules := domainPolicyRules(p.doc); len(domainRules) > 0 {
		name := serviceGuardName("quic")
		groups = append(groups, map[string]interface{}{"name": name, "type": "select", "proxies": []string{"REJECT"}})
		expected[name] = "REJECT"
		rules = append(rules, domainRules...)
	}
	// An application explicitly using its own authenticated proxy retains the
	// whole-application route. Shared collectors use the analytics card only
	// for normal transparent traffic, before overlapping app domain datasets.
	rules = append(rules, dedicatedRules...)
	rules = append(rules, analyticsRules...)
	rules = append(rules, priority[:claudeRuleCount]...)
	rules = append(rules, leading...)
	rules = append(rules, specific...)
	rules = append(rules, priority[claudeRuleCount:]...)
	rules = append(rules, patterns...)
	defaultKey := p.assigned[defaultID]
	if defaultKey != "" || registry.Enabled || protectedRouting {
		if registry.Enabled && defaultKey == "" && !native[defaultTarget] {
			return nil, errors.New("для совпадений Re:filter сначала выберите основной VPN-сервер или пул")
		}
		name := cardPrefix + defaultID
		route := routeFor(defaultID, defaultTarget, policy.Enabled)
		groups = append(groups, map[string]interface{}{"name": name, "type": "select", "proxies": []string{route}})
		expected[name] = route
	}
	if protectedRouting {
		// The explicit panel mode owns the fallback. Keep deliberate named
		// bypasses and blocks above it, and retain a lossless provider tail
		// below the terminal MATCH. Generic DIRECT aliases and broad provider
		// rules can no longer release an unidentified service request.
		for _, rule := range original[head:] {
			fields, end := targetPart(rule)
			if fields[0] == "MATCH" {
				continue
			}
			target := fields[end]
			if target == "DIRECT" && protectedDirectRule(fields, end) {
				fields[end] = terminal(false)
			} else if manualBlocks[target] {
				if target == "REJECT" {
					fields[end] = rejectGroup
				} else {
					sum := sha256.Sum256([]byte(target))
					name := fmt.Sprintf("%sprotected-owner-%x", cardPrefix, sum[:12])
					if expected[name] == "" {
						groups = append(groups, map[string]interface{}{"name": name, "type": "select", "proxies": []string{target}})
						expected[name] = target
					}
					fields[end] = name
				}
			} else {
				continue
			}
			rules = append(rules, strings.Join(fields, ","))
		}
		for _, cidr := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"} {
			rules = append(rules, "IP-CIDR,"+cidr+","+terminal(false)+",no-resolve")
		}
		rules = append(rules, "MATCH,"+cardPrefix+defaultID, "MATCH,"+serviceTerminal(defaultID, policy.Enabled))
		rules = append(rules, original[head:]...)
		p.doc[stateKey] = p.assigned
		p.doc["proxies"], p.doc["proxy-groups"], p.doc["rules"] = nodes, groups, rules
		return expected, nil
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
		rules = append(rules, "RULE-SET,"+refilterSites+","+route, "RULE-SET,"+refilterSites+","+serviceTerminal(defaultID, policy.Enabled))
		// Explicitly known names have already matched the domain database.
		// An IP-only prefix on a shared CDN should not take over another host.
		rules = append(rules, "DOMAIN-REGEX,.+,"+direct)
		rules = append(rules, registryIPOverrides...)
		rules = append(rules,
			"RULE-SET,"+refilterIPs+","+route+",no-resolve", "RULE-SET,"+refilterIPs+","+serviceTerminal(defaultID, policy.Enabled)+",no-resolve",
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
			parts[end] = serviceTerminal(defaultID, policy.Enabled)
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

// drainChanged samples established connections once for the whole transaction.
// A connection can match both a parent and a child card, so decide its service
// before comparing its live chain to the new destination.
func (c *Controller) drainChanged(ctx context.Context, p profile, changes map[string]string, services []xkeen.ServiceRouteView) map[string]bool {
	failed := map[string]bool{}
	if len(changes) == 0 {
		return failed
	}
	var snapshot struct{ Connections []connectionTracker }
	if err := p.api.request(ctx, "GET", "/connections", nil, &snapshot); err != nil {
		for id := range changes {
			failed[id] = true
		}
		return failed
	}

	domains := map[string]string{}
	exactDomains := map[string]string{}
	var analyticsMatches func(string) bool
	if _, changed := changes["analytics"]; changed {
		match, err := c.analyticsMatcher(p)
		if err != nil {
			failed["analytics"] = true
		} else {
			analyticsMatches = match
		}
	}
	inbounds := map[string]string{}
	type network struct {
		id     string
		prefix netip.Prefix
	}
	var networks []network
	if _, changed := changes["openai"]; changed {
		prefixes, err := c.openAIVoicePrefixes(p)
		if err != nil {
			failed["openai"] = true
		} else {
			for _, prefix := range prefixes {
				networks = append(networks, network{"openai", prefix})
			}
		}
	}
	for _, service := range services {
		id := service.ID
		inbounds[serviceInbound(id)] = id
		for _, domain := range service.Domains {
			if suffix, ok := strings.CutPrefix(domain, "domain:"); ok && domains[suffix] == "" {
				domains[suffix] = id
			} else if host, ok := strings.CutPrefix(domain, "full:"); ok && exactDomains[host] == "" {
				exactDomains[host] = id
			}
		}
		if id == "claude" || p.doc[serviceAutoKey] == true {
			for _, cidr := range xkeen.ServiceNetworks(id) {
				networks = append(networks, network{id, netip.MustParsePrefix(cidr)})
			}
		}
	}

	// Owner direct exemptions are before ordinary service rules. A connection
	// matched on one of these predicates may survive the new service policy.
	exempt := map[string]bool{}
	ownerHead := true
	for _, raw := range namesOf(p.doc["rules"]) {
		f, end := targetPart(raw)
		if end < 1 || strings.HasPrefix(f[end], cardPrefix) {
			continue
		}
		if end > 1 && ownerHead && f[end] == "DIRECT" && f[0] != "MATCH" {
			exempt[strings.ToLower(strings.ReplaceAll(f[0], "-", ""))+","+strings.Join(f[1:end], ",")] = true
		} else {
			ownerHead = false
		}
		id := diagnosticServiceTags[f[end]]
		if end == 2 && id != "" && (f[0] == "IP-CIDR" || f[0] == "IP-CIDR6") {
			if prefix, err := netip.ParsePrefix(f[1]); err == nil {
				networks = append(networks, network{id, prefix})
			}
		}
	}
	for _, flow := range snapshot.Connections {
		id := inbounds[flow.Metadata.InboundName]
		if id == "" {
			for _, name := range []string{flow.Metadata.SniffHost, flow.Metadata.Host} {
				host := strings.ToLower(strings.TrimSuffix(name, "."))
				if analyticsMatches != nil && analyticsMatches(host) {
					id = "analytics"
					break
				}
				if id = exactDomains[host]; id != "" {
					break
				}
				for host != "" {
					if id = domains[host]; id != "" {
						break
					}
					_, host, _ = strings.Cut(host, ".")
				}
				if id != "" {
					break
				}
			}
			if ip, err := netip.ParseAddr(flow.Metadata.DestinationIP); err == nil {
				for _, net := range networks {
					if net.prefix.Contains(ip) && (id == "" || net.id == "claude" && id != "analytics") {
						id = net.id
					}
				}
			}
			if id == "" {
				for _, tag := range flow.Chains {
					if id = diagnosticServiceTags[tag]; id != "" {
						break
					}
				}
			}
			if id != "claude" && slices.Contains(flow.Chains, "DIRECT") &&
				exempt[strings.ToLower(strings.ReplaceAll(flow.Rule, "-", ""))+","+flow.RulePayload] {
				continue
			}
		}
		if strings.EqualFold(flow.Rule, "Match") {
			_, cardChanged := changes[id]
			if id == "" || !cardChanged && p.assigned[id] == "" {
				id = defaultID
			}
		}
		want, changed := changes[id]
		if !changed || slices.Contains(flow.Chains, want) {
			continue
		}
		if want == "" && flow.Metadata.InboundName != serviceInbound(id) &&
			!slices.Contains(flow.Chains, cardPrefix+id) && !slices.Contains(flow.Chains, dedicatedGroup(id)) {
			continue
		}
		if flow.ID == "" {
			failed[id] = true
			continue
		}
		err := p.api.request(ctx, "DELETE", "/connections/"+url.PathEscape(flow.ID), nil, nil)
		if err != nil && !errors.Is(err, apiResponseError(404)) {
			failed[id] = true
		}
	}
	return failed
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
