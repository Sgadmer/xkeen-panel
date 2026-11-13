package cardcontroller

import (
	"context"
	"errors"
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

func render(p *profile, services []xkeen.ServiceRouteView, peers map[string]xkeen.CardProxy) (map[string]string, error) {
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
	used := map[string]bool{}
	expected := map[string]string{}
	rejectGroup := cardPrefix + "reject"
	groups = append(groups, map[string]interface{}{"name": rejectGroup, "type": "select", "proxies": []string{"REJECT"}})
	expected[rejectGroup] = "REJECT"
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
	claudeRuleCount := 0
	for _, service := range services {
		id := service.ID
		key := p.assigned[id]
		// A broad assigned GEOSITE (e.g. Google or AI) must not silently
		// take over a more specific existing group. Keep the original group
		// for those destination matches in the same specific-first order.
		protectChild := key == "" && (id == "youtube" && p.assigned["google"] != "" || id == "primevideo" && p.assigned["amazon"] != "" || id == "openai" && p.assigned["ai"] != "")
		if key == "" && id != "claude" && !protectChild {
			continue
		}
		name := cardPrefix + id
		route := "REJECT"
		if key == directTarget {
			route = "DIRECT"
		} else if peer, ok := peers[key]; ok {
			route = nodePrefix + key
			if !used[key] {
				nodes = append(nodes, map[string]interface{}{"name": route, "type": "vless", "server": "127.0.0.1", "port": peer.Port, "uuid": peer.UUID, "network": "tcp", "tls": true, "servername": peer.ServerName, "fingerprint": peer.Fingerprint, "udp": true})
				used[key] = true
			}
		}
		if protectChild {
			name += "-inherited"
			route = groupNames[id]
			defined := false
			for _, group := range groups {
				if str(object(group)["name"]) == route {
					defined = true
					break
				}
			}
			if !defined {
				continue
			}
		}
		groups = append(groups, map[string]interface{}{"name": name, "type": "select", "proxies": []string{route}})
		expected[name] = route
		if forced[id] {
			strict := dedicatedGroup(id)
			groups = append(groups, map[string]interface{}{"name": strict, "type": "select", "proxies": []string{route}})
			expected[strict] = route
		}
		seen := map[string]bool{}
		add := func(r string) {
			if !seen[r] {
				priority = append(priority, r)
				// Mihomo continues to the next rule if a matched adapter lacks
				// UDP, is missing or is PASS. A second identical predicate
				// terminates that path in REJECT before any owner DIRECT.
				if !protectChild && key != directTarget {
					fields, end := targetPart(r)
					fields[end] = rejectGroup
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
	rules = append(rules, original[head:]...)
	p.doc[stateKey] = p.assigned
	p.doc["proxies"], p.doc["proxy-groups"], p.doc["rules"] = nodes, groups, rules
	return expected, nil
}

func (c *Controller) drain(ctx context.Context, a coreAPI, id, want string, services []xkeen.ServiceRouteView) bool {
	var snapshot struct {
		Connections []struct {
			ID       string
			Chains   []string
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
		for _, chain := range flow.Chains {
			if chain == cardPrefix+id || chain == groupNames[id] || chain == dedicatedGroup(id) {
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
