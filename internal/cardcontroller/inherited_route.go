package cardcontroller

import (
	"context"
	"strings"

	"xkeen-panel/internal/xkeen"
)

func inheritedGroups(rules []liveRule) map[string]bool {
	groups := make(map[string]bool)
	for _, rule := range rules {
		if rule.Extra.Disabled {
			continue
		}
		// A catch-all is not a classifier for a particular service.
		if strings.EqualFold(rule.Type, "match") {
			break
		}
		groups[rule.Proxy] = true
	}
	return groups
}

// Some Mihomo versions list only the group and its member names in /proxies.
// Look up provider-backed adapters once for this snapshot if one is needed.
func (a coreAPI) providerNodes(ctx context.Context) map[string]selector {
	var response struct {
		Providers map[string]struct {
			Proxies []struct {
				Name string
				selector
			}
		}
	}
	nodes := make(map[string]selector)
	if a.request(ctx, "GET", "/providers/proxies", nil, &response) != nil {
		return nodes
	}
	for _, provider := range response.Providers {
		for _, node := range provider.Proxies {
			// Different providers can reuse a name for incompatible adapters.
			if other, ok := nodes[node.Name]; ok && !strings.EqualFold(other.Type, node.Type) {
				nodes[node.Name] = selector{}
				continue
			}
			nodes[node.Name] = node.selector
		}
	}
	return nodes
}

func publicRouteName(name string, targets map[string]string) string {
	if strings.HasPrefix(name, nodePrefix) {
		name = targets[name]
	}
	if strings.HasPrefix(name, "XKP-") || strings.Contains(name, "://") || strings.ContainsAny(name, "\n\r") {
		return ""
	}
	return name
}

func inheritedRoute(group string, live map[string]selector, targets map[string]string, providerNode func(string) selector) *xkeen.InheritedRoute {
	route := &xkeen.InheritedRoute{Group: group, Via: []string{}, Kind: "unknown"}
	seen := map[string]bool{}
	for name := group; name != "" && !seen[name]; {
		seen[name] = true
		node, ok := live[name]
		if !ok && name != group {
			node = providerNode(name)
		}
		var strategy string
		switch strings.ToLower(node.Type) {
		case "direct":
			route.Kind = "direct"
			return route
		case "reject", "rejectdrop", "reject-drop":
			route.Kind = "reject"
			return route
		case "urltest", "url-test":
			strategy = "url-test"
		case "fallback":
			strategy = "fallback"
		case "loadbalance", "load-balance":
			strategy = "load-balance"
		case "selector", "select":
		case "", "pass", "compatible", "relay", "dns":
			return route
		default:
			if node.Now == "" && node.All == nil {
				if label := publicRouteName(name, targets); label != "" {
					route.Kind, route.Endpoint = "server", label
				}
			}
			return route
		}
		if name != group {
			if label := publicRouteName(name, targets); label != "" {
				route.Via = append(route.Via, label)
			}
		}
		if strategy != "" {
			route.Strategy = strategy
			route.Members = nil
			for _, member := range node.All {
				if label := publicRouteName(member, targets); label != "" {
					route.Members = append(route.Members, label)
				}
			}
			if strategy == "load-balance" { // the member depends on the connection
				return route
			}
		}
		name = node.Now
	}
	return route
}
