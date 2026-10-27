package xkeen

import "xkeen-panel/internal/models"

func buildSubscriptionPool(servers []models.Server, selection PoolSelection, selector string, template map[string]interface{}, layout PoolLayout) ([]interface{}, error) {
	selected := SelectPoolServers(servers, selection)
	if len(selected) > 0 {
		return BuildPoolOutbounds(selected, selector, template, layout)
	}
	for _, server := range servers {
		if CanBuildServer(server) {
			if selector == "" {
				selector = DefaultPoolSelector
			}
			// A subscription consisting of profiles (or countries excluded from
			// auto selection) still needs an outer balancer for explicit manual pins.
			// Fail closed until that manual target has been installed and acknowledged.
			return []interface{}{map[string]interface{}{"tag": selector + "guard", "protocol": "blackhole"}}, nil
		}
	}
	return BuildPoolOutbounds(selected, selector, template, layout)
}
