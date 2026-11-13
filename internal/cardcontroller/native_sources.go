package cardcontroller

import "xkeen-panel/internal/models"

// SetSourceProviderURLs is wired before HTTP and monitoring start.
func (c *Controller) SetSourceProviderURLs(read func() map[string]string) {
	c.sourceProviderURLs = read
}

// Native groups identify members only by display name. An independently
// imported subscription with the same names cannot identify a native member.
// Older installations may use the provider's alternate Clash URL; only the
// original catalog is eligible to identify such an unlinked provider.
func (c *Controller) nativeServers(p profile, groupName string, catalog []models.Server) []models.Server {
	if c.sourceProviderURLs == nil {
		return catalog
	}
	sources := c.sourceProviderURLs()
	urls := map[string]bool{}
	used := map[string]bool{}
	allProviders := groupName == ""
	if groupName != "" {
		for _, raw := range list(p.doc["proxy-groups"]) {
			group := object(raw)
			if str(group["name"]) != groupName {
				continue
			}
			includeAll, _ := group["include-all"].(bool)
			includeProviders, _ := group["include-all-providers"].(bool)
			allProviders = includeAll || includeProviders
			for _, rawName := range list(group["use"]) {
				used[str(rawName)] = true
			}
			break
		}
	}
	legacyEligible := !allProviders && len(used) == 0
	knownURLs := map[string]bool{}
	configured := map[string]bool{}
	for _, source := range sources {
		if source != "" {
			knownURLs[source] = true
		}
	}
	for providerName, raw := range object(p.doc["proxy-providers"]) {
		url := str(object(raw)["url"])
		if url != "" {
			configured[url] = true
		}
		if !allProviders && !used[providerName] {
			continue
		}
		if url != "" && knownURLs[url] {
			urls[url] = true
		} else {
			legacyEligible = true
		}
	}
	if len(object(p.doc["proxy-providers"])) == 0 {
		legacyEligible = true
	}
	result := make([]models.Server, 0, len(catalog))
	for _, s := range catalog {
		linkedElsewhere := configured[sources[s.SourceID]]
		if urls[sources[s.SourceID]] || legacyEligible && !linkedElsewhere && (s.SourceID == "legacy" || s.SourceID == "") {
			result = append(result, s)
		}
	}
	return result
}
