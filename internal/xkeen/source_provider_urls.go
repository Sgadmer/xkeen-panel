package xkeen

// SourceProviderURLs is an internal snapshot for attributing native Mihomo
// provider membership to a subscription. The API never exposes these URLs.
func (sm *SubscriptionManager) SourceProviderURLs() map[string]string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	urls := make(map[string]string, len(sm.data.Sources))
	for _, source := range sm.data.Sources {
		urls[source.ID] = source.URL
	}
	return urls
}
