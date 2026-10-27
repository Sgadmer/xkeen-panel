package xkeen

import (
	"encoding/json"
	"sort"
	"strings"
)

// Some client applications provide the DNS outbound implicitly. Adapt only the
// recognizable DNS-port-only template; other missing targets remain errors.
func (r *profileRenderer) adaptClientDNSOutbounds(rules, balancers []interface{}) error {
	missing := map[string]bool{}
	for _, item := range rules {
		rule := mapOf(item)
		target, ok := rule["outboundTag"].(string)
		if !ok || r.outboundTags[target] != "" || !profileOneOf(target, "dns", "dns-out", "dns-outbound") {
			continue
		}
		if !profileDNSPort53(rule["port"]) {
			return profileError()
		}
		if _, exists := rule["balancerTag"]; exists {
			return profileError()
		}
		missing[target] = true
	}
	if len(missing) == 0 {
		return nil
	}
	if r.bundle.Globals["dns"] == nil || len(r.outbounds)+len(missing) > 256 {
		return profileError()
	}
	for _, outbound := range r.outbounds {
		proxy, _ := mapOf(outbound["proxySettings"])["tag"].(string)
		dialer, _ := mapOf(mapOf(outbound["streamSettings"])["sockopt"])["dialerProxy"].(string)
		if missing[proxy] || missing[dialer] {
			return profileError()
		}
	}
	for _, item := range balancers {
		balancer := mapOf(item)
		fallback, _ := balancer["fallbackTag"].(string)
		if missing[fallback] || profileSelectorMatchesMissing(balancer["selector"], missing) {
			return profileError()
		}
	}
	for _, key := range []string{"observatory", "burstObservatory"} {
		if profileSelectorMatchesMissing(mapOf(r.document[key])["subjectSelector"], missing) {
			return profileError()
		}
	}
	tags := make([]string, 0, len(missing))
	for tag := range missing {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		r.syntheticDNS[tag] = true
		r.outboundTags[tag] = r.bundle.Namespace + "ob-" + tag
		r.outbounds = append(r.outbounds, map[string]interface{}{"tag": tag, "protocol": "dns", "settings": map[string]interface{}{}})
	}
	r.bundle.Adaptations = append(r.bundle.Adaptations, "Добавлен встроенный DNS-выход для клиентского шаблона провайдера.")
	return nil
}

func profileDNSPort53(value interface{}) bool {
	switch port := value.(type) {
	case string:
		return port == "53"
	case json.Number:
		return port.String() == "53"
	default:
		return false
	}
}

func profileSelectorMatchesMissing(value interface{}, missing map[string]bool) bool {
	selectors, err := profileStrings(value)
	if err != nil {
		return false // The ordinary balancer/observer validator rejects malformed selectors.
	}
	for _, selector := range selectors {
		for tag := range missing {
			if strings.HasPrefix(tag, selector) {
				return true
			}
		}
	}
	return false
}

func (r *profileRenderer) isSourceClientInput(tag string) bool {
	if tag == r.bundle.InboundTag {
		return true
	}
	for source, mapped := range r.inboundTags {
		if mapped == r.bundle.InboundTag && r.loopbackTags[source] == tag {
			return true
		}
	}
	return false
}
