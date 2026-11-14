package xkeen

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"xkeen-panel/internal/models"
)

type clashGroupEndpoint struct {
	server models.Server
	udp    bool
}

// Resolve groups only against literal, unique endpoint names in this document.
// A nested group can reference another provider or DIRECT, even if its name
// happens to coincide with a supported endpoint.
func appendClashGroups(servers []models.Server, groups []interface{}, endpoints map[string]clashGroupEndpoint, report *ImportReport) []models.Server {
	names := map[string]int{}
	for _, raw := range groups {
		name, _ := mapOf(raw)["name"].(string)
		names[name]++
		if _, found := endpoints[name]; found {
			endpoints[name] = clashGroupEndpoint{}
		}
	}
	// Avoid materializing many copies of a large endpoint in repeated groups.
	budget := maxSubscriptionBody
	for i, raw := range groups {
		if len(servers) >= 4096 || budget <= 0 {
			report.SkippedComposite += len(groups) - i
			break
		}
		group := mapOf(raw)
		name, _ := group["name"].(string)
		if names[name] != 1 {
			report.SkippedComposite++
			continue
		}
		server, err := importedClashURLTest(group, endpoints, &budget)
		if err != nil {
			report.SkippedComposite++
			continue
		}
		servers = append(servers, server)
		report.ImportedProfiles++
	}
	return servers
}

func importedClashURLTest(group map[string]interface{}, endpoints map[string]clashGroupEndpoint, budget *int) (models.Server, error) {
	unsupported := models.Server{}
	f := newFormatFields(group)
	name := f.text("name")
	if f.text("type") != "url-test" || strings.TrimSpace(name) == "" {
		return unsupported, errFormatComposite
	}
	// Xray's leastPing has no equivalent to Mihomo's hysteresis or lazy
	// probing. In particular, omitted lazy defaults to true in Mihomo.
	if lazy, ok := f.take("lazy").(bool); !ok || lazy || f.integer("tolerance") != 0 {
		return unsupported, errFormatComposite
	}
	f.text("icon")
	if f.boolean("hidden") {
		return unsupported, errFormatComposite
	}
	if status := f.text("expected-status"); status != "" && status != "*" {
		return unsupported, errFormatComposite
	}
	probe := formatDefault(f.text("url"), "https://www.gstatic.com/generate_204")
	u, err := url.ParseRequestURI(probe)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return unsupported, errFormatComposite
	}
	seconds := f.integer("interval")
	if seconds == 0 {
		seconds = 300
	}
	timeout := f.integer("timeout")
	if timeout == 0 {
		timeout = 5000
	}
	// Mihomo caps its HTTP client at 30s and Xray clamps short burst intervals.
	if seconds < 10 || timeout < 1 || timeout > 30000 {
		return unsupported, errFormatComposite
	}
	denyUDP := f.boolean("disable-udp")
	items, ok := f.take("proxies").([]interface{})
	if !ok || len(items) == 0 || len(items) > MaxMultiPoolMembers || !f.valid() {
		return unsupported, errFormatComposite
	}
	const selector = "member-"
	outbounds := make([]interface{}, 0, len(items)+1)
	var allowUDP bool
	seen := map[string]bool{}
	for i, item := range items {
		ref, _ := item.(string)
		endpoint, found := endpoints[ref]
		switch strings.ToUpper(ref) {
		case "", "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL", "MATCH", "PASS-RULE":
			return unsupported, errFormatComposite
		}
		if !found || len(endpoint.server.RawOutbound) == 0 || seen[ref] {
			return unsupported, errFormatComposite
		}
		seen[ref] = true
		// Mihomo's UDP capability follows the currently measured node. A
		// mixed group cannot be represented by one static UDP route in Xray.
		if i == 0 {
			allowUDP = endpoint.udp
		}
		if !denyUDP && allowUDP != endpoint.udp {
			return unsupported, errFormatComposite
		}
		*budget -= len(endpoint.server.RawOutbound)
		if *budget < 0 {
			return unsupported, errFormatComposite
		}
		out, err := BuildServerOutbound(endpoint.server, fmt.Sprintf("%s%d", selector, i), nil)
		if err != nil || !permittedServiceOutbound(out) {
			return unsupported, errFormatComposite
		}
		outbounds = append(outbounds, out)
	}

	// Mihomo tries the first listed proxy when all measurements are absent
	// or failed. This preserves that fallback as an explicit VPN endpoint.
	balancer := balancerBlock("provider", selector)
	balancer["fallbackTag"] = "member-0"
	rules := []interface{}{}
	if denyUDP || !allowUDP {
		outbounds = append(outbounds, map[string]interface{}{"protocol": "blackhole", "tag": "block-udp"})
		rules = append(rules, map[string]interface{}{"type": "field", "network": "udp", "outboundTag": "block-udp"})
	}
	rules = append(rules, map[string]interface{}{"type": "field", "network": "tcp,udp", "balancerTag": "provider"})
	profile := map[string]interface{}{
		"remarks":   name,
		"outbounds": outbounds,
		"routing":   map[string]interface{}{"rules": rules, "balancers": []interface{}{balancer}},
		"burstObservatory": map[string]interface{}{
			"subjectSelector": []string{selector},
			"pingConfig": map[string]interface{}{"destination": probe, "interval": (time.Duration(seconds) * time.Second).String(),
				"timeout": (time.Duration(timeout) * time.Millisecond).String(), "sampling": 1, "httpMethod": "HEAD"},
		},
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		return unsupported, err
	}
	return serverFromRawProfile(raw)
}
