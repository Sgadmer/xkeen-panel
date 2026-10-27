package xkeen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"xkeen-panel/internal/models"
)

func profileFixture() map[string]interface{} {
	sniff := func() map[string]interface{} {
		return map[string]interface{}{"enabled": true, "destOverride": []interface{}{"http", "tls", "quic"}, "routeOnly": true}
	}
	return map[string]interface{}{
		"remarks": "Provider automatic",
		"inbounds": []interface{}{
			map[string]interface{}{"tag": "socks-in", "protocol": "socks", "port": 10808, "settings": map[string]interface{}{"udp": true}, "sniffing": sniff()},
			map[string]interface{}{"tag": "http-in", "protocol": "http", "port": 10809, "sniffing": sniff()},
		},
		"outbounds": []interface{}{
			map[string]interface{}{"tag": "node-1", "protocol": "vless", "settings": map[string]interface{}{"address": "one.example", "port": 443, "id": "11111111-2222-3333-4444-555555555555"}, "streamSettings": map[string]interface{}{"network": "tcp", "sockopt": map[string]interface{}{"mark": 1, "tcpFastOpen": true}}},
			map[string]interface{}{"tag": "node-2", "protocol": "vless", "settings": map[string]interface{}{"address": "two.example", "port": 443, "id": "22222222-3333-4444-5555-666666666666"}},
			map[string]interface{}{"tag": "direct", "protocol": "freedom"},
			map[string]interface{}{"tag": "block", "protocol": "blackhole"},
		},
		"routing": map[string]interface{}{
			"domainStrategy": "IPIfNonMatch",
			"balancers":      []interface{}{map[string]interface{}{"tag": "provider-auto", "selector": []interface{}{"node-"}, "fallbackTag": "direct", "strategy": map[string]interface{}{"type": "leastLoad", "settings": map[string]interface{}{"baselines": []interface{}{"30ms", "50ms"}, "expected": 2, "maxRTT": "2s", "tolerance": 0.1}}}},
			"rules": []interface{}{
				map[string]interface{}{"type": "field", "inboundTag": []interface{}{"socks-in", "http-in"}, "port": "53", "outboundTag": "direct"},
				map[string]interface{}{"type": "field", "inboundTag": []interface{}{"dns-in"}, "outboundTag": "direct"},
				map[string]interface{}{"type": "field", "domain": []interface{}{"domain:ru"}, "outboundTag": "direct"},
				map[string]interface{}{"type": "field", "network": "tcp,udp", "balancerTag": "provider-auto"},
			},
		},
		"dns":              map[string]interface{}{"tag": "dns-in", "servers": []interface{}{"1.1.1.1", map[string]interface{}{"address": "8.8.8.8", "tag": "dns-secondary"}}, "queryStrategy": "UseIPv4"},
		"burstObservatory": map[string]interface{}{"subjectSelector": []interface{}{"node-"}, "pingConfig": map[string]interface{}{"destination": "https://www.gstatic.com/generate_204", "interval": "1m", "sampling": 3, "timeout": "5s"}},
	}
}

func profileServer(t *testing.T, document map[string]interface{}) models.Server {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return models.Server{Name: "Provider automatic", Protocol: "xray-profile", RawProfile: raw, Latency: -1}
}

func TestProfileBundleScopesAndPreservesProviderLeastLoad(t *testing.T) {
	server := profileServer(t, profileFixture())
	original := append([]byte(nil), server.RawProfile...)
	template := map[string]interface{}{"streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": 255, "tcpFastOpen": false}}}
	bundle, err := BuildProfileBundle(server, "manual", template)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(server.RawProfile, original) {
		t.Fatal("renderer mutated source JSON")
	}
	if bundle.Entry["protocol"] != "loopback" || bundle.Entry["tag"] != "manual" || mapOf(bundle.Entry["settings"])["inboundTag"] != bundle.InboundTag {
		t.Fatal("profile entry is not native loopback")
	}
	if len(bundle.Namespace) != 69 || !IsProfileInternalTag(bundle.Namespace+"ob-test") {
		t.Fatal("profile hash namespace is not stable/full length")
	}
	if len(bundle.InternalOutbounds) != 4 || len(bundle.Balancers) != 1 {
		t.Fatal("provider members were flattened or lost")
	}
	balancer := mapOf(bundle.Balancers[0])
	strategy := mapOf(balancer["strategy"])
	if strategy["type"] != "leastLoad" || mapOf(strategy["settings"])["maxRTT"] != "2s" {
		t.Fatal("provider balancing strategy changed")
	}
	if balancer["fallbackTag"] != bundle.Namespace+"ob-direct" {
		t.Fatal("balancer fallback was not remapped")
	}
	if bundle.Globals["observatory"] != nil || bundle.Globals["burstObservatory"] == nil || bundle.RoutingGlobals["domainStrategy"] != "IPIfNonMatch" {
		t.Fatal("provider global requirements were lost")
	}
	if bundle.Sniffing["enabled"] != true {
		t.Fatal("entry sniffing requirement was dropped")
	}
	owned := map[string]bool{bundle.InboundTag: true, bundle.Namespace + "dns-dns-in": true, bundle.Namespace + "dns-dns-secondary": true}
	for _, item := range bundle.Rules {
		rule := mapOf(item)
		tags, err := profileStrings(rule["inboundTag"])
		if err != nil || len(tags) == 0 {
			t.Fatal("unscoped provider rule")
		}
		for _, tag := range tags {
			if !owned[tag] {
				t.Fatalf("provider rule can match foreign traffic: %s", tag)
			}
		}
	}
	firstRule := mapOf(bundle.Rules[0])
	tags, _ := profileStrings(firstRule["inboundTag"])
	if len(tags) != 1 || tags[0] != bundle.InboundTag {
		t.Fatal("HTTP/SOCKS input tags were not collapsed into virtual entry")
	}
	second := mapOf(bundle.Rules[1])
	tags, _ = profileStrings(second["inboundTag"])
	if len(tags) != 1 || tags[0] != bundle.Namespace+"dns-dns-in" {
		t.Fatal("DNS query input was not separately scoped")
	}
	options := mapOf(mapOf(mapOf(bundle.InternalOutbounds[0])["streamSettings"])["sockopt"])
	if options["mark"] != 255 || options["tcpFastOpen"] != true {
		t.Fatal("local mark was not applied independently of provider socket settings")
	}
	dns := mapOf(bundle.Globals["dns"])
	secondary := mapOf(asSlice(dns["servers"])[1])
	if dns["tag"] != bundle.Namespace+"dns-dns-in" || secondary["tag"] != bundle.Namespace+"dns-dns-secondary" {
		t.Fatal("DNS tags escaped the profile namespace")
	}
}

func TestProfileBundleHasScopedDefaultWithoutRouterFallback(t *testing.T) {
	profile := profileFixture()
	routing := mapOf(profile["routing"])
	routing["rules"] = []interface{}{}
	bundle, err := BuildProfileBundle(profileServer(t, profile), "manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	last := mapOf(bundle.Rules[len(bundle.Rules)-1])
	if last["outboundTag"] != bundle.Namespace+"ob-node-1" {
		t.Fatal("unmatched traffic can escape into the router's default outbound")
	}
	tags, _ := profileStrings(last["inboundTag"])
	if len(tags) != 3 {
		t.Fatal("terminal default does not cover every owned virtual input")
	}
}

func TestProfileBundleRewritesChainDependencies(t *testing.T) {
	profile := profileFixture()
	outbounds := asSlice(profile["outbounds"])
	mapOf(outbounds[0])["proxySettings"] = map[string]interface{}{"tag": "node-2", "transportLayer": true}
	bundle, err := BuildProfileBundle(profileServer(t, profile), "manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	if mapOf(mapOf(bundle.InternalOutbounds[0])["proxySettings"])["tag"] != bundle.Namespace+"ob-node-2" {
		t.Fatal("chain dependency was not rewritten")
	}
	mapOf(outbounds[1])["streamSettings"] = map[string]interface{}{"sockopt": map[string]interface{}{"dialerProxy": "node-1"}}
	if _, err := BuildProfileBundle(profileServer(t, profile), "manual", nil); err == nil {
		t.Fatal("cyclic outbound chain was accepted")
	}
}

func TestProfileBundleRejectsDanglingAndUnknownSemantics(t *testing.T) {
	cases := map[string]func(map[string]interface{}){
		"empty inbound": func(p map[string]interface{}) {
			mapOf(asSlice(mapOf(p["routing"])["rules"])[0])["inboundTag"] = []interface{}{""}
		},
		"dangling target": func(p map[string]interface{}) {
			mapOf(asSlice(mapOf(p["routing"])["rules"])[0])["outboundTag"] = "external-router-tag"
		},
		"dangling chain": func(p map[string]interface{}) {
			mapOf(asSlice(p["outbounds"])[0])["proxySettings"] = map[string]interface{}{"tag": "outside-profile"}
		},
		"both observers": func(p map[string]interface{}) {
			p["observatory"] = map[string]interface{}{"subjectSelector": []interface{}{"node-"}}
		},
		"reverse": func(p map[string]interface{}) { p["reverse"] = map[string]interface{}{"bridges": []interface{}{}} },
		"sniff mismatch": func(p map[string]interface{}) {
			mapOf(mapOf(asSlice(p["inbounds"])[0])["sniffing"])["routeOnly"] = false
		},
		"missing selector": func(p map[string]interface{}) {
			mapOf(asSlice(mapOf(p["routing"])["balancers"])[0])["selector"] = []interface{}{"outside"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			profile := profileFixture()
			mutate(profile)
			if _, err := BuildProfileBundle(profileServer(t, profile), "manual", nil); err == nil {
				t.Fatal("unsupported profile accepted")
			}
		})
	}
}

func TestProfileBundleRejectsLoopbackRoutingCycle(t *testing.T) {
	profile := profileFixture()
	profile["outbounds"] = []interface{}{map[string]interface{}{"tag": "cycle", "protocol": "loopback", "settings": map[string]interface{}{"inboundTag": "socks-in"}}}
	profile["routing"] = map[string]interface{}{"rules": []interface{}{map[string]interface{}{"type": "field", "outboundTag": "cycle"}}}
	delete(profile, "burstObservatory")
	if _, err := BuildProfileBundle(profileServer(t, profile), "manual", nil); err == nil {
		t.Fatal("loopback can recursively select itself")
	}
}

func TestProfileBundleCostMatchingDoesNotMatchNamespaceHash(t *testing.T) {
	profile := profileFixture()
	balancer := mapOf(asSlice(mapOf(profile["routing"])["balancers"])[0])
	settings := mapOf(mapOf(balancer["strategy"])["settings"])
	settings["costs"] = []interface{}{map[string]interface{}{"match": "1", "value": 10}}
	bundle, err := BuildProfileBundle(profileServer(t, profile), "manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	costs := asSlice(mapOf(mapOf(mapOf(bundle.Balancers[0])["strategy"])["settings"])["costs"])
	if len(costs) != 1 || mapOf(costs[0])["regexp"] != true {
		t.Fatal("substring cost expanded to unrelated namespaced nodes")
	}
	pattern := mapOf(costs[0])["match"].(string)
	if !strings.Contains(pattern, "node-1") || strings.Contains(pattern, "node-2") {
		t.Fatal("provider's original cost matching changed")
	}
}

func TestProfileBundleRetainsKnownLegacyDomainMatcher(t *testing.T) {
	for _, matcher := range []string{"", "linear", "hybrid", "mph"} {
		t.Run(matcher, func(t *testing.T) {
			profile := profileFixture()
			mapOf(profile["routing"])["domainMatcher"] = matcher
			bundle, err := BuildProfileBundle(profileServer(t, profile), "manual", nil)
			if err != nil {
				t.Fatal(err)
			}
			if value, exists := bundle.RoutingGlobals["domainMatcher"]; !exists || value != matcher {
				t.Fatal("recognized legacy routing metadata was discarded")
			}
			if bundle.RoutingGlobals["domainStrategy"] != "IPIfNonMatch" {
				t.Fatal("legacy matcher metadata changed domainStrategy")
			}
		})
	}
	for _, invalid := range []interface{}{true, "unknown-matcher"} {
		profile := profileFixture()
		mapOf(profile["routing"])["domainMatcher"] = invalid
		if _, err := BuildProfileBundle(profileServer(t, profile), "manual", nil); err == nil || ProfileRenderPhase(err) != "routing" {
			t.Fatal("unknown legacy matcher semantics were accepted")
		}
	}
	bundle, err := BuildProfileBundle(profileServer(t, profileFixture()), "manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	if value, exists := bundle.RoutingGlobals["domainMatcher"]; !exists || value != nil {
		t.Fatal("absent legacy matcher cannot clear baseline routing metadata")
	}
}

func TestProfileBundleAssignsOwnedTagToUntaggedDNS(t *testing.T) {
	for _, emptyTag := range []bool{false, true} {
		profile := profileFixture()
		dns := mapOf(profile["dns"])
		delete(dns, "tag")
		if emptyTag {
			dns["tag"] = ""
		}
		bundle, err := BuildProfileBundle(profileServer(t, profile), "manual", nil)
		if err != nil {
			t.Fatal(err)
		}
		generated := bundle.Namespace + "dns-default"
		if mapOf(bundle.Globals["dns"])["tag"] != generated {
			t.Fatal("untagged DNS still uses an unscoped native random input")
		}
		for _, item := range []interface{}{bundle.Rules[2], bundle.Rules[len(bundle.Rules)-1]} {
			inputs, err := profileStrings(mapOf(item)["inboundTag"])
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, input := range inputs {
				if input == generated {
					found = true
				}
			}
			if !found {
				t.Fatal("original unscoped/default provider rule misses DNS input")
			}
		}
		inputs, err := profileStrings(mapOf(bundle.Rules[1])["inboundTag"])
		if err != nil || len(inputs) != 1 || inputs[0] != bundle.Namespace+"dormant-dns-in" {
			t.Fatal("nonexistent source dns-in rule was revived by generated DNS tag")
		}
	}
}

func TestProfileBundleGeneratedDNSInputDoesNotCollideWithServerTag(t *testing.T) {
	profile := profileFixture()
	dns := mapOf(profile["dns"])
	delete(dns, "tag")
	mapOf(asSlice(dns["servers"])[1])["tag"] = "default"
	bundle, err := BuildProfileBundle(profileServer(t, profile), "manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	rendered := mapOf(bundle.Globals["dns"])
	serverTag := mapOf(asSlice(rendered["servers"])[1])["tag"]
	if serverTag != bundle.Namespace+"dns-default" || rendered["tag"] != bundle.Namespace+"dns-default-1" {
		t.Fatal("generated global DNS input changed a source nameserver tag")
	}
}

func TestProfileRenderPhaseHasFixedDiagnosticCodes(t *testing.T) {
	cases := []struct {
		phase  string
		mutate func(map[string]interface{})
	}{
		{"schema", func(p map[string]interface{}) { p["private-example-value"] = true }},
		{"clients", func(p map[string]interface{}) { mapOf(asSlice(p["inbounds"])[0])["protocol"] = "unsupported-example" }},
		{"dns", func(p map[string]interface{}) { p["dns"] = true }},
		{"outbound-index", func(p map[string]interface{}) { p["outbounds"] = []interface{}{} }},
		{"routing", func(p map[string]interface{}) { mapOf(p["routing"])["unsupported-example"] = true }},
		{"balancer-index", func(p map[string]interface{}) { mapOf(p["routing"])["balancers"] = true }},
		{"outbounds", func(p map[string]interface{}) { mapOf(asSlice(p["outbounds"])[0])["private-example-value"] = true }},
		{"balancers", func(p map[string]interface{}) {
			mapOf(asSlice(mapOf(p["routing"])["balancers"])[0])["selector"] = []interface{}{"missing-example"}
		}},
		{"rules", func(p map[string]interface{}) {
			mapOf(asSlice(mapOf(p["routing"])["rules"])[0])["outboundTag"] = "missing-example"
		}},
		{"observer", func(p map[string]interface{}) { p["observatory"] = map[string]interface{}{} }},
		{"policy", func(p map[string]interface{}) { p["policy"] = true }},
		{"cycles", func(p map[string]interface{}) {
			mapOf(asSlice(p["outbounds"])[0])["proxySettings"] = map[string]interface{}{"tag": "node-1"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.phase, func(t *testing.T) {
			profile := profileFixture()
			tc.mutate(profile)
			_, err := BuildProfileBundle(profileServer(t, profile), "manual", nil)
			if err == nil || ProfileRenderPhase(fmt.Errorf("caller context: %w", err)) != tc.phase {
				t.Fatalf("expected fixed phase %q, got %q", tc.phase, ProfileRenderPhase(err))
			}
			if strings.Contains(err.Error(), "example") {
				t.Fatal("renderer diagnostic includes source data")
			}
		})
	}
	if ProfileRenderPhase(fmt.Errorf("unrelated")) != "" || ProfileRenderPhase(nil) != "" {
		t.Fatal("unrelated error was given a profile phase")
	}
}
