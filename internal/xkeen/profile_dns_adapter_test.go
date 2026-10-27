package xkeen

import "testing"

func profileImplicitDNSFixture(target string, port interface{}) map[string]interface{} {
	profile := profileFixture()
	routing := mapOf(profile["routing"])
	routing["rules"] = append([]interface{}{map[string]interface{}{"type": "field", "port": port, "outboundTag": target}}, asSlice(routing["rules"])...)
	return profile
}

func TestProfileDNSAdapterAddsOnlyKnownDNSPortService(t *testing.T) {
	for _, target := range []string{"dns", "dns-out", "dns-outbound"} {
		for _, port := range []interface{}{"53", 53} {
			profile := profileImplicitDNSFixture(target, port)
			bundle, err := BuildProfileBundle(profileServer(t, profile), "manual", nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(bundle.Adaptations) != 1 || len(bundle.InternalOutbounds) != 5 {
				t.Fatal("implicit DNS adaptation is absent or silently unreported")
			}
			service := mapOf(bundle.InternalOutbounds[4])
			if service["protocol"] != "dns" || service["tag"] != bundle.Namespace+"ob-"+target || len(mapOf(service["settings"])) != 0 {
				t.Fatal("implicit DNS target is not the native DNS proxy")
			}
			first := mapOf(bundle.Rules[0])
			inputs, err := profileStrings(first["inboundTag"])
			if err != nil || len(inputs) != 1 || inputs[0] != bundle.InboundTag {
				t.Fatal("DNS engine query can be intercepted by the synthetic DNS service")
			}
			bound, err := BindProfileRules(bundle, []string{"redirect", "tproxy"})
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range bound.OwnedRules {
				if mapOf(item)["outboundTag"] == service["tag"] {
					t.Fatal("synthetic DNS service handles owned DNS-engine traffic")
				}
			}
			if mapOf(bound.ClientRules[0])["outboundTag"] != service["tag"] {
				t.Fatal("real client DNS request lost its synthetic service route")
			}
		}
	}
}

func TestProfileDNSAdapterPreservesClientLoopbackWithoutEngineRecursion(t *testing.T) {
	profile := profileImplicitDNSFixture("dns-out", "53")
	profile["outbounds"] = append(asSlice(profile["outbounds"]), map[string]interface{}{"tag": "inner", "protocol": "loopback", "settings": map[string]interface{}{"inboundTag": "socks-in"}})
	bundle, err := BuildProfileBundle(profileServer(t, profile), "manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindProfileRules(bundle, []string{"tproxy"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range bound.OwnedRules {
		rule := mapOf(item)
		if rule["outboundTag"] == bundle.Namespace+"ob-dns-out" {
			inputs, err := profileStrings(rule["inboundTag"])
			if err != nil || len(inputs) != 1 || inputs[0] != bundle.Namespace+"loop-socks-in" {
				t.Fatal("synthetic DNS scope includes a source other than client loopback")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("original client loopback cannot use the implicit DNS service")
	}
}

func TestProfileDNSAdapterRejectsAmbiguousOrNonDNSReferences(t *testing.T) {
	cases := map[string]func(map[string]interface{}){
		"wide port": func(p map[string]interface{}) { mapOf(asSlice(mapOf(p["routing"])["rules"])[0])["port"] = "53,443" },
		"another port reference": func(p map[string]interface{}) {
			routing := mapOf(p["routing"])
			routing["rules"] = append(asSlice(routing["rules"]), map[string]interface{}{"type": "field", "port": "443", "outboundTag": "dns-out"})
		},
		"no DNS component": func(p map[string]interface{}) { delete(p, "dns") },
		"unknown missing target": func(p map[string]interface{}) {
			mapOf(asSlice(mapOf(p["routing"])["rules"])[0])["outboundTag"] = "unrelated-missing"
		},
		"chain": func(p map[string]interface{}) {
			mapOf(asSlice(p["outbounds"])[0])["proxySettings"] = map[string]interface{}{"tag": "dns-out"}
		},
		"dialer": func(p map[string]interface{}) {
			mapOf(mapOf(mapOf(asSlice(p["outbounds"])[0])["streamSettings"])["sockopt"])["dialerProxy"] = "dns-out"
		},
		"fallback": func(p map[string]interface{}) {
			mapOf(asSlice(mapOf(p["routing"])["balancers"])[0])["fallbackTag"] = "dns-out"
		},
		"balancer selector": func(p map[string]interface{}) {
			mapOf(asSlice(mapOf(p["routing"])["balancers"])[0])["selector"] = []interface{}{"node-", "dns"}
		},
		"observer selector": func(p map[string]interface{}) {
			mapOf(p["burstObservatory"])["subjectSelector"] = []interface{}{"node-", "dns"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			profile := profileImplicitDNSFixture("dns-out", "53")
			mutate(profile)
			if _, err := BuildProfileBundle(profileServer(t, profile), "manual", nil); err == nil {
				t.Fatal("ambiguous missing outbound was silently repaired")
			}
		})
	}
}

func TestProfileDNSAdapterDoesNotChangeExplicitDNSOutbound(t *testing.T) {
	profile := profileImplicitDNSFixture("dns-out", "53")
	profile["outbounds"] = append(asSlice(profile["outbounds"]), map[string]interface{}{"tag": "dns-out", "protocol": "dns", "settings": map[string]interface{}{"network": "tcp"}})
	bundle, err := BuildProfileBundle(profileServer(t, profile), "manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Adaptations) != 0 || mapOf(mapOf(bundle.InternalOutbounds[4])["settings"])["network"] != "tcp" {
		t.Fatal("explicit provider DNS service was replaced by the adapter")
	}
}
