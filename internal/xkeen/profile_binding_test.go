package xkeen

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProfileBindingUsesRealInputsAndKeepsPredicateMetadata(t *testing.T) {
	profile := profileFixture()
	rules := asSlice(mapOf(profile["routing"])["rules"])
	mapOf(rules[2])["protocol"] = []interface{}{"tls"}
	mapOf(rules[2])["ip"] = []interface{}{"203.0.113.0/24"}
	bundle, err := BuildProfileBundle(profileServer(t, profile), "manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(bundle.Rules)
	bound, err := BindProfileRules(bundle, []string{"redirect", "tproxy"})
	if err != nil {
		t.Fatal(err)
	}
	if len(bound.GuardOutbounds) != 1 || mapOf(bound.GuardOutbounds[0])["protocol"] != "blackhole" {
		t.Fatal("virtual entry has no native blackhole guard")
	}
	if mapOf(bound.OwnedRules[0])["outboundTag"] != mapOf(bound.GuardOutbounds[0])["tag"] {
		t.Fatal("guard rule does not target its blackhole")
	}
	foundPredicate := false
	for _, item := range bound.ClientRules {
		rule := mapOf(item)
		inputs, err := profileStrings(rule["inboundTag"])
		if err != nil || len(inputs) != 2 || inputs[0] != "redirect" || inputs[1] != "tproxy" {
			t.Fatal("client traffic still crosses a loopback entry")
		}
		if _, ok := rule["protocol"]; ok {
			foundPredicate = true
			if rule["domain"] == nil || rule["ip"] == nil {
				t.Fatal("provider protocol/IP/domain predicates changed")
			}
		}
	}
	if !foundPredicate {
		t.Fatal("source protocol predicate disappeared")
	}
	for index, item := range bound.OwnedRules {
		inputs, _ := profileStrings(mapOf(item)["inboundTag"])
		for _, input := range inputs {
			if index == 0 {
				if input != bundle.InboundTag {
					t.Fatal("guard can match actual client input")
				}
			} else if !strings.HasPrefix(input, bundle.Namespace) {
				t.Fatal("owned DNS rules can match global traffic")
			}
		}
	}
	after, _ := json.Marshal(bundle.Rules)
	if string(before) != string(after) {
		t.Fatal("binding mutated its reusable source bundle")
	}
}

func TestProfileBindingSeparateProbeRulesHaveUniqueRuleTags(t *testing.T) {
	bundle, err := BuildProfileBundle(profileServer(t, profileFixture()), "manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	clients, err := BindProfileRules(bundle, []string{"redirect", "tproxy"})
	if err != nil {
		t.Fatal(err)
	}
	probe, err := BindProfileRules(bundle, []string{"panel-probe"})
	if err != nil {
		t.Fatal(err)
	}
	tags := map[string]bool{}
	for _, rule := range append(clients.ClientRules, probe.ClientRules...) {
		tag := mapOf(rule)["ruleTag"].(string)
		if tags[tag] {
			t.Fatal("probe and client binding reuse a ruleTag")
		}
		tags[tag] = true
	}
	// OwnedRules/GuardOutbounds are shared, and are installed only once.
	if mapOf(clients.GuardOutbounds[0])["tag"] != mapOf(probe.GuardOutbounds[0])["tag"] {
		t.Fatal("the same profile produced inconsistent guard identity")
	}
}

func TestProfileBindingRejectsForeignOrRecursiveInputs(t *testing.T) {
	bundle, err := BuildProfileBundle(profileServer(t, profileFixture()), "manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, inputs := range [][]string{nil, {""}, {bundle.InboundTag}, {bundle.Namespace + "dns-foreign"}} {
		if _, err := BindProfileRules(bundle, inputs); err == nil {
			t.Fatal("invalid binding accepted")
		}
	}
	mapOf(bundle.Rules[0])["inboundTag"] = []interface{}{"api"}
	if _, err := BindProfileRules(bundle, []string{"tproxy"}); err == nil {
		t.Fatal("foreign provider routing input escaped namespace checks")
	}
}

func TestProfileBindingKeepsOriginalInnerLoopbackSeparate(t *testing.T) {
	profile := profileFixture()
	profile["outbounds"] = append(asSlice(profile["outbounds"]), map[string]interface{}{"tag": "inner", "protocol": "loopback", "settings": map[string]interface{}{"inboundTag": "inner-input"}})
	routing := mapOf(profile["routing"])
	routing["rules"] = append([]interface{}{map[string]interface{}{"type": "field", "inboundTag": []interface{}{"inner-input"}, "outboundTag": "direct"}}, asSlice(routing["rules"])...)
	bundle, err := BuildProfileBundle(profileServer(t, profile), "manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindProfileRules(bundle, []string{"tproxy"})
	if err != nil {
		t.Fatal(err)
	}
	inner := mapOf(bundle.InternalOutbounds[len(bundle.InternalOutbounds)-1])
	loopTag := mapOf(inner["settings"])["inboundTag"]
	if loopTag == bundle.InboundTag {
		t.Fatal("source inner loopback was redirected into the control guard")
	}
	matched := false
	for _, item := range bound.OwnedRules {
		rule := mapOf(item)
		inputs, _ := profileStrings(rule["inboundTag"])
		for _, input := range inputs {
			if input == loopTag {
				matched = true
			}
		}
	}
	if !matched {
		t.Fatal("source inner loopback input lost its provider rules")
	}
}

func TestProfileBindingKeepsLoopbackToOriginalClientTagSeparate(t *testing.T) {
	profile := profileFixture()
	profile["outbounds"] = append(asSlice(profile["outbounds"]), map[string]interface{}{"tag": "inner", "protocol": "loopback", "settings": map[string]interface{}{"inboundTag": "socks-in"}})
	bundle, err := BuildProfileBundle(profileServer(t, profile), "manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindProfileRules(bundle, []string{"tproxy"})
	if err != nil {
		t.Fatal(err)
	}
	inner := mapOf(bundle.InternalOutbounds[len(bundle.InternalOutbounds)-1])
	loopTag := mapOf(inner["settings"])["inboundTag"].(string)
	if loopTag == bundle.InboundTag || loopTag != bundle.Namespace+"loop-socks-in" {
		t.Fatal("original client loopback was collapsed into guarded control input")
	}
	found := false
	for _, item := range bound.OwnedRules[1:] {
		rule := mapOf(item)
		inputs, _ := profileStrings(rule["inboundTag"])
		if rule["port"] == "53" {
			for _, input := range inputs {
				if input == loopTag {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("source client-tag-specific rule no longer matches its inner loopback")
	}
}

func TestProfileBindingLeavesUnknownSourceInputDormant(t *testing.T) {
	profile := profileFixture()
	routing := mapOf(profile["routing"])
	routing["rules"] = append([]interface{}{
		map[string]interface{}{"type": "field", "inboundTag": []interface{}{"unavailable-input"}, "outboundTag": "block"},
		map[string]interface{}{"type": "field", "inboundTag": []interface{}{"socks-in", "unavailable-input"}, "protocol": []interface{}{"http"}, "outboundTag": "direct"},
	}, asSlice(routing["rules"])...)
	bundle, err := BuildProfileBundle(profileServer(t, profile), "manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindProfileRules(bundle, []string{"redirect", "tproxy"})
	if err != nil {
		t.Fatal(err)
	}
	dormant := bundle.Namespace + "dormant-unavailable-input"
	dormantRuleFound, mixedOwnedFound, mixedClientFound := false, false, false
	for _, item := range bound.OwnedRules {
		rule := mapOf(item)
		inputs, err := profileStrings(rule["inboundTag"])
		if err != nil {
			t.Fatal(err)
		}
		for _, input := range inputs {
			if input == "redirect" || input == "tproxy" {
				t.Fatal("dormant source predicate expanded onto real client input")
			}
			if input == dormant {
				if rule["outboundTag"] == bundle.Namespace+"ob-block" {
					dormantRuleFound = true
				}
				if rule["protocol"] != nil {
					mixedOwnedFound = true
				}
			}
		}
	}
	for _, item := range bound.ClientRules {
		rule := mapOf(item)
		if rule["outboundTag"] == bundle.Namespace+"ob-block" {
			t.Fatal("unknown-input-only block rule can now affect client traffic")
		}
		if rule["protocol"] != nil {
			mixedClientFound = true
		}
	}
	if !dormantRuleFound || !mixedOwnedFound || !mixedClientFound {
		t.Fatal("dormant or mixed input predicate was discarded")
	}
}
