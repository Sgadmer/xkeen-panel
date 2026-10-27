package xkeen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func policyRules(t *testing.T, rt Runtime) []interface{} {
	t.Helper()
	return asSlice(mapOf(profileApplyDocument(t, ExclusionsConfigPath(rt))["routing"])["rules"])
}
func ownedPolicyRules(rules []interface{}) []interface{} {
	var out []interface{}
	for _, raw := range rules {
		tag, _ := mapOf(raw)["ruleTag"].(string)
		if strings.HasPrefix(tag, routingPolicyRulePrefix) {
			out = append(out, raw)
		}
	}
	return out
}
func foreignPolicyRules(rules []interface{}) []interface{} {
	var out []interface{}
	for _, raw := range rules {
		tag, _ := mapOf(raw)["ruleTag"].(string)
		if !strings.HasPrefix(tag, routingPolicyRulePrefix) {
			out = append(out, raw)
		}
	}
	return out
}

func TestRoutingPolicySelectedAllAndPreserveKeepForeignRules(t *testing.T) {
	rt, path, _, _ := profileApplyBaseline(t)
	doc := profileApplyDocument(t, rt.RoutingFile)
	routing := mapOf(doc["routing"])
	routing["rules"] = append([]interface{}{map[string]interface{}{"type": "field", "inboundTag": []interface{}{"redirect", "tproxy"}, "port": "53", "outboundTag": "direct"}}, asSlice(routing["rules"])...)
	profileApplyWrite(t, rt.RoutingFile, doc)
	baseline := policyRules(t, rt)
	p := RoutingPolicy{Mode: "selected", Services: []string{"youtube"}, Addresses: []string{"https://shop.example/a", "203.0.113.19/24"}}
	if err := SetRoutingPolicy(rt, path, p); err != nil {
		t.Fatal(err)
	}
	rules := policyRules(t, rt)
	owned := ownedPolicyRules(rules)
	if len(owned) != 5 {
		t.Fatalf("want DNS,local,domains,ips,direct-default; got %d", len(owned))
	}
	if !reflect.DeepEqual(foreignPolicyRules(rules), baseline) {
		t.Fatal("selected mode changed existing rules")
	}
	for _, raw := range owned {
		r := mapOf(raw)
		if !reflect.DeepEqual(stringList(r["inboundTag"]), []string{"redirect", "tproxy"}) {
			t.Fatal("policy touched an internal or probe input")
		}
	}
	if err := SetRoutingPolicy(rt, path, RoutingPolicy{Mode: "all"}); err != nil {
		t.Fatal(err)
	}
	owned = ownedPolicyRules(policyRules(t, rt))
	if len(owned) != 3 || mapOf(owned[len(owned)-1])["balancerTag"] != DefaultBalancerTag {
		t.Fatal("all mode does not send normal client traffic to current balancer")
	}
	if err := SetRoutingPolicy(rt, path, RoutingPolicy{Mode: "preserve"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(policyRules(t, rt), baseline) {
		t.Fatal("preserve did not recover exact original rule order")
	}
}

func TestRoutingPolicyKeepsExclusionsBeforeSelectedAndSurvivesPoolSelection(t *testing.T) {
	rt, path, entries := exclusionsFixture(t)
	if err := WriteExclusionsConfig(rt, entries); err != nil {
		t.Fatal(err)
	}
	if err := SetRoutingPolicy(rt, path, RoutingPolicy{Mode: "selected", Addresses: []string{"shop.example.com"}}); err != nil {
		t.Fatal(err)
	}
	check := func() {
		rules := policyRules(t, rt)
		if !strings.HasPrefix(mapOf(rules[0])["ruleTag"].(string), exclusionRulePrefix) {
			t.Fatal("policy shadows direct exclusion")
		}
		if len(ownedPolicyRules(rules)) < 2 {
			t.Fatal("selection removed mode")
		}
	}
	check()
	if err := SetManualOutbound(rt, path, poolServers()[0]); err != nil {
		t.Fatal(err)
	}
	check()
	if _, err := RefreshPool(rt, path, "", poolServers(), PoolState{Selector: DefaultPoolSelector, BalancerTag: DefaultBalancerTag}, PoolSelection{MaxNodes: 2}); err != nil {
		t.Fatal(err)
	}
	check()
	loaded, err := LoadRoutingPolicy(rt)
	if err != nil || loaded.Mode != "selected" {
		t.Fatal("mode was not persisted")
	}
}

func TestRoutingPolicyProfileCompatibilityGateNeverFlattensProfile(t *testing.T) {
	rt, path, _, _ := profileApplyBaseline(t)
	profile := profileServer(t, profileFixture())
	if err := SetManualOutbound(rt, path, profile); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(rt.RoutingFile)
	if err := SetRoutingPolicy(rt, path, RoutingPolicy{Mode: "all"}); err == nil {
		t.Fatal("profile conflict was not detected")
	}
	after, _ := os.ReadFile(rt.RoutingFile)
	if string(before) != string(after) {
		t.Fatal("conflict changed profile routes")
	}
	if _, err := os.Stat(RoutingPolicyPath(rt)); !os.IsNotExist(err) {
		t.Fatal("rejected profile mode left state file")
	}
	if err := SetManualOutbound(rt, path, poolServers()[0]); err != nil {
		t.Fatal(err)
	}
	if err := SetRoutingPolicy(rt, path, RoutingPolicy{Mode: "all"}); err != nil {
		t.Fatal(err)
	}
	before, _ = os.ReadFile(path)
	if err := SetManualOutbound(rt, path, profile); err == nil {
		t.Fatal("profile selection bypassed compatibility gate")
	}
	after, _ = os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("rejected profile replaced ordinary server")
	}
}

func TestRoutingPolicyRejectsUnknownAndNormalizesAddresses(t *testing.T) {
	p, err := NormalizeRoutingPolicy(RoutingPolicy{Mode: "selected", Services: []string{"youtube", "youtube"}, Addresses: []string{"Example.COM", "domain:example.com", "203.0.113.19/24"}})
	if err != nil || len(p.Services) != 1 || len(p.Addresses) != 2 {
		t.Fatal("normalization failed")
	}
	for _, p := range []RoutingPolicy{{Mode: "unsafe"}, {Mode: "all", Services: []string{"unknown"}}, {Mode: "selected", Addresses: []string{"https://user:secret@example.com"}}} {
		if _, err := NormalizeRoutingPolicy(p); err == nil {
			t.Fatal("invalid routing policy accepted")
		}
	}
	rt := Runtime{XrayConfDir: t.TempDir()}
	raw, _ := json.Marshal(RoutingPolicy{Mode: "selected", Services: []string{"not-known"}})
	if err := os.WriteFile(filepath.Join(rt.XrayConfDir, ".panel-routing-policy"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRoutingPolicy(rt); err == nil {
		t.Fatal("corrupt service accepted")
	}
}

func TestRoutingPolicyRestoresSniffingWhenReturningToPreserve(t *testing.T) {
	rt, path, input, _ := profileApplyBaseline(t)
	want := profileApplyDocument(t, input)
	if err := SetRoutingPolicy(rt, path, RoutingPolicy{Mode: "selected", Services: []string{"youtube"}}); err != nil {
		t.Fatal(err)
	}
	doc := profileApplyDocument(t, input)
	for _, raw := range asSlice(doc["inbounds"]) {
		sniff := mapOf(mapOf(raw)["sniffing"])
		if sniff["enabled"] != true {
			t.Fatal("selected domains cannot be recognized on client inputs")
		}
	}
	if err := SetRoutingPolicy(rt, path, RoutingPolicy{Mode: "all"}); err != nil {
		t.Fatal(err)
	}
	if err := SetRoutingPolicy(rt, path, RoutingPolicy{Mode: "preserve"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(profileApplyDocument(t, input), want) {
		t.Fatal("preserve lost initial sniffing settings")
	}
}
