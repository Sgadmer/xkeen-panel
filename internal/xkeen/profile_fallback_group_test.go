package xkeen

import (
	"strings"
	"testing"
)

// A provider's group may fall back to another group, like «АВТО ОБХОД (БС)»:
// whitelist servers first, the rest when none of them answers. Xray takes a
// fallback for an outbound only, so the panel passes it through a loopback.
func TestGroupFallsBackToAnotherGroupThroughLoopback(t *testing.T) {
	document := profileFixture()
	routing := mapOf(document["routing"])
	routing["balancers"] = []interface{}{
		map[string]interface{}{"tag": "whitelist", "selector": []interface{}{"node-1"}, "fallbackTag": "spare", "strategy": map[string]interface{}{"type": "leastPing"}},
		map[string]interface{}{"tag": "spare", "selector": []interface{}{"node-2"}, "fallbackTag": "direct"},
	}
	routing["rules"] = []interface{}{map[string]interface{}{"type": "field", "network": "tcp,udp", "balancerTag": "whitelist"}}
	bundle, err := BuildProfileBundle(profileServer(t, document), "manual", nil)
	if err != nil {
		t.Fatalf("a group falling back to a group was refused: %v (%s)", err, ProfileRefusal(err))
	}
	var first, spare map[string]interface{}
	for _, raw := range bundle.Balancers {
		balancer := mapOf(raw)
		switch {
		case strings.HasSuffix(balancer["tag"].(string), "bal-whitelist"):
			first = balancer
		case strings.HasSuffix(balancer["tag"].(string), "bal-spare"):
			spare = balancer
		}
	}
	if first == nil || spare == nil {
		t.Fatal("both groups must stay")
	}
	loop := ""
	for _, raw := range bundle.InternalOutbounds {
		out := mapOf(raw)
		if out["tag"] == first["fallbackTag"] && out["protocol"] == "loopback" {
			loop = mapOf(out["settings"])["inboundTag"].(string)
		}
	}
	if loop == "" {
		t.Fatalf("the first group's fallback is not a loopback: %v", first["fallbackTag"])
	}
	handed := false
	for _, raw := range bundle.Rules {
		rule := mapOf(raw)
		tags, _ := profileStrings(rule["inboundTag"])
		if len(tags) == 1 && tags[0] == loop && rule["balancerTag"] == spare["tag"] {
			handed = true
		}
	}
	if !handed {
		t.Fatal("what comes back through the loopback must go to the spare group")
	}
	if _, err := BindProfileRules(bundle, []string{"client-in"}); err != nil {
		t.Fatalf("the loopback rule must bind like the provider's own: %v", err)
	}
}

func TestGroupsFallingBackToEachOtherAreRefused(t *testing.T) {
	document := profileFixture()
	routing := mapOf(document["routing"])
	routing["balancers"] = []interface{}{
		map[string]interface{}{"tag": "a", "selector": []interface{}{"node-1"}, "fallbackTag": "b"},
		map[string]interface{}{"tag": "b", "selector": []interface{}{"node-2"}, "fallbackTag": "a"},
	}
	routing["rules"] = []interface{}{map[string]interface{}{"type": "field", "network": "tcp,udp", "balancerTag": "a"}}
	if _, err := BuildProfileBundle(profileServer(t, document), "manual", nil); err == nil {
		t.Fatal("two groups falling back to each other loop forever and must be refused")
	}
}
