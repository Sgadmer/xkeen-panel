package cardcontroller

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestConnectionUsesObservedChainAndOnlyPublicFields(t *testing.T) {
	var f connectionTracker
	err := json.Unmarshal([]byte(`{"id":"flow","metadata":{"sourceIP":"::ffff:192.0.2.2","sniffHost":"example.com","destinationIP":"192.0.2.1","destinationPort":"443","network":"tcp","inboundUser":"private"},"chains":["DIRECT","RuleGroup"],"rule":"IPCIDR","rulePayload":"192.0.2.0/24"}`), &f)
	if err != nil {
		t.Fatal(err)
	}
	row := f.project(map[string]string{"DIRECT": "Напрямую"})
	if row.Host != "example.com" || row.Device != "192.0.2.2" || row.Port != "443" || row.Rule != "IPCIDR 192.0.2.0/24" || !reflect.DeepEqual(row.Route, []string{"RuleGroup", "Напрямую"}) {
		t.Fatalf("%+v", row)
	}
	f.Metadata.Host = "https://example.com/path?token=test"
	f.Metadata.SniffHost = ""
	f.Chains = nil
	row = f.project(nil)
	if row.Host != "192.0.2.1" || len(row.Route) != 0 {
		t.Fatalf("%+v", row)
	}
	for tag, id := range map[string]string{"ChatGPT": "openai", cardPrefix + "openai-inherited": "openai", dedicatedGroup("claude"): "claude", "Other": ""} {
		f.Chains = []string{"DIRECT", tag}
		if got := f.project(nil).ServiceID; got != id {
			t.Errorf("tag %q: %q", tag, got)
		}
	}
	f.Chains = []string{"DIRECT"}
	for domain, want := range map[string]string{"API.Anthropic.com.": "claude", "chatgpt.com": "openai", "notchatgpt.com": "", "chatgpt.com.example": ""} {
		f.Metadata.Host = domain
		row = f.project(nil)
		if row.ServiceID != want || !reflect.DeepEqual(row.Route, []string{"DIRECT"}) {
			t.Errorf("incorrect service icon or route for %q", domain)
		}
	}
}
