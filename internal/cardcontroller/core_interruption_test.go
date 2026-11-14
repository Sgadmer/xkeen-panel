package cardcontroller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoreInterruptionWithInheritedServiceRoutes(t *testing.T) {
	hash := strings.Repeat("a", 64)
	releasedClaude := map[string]string{"claude": "off"}
	releasedServices := map[string]string{}
	for id := range groupNames {
		releasedServices[id] = "inherit"
	}
	for _, tc := range []struct {
		name     string
		rules    []string
		global   bool
		modes    map[string]string
		assigned map[string]string
		refilter bool
		blocked  bool
	}{
		{name: "all inherited routes direct", modes: releasedClaude, rules: []string{"DOMAIN,local.test,DIRECT", "MATCH,DIRECT"}},
		{name: "rendered profile with only direct owner routes", modes: releasedClaude, rules: []string{"DOMAIN-SUFFIX,claude.ai," + cardPrefix + "claude", "MATCH,DIRECT"}},
		{name: "explicit direct service route", modes: releasedClaude, assigned: map[string]string{"openai": directTarget}, rules: []string{"MATCH,DIRECT"}},
		{name: "Claude blocked pending assignment", rules: []string{"MATCH,DIRECT"}, blocked: true},
		{name: "global protection on", modes: releasedClaude, global: true, rules: []string{"MATCH,DIRECT"}, blocked: true},
		{name: "specific VPN in profile", modes: releasedClaude, rules: []string{"DOMAIN,chatgpt.com,Proxy", "MATCH,DIRECT"}, blocked: true},
		{name: "child classifier reused by an assigned parent", modes: releasedClaude, assigned: map[string]string{"google": directTarget}, rules: []string{"MATCH,DIRECT", "GEOSITE,youtube,YouTube"}, blocked: true},
		{name: "unassigned cards can use default VPN", modes: releasedClaude, assigned: map[string]string{defaultID: hash}, rules: []string{"MATCH,DIRECT"}, blocked: true},
		{name: "protected card assigned VPN", modes: releasedClaude, assigned: map[string]string{"openai": hash}, rules: []string{"MATCH,DIRECT"}, blocked: true},
		{name: "unassigned cards can use registry", modes: releasedClaude, refilter: true, rules: []string{"MATCH,DIRECT"}, blocked: true},
		{name: "all cards explicitly inherit disabled global", modes: releasedServices, rules: []string{"MATCH,Proxy"}},
		{name: "missing owner rules", modes: releasedClaude, blocked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := map[string]interface{}{
				"mode": "rule", "external-controller": "127.0.0.1:9090", "secret": "test",
				"rules": tc.rules, killSwitchKey: map[string]interface{}{"enabled": tc.global, "services": tc.modes},
				stateKey: tc.assigned,
			}
			if tc.modes == nil {
				cfg[killSwitchKey] = map[string]interface{}{"enabled": tc.global, "services": map[string]string{}}
			}
			if tc.assigned == nil {
				cfg[stateKey] = map[string]string{}
			}
			if tc.refilter {
				cfg[refilterKey] = map[string]interface{}{"enabled": true, "domain_behavior": "domain", "site_hash": hash, "ip_hash": hash, "domains": 1, "prefixes": 1}
			}
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			c := &Controller{path: path}
			err = c.CheckCoreInterruption()
			if err != nil && !strings.Contains(err.Error(), "Kill switch") || (err != nil) != tc.blocked {
				t.Fatalf("CheckCoreInterruption() = %v, want blocked %t", err, tc.blocked)
			}
		})
	}
}
