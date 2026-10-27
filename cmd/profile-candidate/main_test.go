package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"xkeen-panel/internal/xkeen"
)

func syntheticProfile(name, prefix string) map[string]interface{} {
	return map[string]interface{}{
		"remarks": name,
		"outbounds": []interface{}{
			map[string]interface{}{"tag": "one", "protocol": "vless", "settings": map[string]interface{}{"address": prefix + "-one.invalid", "port": 443, "id": "00000000-0000-4000-8000-000000000001", "encryption": "none"}},
			map[string]interface{}{"tag": "two", "protocol": "vless", "settings": map[string]interface{}{"address": prefix + "-two.invalid", "port": 443, "id": "00000000-0000-4000-8000-000000000002", "encryption": "none"}},
			map[string]interface{}{"tag": "direct", "protocol": "freedom"},
		},
		"routing":     map[string]interface{}{"rules": []interface{}{map[string]interface{}{"type": "field", "network": "tcp,udp", "balancerTag": "pick"}}, "balancers": []interface{}{map[string]interface{}{"tag": "pick", "selector": []interface{}{"one", "two"}, "strategy": map[string]interface{}{"type": "leastPing"}}}},
		"observatory": map[string]interface{}{"subjectSelector": []interface{}{"one", "two"}, "probeURL": "https://www.gstatic.com/generate_204", "probeInterval": "1m"},
	}
}

func fixtureStage(t *testing.T) (string, []byte) {
	t.Helper()
	stage := t.TempDir()
	source := filepath.Join(stage, "live-configs")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal([]interface{}{syntheticProfile("САМЫЙ БЫСТРЫЙ", "fast"), syntheticProfile("АВТО-ОБХОД", "auto")})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "source-response.json"), response, 0600); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"00_api.json":         `{"api":{"tag":"api","listen":"127.0.0.1:10085","services":["RoutingService","HandlerService"]}}`,
		"00_panel_probe.json": `{"inbounds":[{"tag":"panel-probe","listen":"127.0.0.1","port":10086,"protocol":"socks","settings":{"auth":"noauth","udp":false}},{"tag":"router-tproxy","port":12345,"protocol":"dokodemo-door","settings":{"network":"tcp,udp","followRedirect":true}}]}`,
		"02_log.json":         `{"log":{"loglevel":"warning","access":"/opt/var/log/xray-access.log","error":"/opt/var/log/xray-error.log"}}`,
		"04_outbounds.json":   `{"outbounds":[{"tag":"sub-1","protocol":"vless","settings":{"address":"baseline.invalid","port":443,"id":"00000000-0000-4000-8000-000000000003"},"streamSettings":{"sockopt":{"mark":255}}},{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]}`,
		"05_routing.json":     `{"routing":{"rules":[{"type":"field","inboundTag":["panel-probe"],"balancerTag":"outer-balancer"},{"type":"field","network":"tcp,udp","balancerTag":"outer-balancer"}],"balancers":[{"tag":"outer-balancer","selector":["sub-"],"strategy":{"type":"leastPing"}}]}}`,
		"07_observatory.json": `{"observatory":{"subjectSelector":["sub-"],"probeURL":"https://www.gstatic.com/generate_204","probeInterval":"1m"}}`,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(source, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return stage, response
}

func TestProfileCandidatesUseProductionWriterOnIsolatedCopies(t *testing.T) {
	stage, response := fixtureStage(t)
	profiles, err := selectProfiles(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 || profileKind(profiles[0].Name) != "AUTO" || profileKind(profiles[1].Name) != "FAST" {
		t.Fatal("profile order was guessed from source order")
	}
	source, err := loadSourceConfigs(stage)
	if err != nil {
		t.Fatal(err)
	}
	for index, profile := range profiles {
		info, err := prepareCandidate(stage, index, profile, source)
		if err != nil {
			t.Fatal("isolated candidate rejected", err)
		}
		if info.MainBalancer != "outer-balancer" || info.PinnedTag != xkeen.ManualTag || !info.PinManual {
			t.Fatal("manual override metadata incorrect")
		}
		paths, _ := filepath.Glob(filepath.Join(info.ConfigDir, "*.json"))
		probes, apis := 0, 0
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			document, err := decodeDocument(data)
			if err != nil {
				t.Fatal(err)
			}
			if raw, exists := document["inbounds"]; exists {
				for _, item := range raw.([]interface{}) {
					inbound := item.(map[string]interface{})
					if inbound["tag"] != xkeen.ProbeInboundTag || inbound["listen"] != "127.0.0.1" || inbound["port"] != json.Number("18086") {
						t.Fatal("production/extra listener survived isolation")
					}
					probes++
				}
			}
			if raw, exists := document["api"]; exists {
				if raw.(map[string]interface{})["listen"] != "127.0.0.1:18085" {
					t.Fatal("API not isolated")
				}
				apis++
			}
			if raw, exists := document["log"]; exists {
				logging := raw.(map[string]interface{})
				if logging["access"] != "none" || logging["error"] != filepath.Join(info.ConfigDir, "core-runtime.log") {
					t.Fatal("preview could write a production log")
				}
			}
		}
		if probes != 1 || apis != 1 {
			t.Fatal("wrong isolated listener count")
		}
	}
	if !sourceUnchanged(stage, hash(response), source) {
		t.Fatal("source response/configs were mutated")
	}
}

func TestProfileCandidatesRejectAmbiguousKindsAndExistingDirectory(t *testing.T) {
	for _, name := range []string{"Unknown", "AUTO FAST", "САМЫЙ БЫСТРЫЙ АВТО"} {
		if profileKind(name) != "" {
			t.Fatal("ambiguous kind guessed")
		}
	}
	stage, response := fixtureStage(t)
	profiles, err := selectProfiles(response)
	if err != nil {
		t.Fatal(err)
	}
	source, err := loadSourceConfigs(stage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareCandidate(stage, 0, profiles[0], source); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareCandidate(stage, 0, profiles[0], source); err == nil {
		t.Fatal("existing candidate directory overwritten")
	}
}
