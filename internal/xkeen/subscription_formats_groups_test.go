package xkeen

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"xkeen-panel/internal/models"
)

const staticClashEndpoints = `proxies:
  - {name: "🇩🇪 One", type: trojan, server: one.invalid, port: 443, password: synthetic, udp: true}
  - {name: Two, type: trojan, server: two.invalid, port: 443, password: synthetic, udp: true}
`

func TestStaticClashProviderGroups(t *testing.T) {
	body := staticClashEndpoints + `proxy-groups:
  - {name: "⚡ Быстрые", type: url-test, proxies: ["🇩🇪 One", Two], lazy: false, interval: 40, timeout: 2200, url: https://probe.invalid/ping}
  - {name: "Только TCP", type: url-test, proxies: [Two], lazy: false, disable-udp: true}
`
	servers, report, err := ParseSubscriptionDetailed(body)
	if err != nil || len(servers) != 4 || report.ImportedProfiles != 2 || report.SkippedComposite != 0 {
		t.Fatalf("servers=%d report=%+v err=%v", len(servers), report, err)
	}
	for i, server := range servers[2:] {
		if server.Protocol != "xray-profile" || server.ProfileNodes != 2-i || ServiceTargetID(server) == "" {
			t.Fatalf("provider profile lost identity or membership (%d)", i)
		}
		key, err := newServiceWorkerKey(39512)
		if err != nil {
			t.Fatal(err)
		}
		config, err := serviceWorkerConfig(server, nil, key)
		if err != nil {
			t.Fatal(err)
		}
		probe := mapOf(mapOf(config["burstObservatory"])["pingConfig"])
		if probe["httpMethod"] != "HEAD" || jsonPort(probe["sampling"]) != 1 || probe["connectivity"] != nil {
			t.Fatal("unexpected health check")
		}
		if i == 0 && (server.Name != "⚡ Быстрые" || probe["destination"] != "https://probe.invalid/ping" || probe["interval"] != "40s" || probe["timeout"] != "2.2s") {
			t.Fatal("group name or probe parameters changed")
		}
		if i == 1 && (server.Name != "Только TCP" || probe["destination"] != "https://www.gstatic.com/generate_204" || probe["interval"] != "5m0s" || probe["timeout"] != "5s") {
			t.Fatal("defaults changed")
		}
		routing := mapOf(config["routing"])
		bal := mapOf(asSlice(routing["balancers"])[0])
		fallback, _ := bal["fallbackTag"].(string)
		if !strings.HasSuffix(fallback, "member-0") || mapOf(bal["strategy"])["type"] != "leastPing" {
			t.Fatal("wrong selection/fallback")
		}
		var blocksUDP bool
		for _, raw := range asSlice(routing["rules"]) {
			rule := mapOf(raw)
			tag, _ := rule["outboundTag"].(string)
			blocksUDP = blocksUDP || (rule["network"] == "udp" && strings.HasSuffix(tag, "block-udp"))
		}
		if blocksUDP != (i == 1) {
			t.Fatal("UDP policy changed")
		}
		for _, raw := range asSlice(config["outbounds"]) {
			if proto := mapOf(raw)["protocol"]; proto == "freedom" || proto == "direct" {
				t.Fatal("direct egress in protected group")
			}
		}
		if bin := os.Getenv("XRAY_TEST_BINARY"); bin != "" {
			raw, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "group.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if msg, err := exec.Command(bin, "run", "-test", "-config", path).CombinedOutput(); err != nil {
				t.Fatalf("xray -test: %v: %s", err, msg)
			}
		}
	}
}

func TestUnrepresentableProviderGroupReportedPerSource(t *testing.T) {
	body := staticClashEndpoints + `proxy-groups:
  - {name: default-lazy, type: url-test, proxies: [Two]}
  - {name: hysteresis, type: url-test, proxies: [Two], lazy: false, tolerance: 100}
  - {name: dynamic, type: url-test, use: [remote], lazy: false}
  - {name: nested, type: url-test, proxies: [dynamic, Two], lazy: false}
  - {name: direct-exit, type: url-test, proxies: [DIRECT, Two], lazy: false}
  - {name: expects-204, type: url-test, proxies: [Two], lazy: false, expected-status: "204"}
  - {name: priorities, type: fallback, proxies: [Two], lazy: false}
  - {name: duplicated, type: url-test, proxies: [Two], lazy: false}
  - {name: duplicated, type: url-test, proxies: [Two], lazy: false}
  - {name: missing, type: url-test, proxies: [Two, Absent], lazy: false}
  - {name: repeated, type: url-test, proxies: [Two, Two], lazy: false}
`
	_, report, err := ParseSubscriptionDetailed(body)
	if err != nil || report.Imported != 2 || report.ImportedProfiles != 0 || report.SkippedComposite != 11 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	for _, body := range []string{
		strings.Replace(staticClashEndpoints, "udp: true}", "udp: false}", 1),
		strings.Replace(staticClashEndpoints, "name: \"🇩🇪 One\"", "name: Two", 1),
		"unified-delay: true\n" + staticClashEndpoints,
	} {
		_, r, err := ParseSubscriptionDetailed(body + "proxy-groups:\n  - {name: ambiguous, type: url-test, proxies: [Two, \"🇩🇪 One\"], lazy: false}\n")
		if err != nil || r.SkippedComposite != 1 || r.ImportedProfiles != 0 {
			t.Fatal("ambiguous or changed membership accepted")
		}
	}
	_, sb, err := ParseSubscriptionDetailed(`{"outbounds":[{"type":"socks","tag":"A","server":"example.invalid","server_port":1080},{"type":"urltest","tag":"fast","outbounds":["A"],"tolerance":0}]}`)
	if err != nil || sb.SkippedComposite != 1 || sb.ImportedProfiles != 0 {
		t.Fatal("sing-box tolerance/idle behavior discarded")
	}
	data := models.SubscriptionData{Sources: []models.SubscriptionSource{{ID: "clash", Report: report}, {ID: "singbox", Report: sb}}}
	summaries := SourceSummaries(data)
	if len(summaries) != 2 || summaries[0].SkippedComposite != 11 || summaries[1].SkippedComposite != 1 {
		t.Fatal("import counters mixed between sources")
	}
}
