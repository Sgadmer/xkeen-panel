package xkeen

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"xkeen-panel/internal/models"
)

func TestServiceTargetPathClearsConflictingAliasExit(t *testing.T) {
	rt := Runtime{XrayConfDir: t.TempDir()}
	server := poolServers()[0]
	server.SourceName, server.EntryCountry, server.ExitCountry, server.ExitCheckedAt = "A", "RU", "SE", time.Now()
	alias := server
	alias.SourceName = "B"
	view := func() ServiceTarget {
		t.Helper()
		result, err := ReadServiceRoutes(rt, []models.Server{server, alias})
		if err != nil || len(result.Targets) != 1 {
			t.Fatalf("read target: %v", err)
		}
		return result.Targets[0]
	}
	got := view()
	if !slices.Equal(got.CountryPath, []string{"RU", "SE"}) || len(got.Sources) != 2 {
		t.Fatal(got)
	}
	alias.ExitCountry = "NL"
	got = view()
	if got.EntryCountry != "RU" || got.ExitCountry != "" || len(got.CountryPath) != 0 {
		t.Fatal(got)
	}
}

func TestServiceRoutesPreserveDirectAndPinExactTarget(t *testing.T) {
	rt, path, _, baseline := profileApplyBaseline(t)
	servers := poolServers()
	first, second := ServiceTargetID(servers[0]), ServiceTargetID(servers[1])
	if first == "" || first == second {
		t.Fatal("identities must distinguish servers")
	}
	rename := servers[0]
	rename.Name = "renamed server"
	rename.ID = 94
	if ServiceTargetID(rename) != first {
		t.Fatal("reordering changed an identity")
	}
	if _, err := reconcileServiceRoutes(rt, path, servers, "claude", first); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcileServiceRoutes(rt, path, servers, "openai", second); err != nil {
		t.Fatal(err)
	}
	rules := policyRules(t, rt)
	if mapOf(rules[0])["outboundTag"] != servicePrefix+first || mapOf(rules[1])["outboundTag"] != servicePrefix+first || mapOf(rules[2])["outboundTag"] != servicePrefix+second {
		t.Fatal("service did not select its exact target")
	}
	if !sameJSON(map[string]interface{}{"rules": rules[3:]}, map[string]interface{}{"rules": mapOf(baseline["routing"])["rules"]}) {
		t.Fatal("changed unassigned or direct routes")
	}
	ob := asSlice(profileApplyDocument(t, ServiceFragmentPath(rt))["outbounds"])
	if len(ob) != 3 || mapOf(ob[0])["protocol"] != "blackhole" {
		t.Fatal("service handlers were lost")
	}
	for _, tag := range ReadTopology(rt).ProxyTags {
		if strings.HasPrefix(tag, servicePrefix) {
			t.Fatal("service target entered global pool")
		}
	}
	if changed, err := reconcileServiceRoutes(rt, path, servers, "", ""); err != nil || changed {
		t.Fatalf("idempotent refresh: %v %v", changed, err)
	}
	replacement := servers[1]
	replacement.Name = servers[0].Name
	if _, err := reconcileServiceRoutes(rt, path, []models.Server{replacement}, "", ""); err != nil {
		t.Fatal(err)
	}
	rules = policyRules(t, rt)
	if mapOf(rules[0])["outboundTag"] != serviceBlock || mapOf(rules[1])["outboundTag"] != serviceBlock || mapOf(rules[2])["outboundTag"] != servicePrefix+second {
		t.Fatal("a missing node inherited another target")
	}
	view, err := ReadServiceRoutes(rt, []models.Server{replacement})
	if err != nil || !view.Services[0].Blocked || view.Services[0].Target != first {
		t.Fatal("missing assignment wasn't kept as blocked")
	}
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), "vless://") || strings.Contains(string(raw), "settings") {
		t.Fatal("API exposed raw outbound")
	}
	if _, err := reconcileServiceRoutes(rt, path, servers, "claude", ""); err == nil {
		t.Fatal("accepted direct for Claude")
	}
}

func TestServicePriorityWithExclusionsAndSeparateClaudeIngress(t *testing.T) {
	rt, path, _, _ := profileApplyBaseline(t)
	profileApplyWrite(t, filepath.Join(rt.XrayConfDir, "03_private.json"), map[string]interface{}{"inbounds": []interface{}{
		map[string]interface{}{"tag": ClaudeClientInbound, "protocol": "http", "listen": "127.0.0.1", "port": 49001},
	}})
	servers := poolServers()
	if _, err := reconcileServiceRoutes(rt, path, servers, "openai", ServiceTargetID(servers[0])); err != nil {
		t.Fatal(err)
	}
	ex, err := NormalizeExclusion("claude.ai", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteExclusionsConfig(rt, Exclusions{Entries: []Exclusion{ex}}); err != nil {
		t.Fatal(err)
	}
	rules := policyRules(t, rt)
	first := mapOf(rules[0])
	if first["outboundTag"] != serviceBlock || strings.Join(stringList(first["inboundTag"]), ",") != ClaudeClientInbound {
		t.Fatal("dedicated client can reach legacy rules")
	}
	if mapOf(rules[1])["ruleTag"] != servicePrefix+"claude" || mapOf(rules[2])["ruleTag"] != servicePrefix+"claude-ips" || mapOf(rules[3])["ruleTag"] != servicePrefix+"openai" || mapOf(rules[4])["outboundTag"] != "direct" {
		t.Fatal("exclusion precedes protected service or was removed")
	}
	if err := SetManualOutbound(rt, path, servers[1]); err != nil {
		t.Fatal(err)
	}
	if mapOf(policyRules(t, rt)[1])["outboundTag"] != serviceBlock {
		t.Fatal("global selection removed protected rule")
	}
}
