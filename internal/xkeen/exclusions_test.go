package xkeen

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestNormalizeExclusion(t *testing.T) {
	for _, tc := range []struct{ input, kind, value string }{
		{" HTTPS://Shop.Example.COM:443/path?token=ignored#fragment ", "domain", "domain:shop.example.com"},
		{"Example.COM.", "domain", "domain:example.com"},
		{"full:API.Example.COM", "full", "full:api.example.com"},
		{"domain:Example.COM", "domain", "domain:example.com"},
		{"192.0.2.9", "ip", "192.0.2.9"},
		{"192.0.2.19/24", "ip", "192.0.2.0/24"},
		{"2001:db8::1234/48", "ip", "2001:db8::/48"},
		{"https://[2001:db8::1]:443/a", "ip", "2001:db8::1"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			entry, err := NormalizeExclusion(tc.input, " comment ")
			if err != nil || entry.Type != tc.kind || entry.Value != tc.value || entry.Comment != "comment" {
				t.Fatalf("normalization failed: %+v %v", entry, err)
			}
			again, err := NormalizeExclusion(entry.Value, entry.Comment)
			if err != nil || entry != again {
				t.Fatal("normalization was not stable")
			}
		})
	}
}

func TestNormalizeExclusionRejectsAmbiguousAndUnsafeInput(t *testing.T) {
	for _, input := range []string{"", "*.example.com", "https://user:secret@example.com/a", "ftp://example.com", "https:///example.com", "example.com/path", "example.com:443", "999.1.2.3", "10.0.0.0/33", "2001:db8::%eth0", "regexp:.*", "geosite:ru", "domain:example.com;echo secret", "https://example.com:bad/path", "-bad.example", "a..example", "https://example.com\nattacker.test"} {
		if _, err := NormalizeExclusion(input, ""); err == nil {
			t.Errorf("accepted invalid exclusion %q", input)
		}
	}
	if _, err := NormalizeExclusion("example.com", "line\nbreak"); err == nil {
		t.Fatal("accepted control character comment")
	}
}

func exclusionsFixture(t *testing.T) (Runtime, string, Exclusions) {
	t.Helper()
	rt, path, _, _ := profileApplyBaseline(t)
	inputs := filepath.Join(rt.XrayConfDir, "03_inbounds.json")
	doc := profileApplyDocument(t, inputs)
	doc["inbounds"] = append(asSlice(doc["inbounds"]),
		map[string]interface{}{"tag": "api", "protocol": "dokodemo-door"},
		map[string]interface{}{"tag": ProbeInboundTag, "protocol": "socks"},
		map[string]interface{}{"tag": profileInboundPrefix + "synthetic", "protocol": "tunnel"})
	profileApplyWrite(t, inputs, doc)
	entry, err := NormalizeExclusion("https://shop.example.com/app?private=removed", "Лента")
	if err != nil {
		t.Fatal(err)
	}
	return rt, path, Exclusions{Entries: []Exclusion{entry}}
}

func TestExclusionsScopeDoesNotBypassProbeOrProviderGuards(t *testing.T) {
	rt, _, entries := exclusionsFixture(t)
	doc, err := BuildExclusionsConfig(rt, entries)
	if err != nil {
		t.Fatal(err)
	}
	rules := asSlice(mapOf(doc["routing"])["rules"])
	if len(rules) < 1 {
		t.Fatal("missing exception route")
	}
	rule := mapOf(rules[0])
	if !reflect.DeepEqual(rule["inboundTag"], []string{"redirect", "tproxy"}) || rule["outboundTag"] != "direct" {
		t.Fatalf("unsafe route scope: %+v", rule)
	}
}

func TestExclusionsSurviveProfileReapplyPoolRefreshAndOrdinarySelection(t *testing.T) {
	rt, path, entries := exclusionsFixture(t)
	if err := WriteExclusionsConfig(rt, entries); err != nil {
		t.Fatal(err)
	}
	before := exclusionRulesForTest(t, rt)
	profile := profileServer(t, profileFixture())
	for i := 0; i < 2; i++ {
		if err := SetManualOutbound(rt, path, profile); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, exclusionRulesForTest(t, rt)) {
			t.Fatal("profile reapply changed exclusions")
		}
	}
	if _, err := RefreshPool(rt, path, "", poolServers(), PoolState{Selector: DefaultPoolSelector, BalancerTag: DefaultBalancerTag}, PoolSelection{MaxNodes: 2}); err != nil {
		t.Fatal(err)
	}
	if err := SetManualOutbound(rt, path, poolServers()[0]); err != nil {
		t.Fatal(err)
	}
	after := exclusionRulesForTest(t, rt)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("profile or pool changed exclusions")
	}
}

func exclusionRulesForTest(t *testing.T, rt Runtime) []interface{} {
	t.Helper()
	doc := profileApplyDocument(t, ExclusionsConfigPath(rt))
	rules := asSlice(mapOf(doc["routing"])["rules"])
	var found []interface{}
	for _, raw := range rules {
		rule := mapOf(raw)
		tag, _ := rule["ruleTag"].(string)
		if strings.HasPrefix(tag, exclusionRulePrefix) {
			found = append(found, raw)
			continue
		}
		if len(stringList(rule["inboundTag"])) == 0 || containsString(stringList(rule["inboundTag"]), "redirect") {
			if rule["balancerTag"] != nil || rule["outboundTag"] == "block" {
				if len(found) == 0 {
					t.Fatal("proxy or block precedes exclusions")
				}
			}
		}
	}
	if len(found) != 1 {
		t.Fatal("missing or duplicated exclusion")
	}
	return found
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func TestExclusionsStoreRoundTripAndDamagedData(t *testing.T) {
	dir := t.TempDir()
	entry, _ := NormalizeExclusion("example.com", "test")
	want := Exclusions{Entries: []Exclusion{entry}}
	if err := SaveExclusions(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadExclusions(dir)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("roundtrip failed: %+v %v", got, err)
	}
	if err := os.WriteFile(ExclusionsPath(dir), []byte(`{"entries":[{"id":"fake","type":"domain","value":"domain:example.com"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExclusions(dir); err == nil {
		t.Fatal("loaded forged or corrupted store")
	}
}

func TestExclusionsChangedDuringActiveProfileSurviveDifferentProfileAndRemoval(t *testing.T) {
	rt, path, entries := exclusionsFixture(t)
	if err := SetManualOutbound(rt, path, profileServer(t, profileFixture())); err != nil {
		t.Fatal(err)
	}
	if err := WriteExclusionsConfig(rt, entries); err != nil {
		t.Fatal(err)
	}
	before := exclusionRulesForTest(t, rt)
	other := profileFixture()
	other["dns"] = map[string]interface{}{"servers": []interface{}{"1.1.1.1"}}
	if err := SetManualOutbound(rt, path, profileServer(t, other)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, exclusionRulesForTest(t, rt)) {
		t.Fatal("distinct profile changed exceptions added during active profile")
	}
	if err := WriteExclusionsConfig(rt, Exclusions{Entries: []Exclusion{}}); err != nil {
		t.Fatal(err)
	}
	if err := SetManualOutbound(rt, path, poolServers()[0]); err != nil {
		t.Fatal(err)
	}
	doc := profileApplyDocument(t, ExclusionsConfigPath(rt))
	for _, raw := range asSlice(mapOf(doc["routing"])["rules"]) {
		tag, _ := mapOf(raw)["ruleTag"].(string)
		if strings.HasPrefix(tag, exclusionRulePrefix) {
			t.Fatal("ordinary restore resurrected deleted exclusion")
		}
	}
}

func TestExclusionCandidateFailureNeverChangesLiveFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake core is a POSIX executable")
	}
	rt, _, entries := exclusionsFixture(t)
	if err := WriteExclusionsConfig(rt, entries); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(ExclusionsConfigPath(rt))
	core := filepath.Join(t.TempDir(), "fake-xray")
	if err := os.WriteFile(core, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	rt.Installed = true
	rt.CoreBin = core
	if err := WriteExclusionsConfig(rt, Exclusions{Entries: []Exclusion{}}); err == nil {
		t.Fatal("rejected candidate was accepted")
	}
	after, _ := os.ReadFile(ExclusionsConfigPath(rt))
	if !bytes.Equal(before, after) {
		t.Fatal("rejected candidate changed live fragment")
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(rt.XrayConfDir), ".panel-exclusions-test-*"))
	if len(matches) != 0 {
		t.Fatal("candidate staging was not removed")
	}
}
