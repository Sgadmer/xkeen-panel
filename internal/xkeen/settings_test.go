package xkeen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateSettingsRejectsNamelessPolicy(t *testing.T) {
	cases := map[string]struct {
		cfg     map[string]interface{}
		wantErr bool
	}{
		"empty config": {map[string]interface{}{}, false},
		"scalars only": {map[string]interface{}{
			"xkeen": map[string]interface{}{"gh_proxy": "https://gh-proxy.com"},
		}, false},
		"named policy": {map[string]interface{}{
			"xkeen": map[string]interface{}{
				"policy": []interface{}{map[string]interface{}{"name": "XKeen", "port": "1181"}},
			},
		}, false},
		// XKeen refuses to start the proxy when a policy has no name
		"nameless policy": {map[string]interface{}{
			"xkeen": map[string]interface{}{
				"policy": []interface{}{map[string]interface{}{"port": "1181"}},
			},
		}, true},
		"blank name": {map[string]interface{}{
			"xkeen": map[string]interface{}{
				"policy": []interface{}{map[string]interface{}{"name": "  "}},
			},
		}, true},
		"policy not an array": {map[string]interface{}{
			"xkeen": map[string]interface{}{"policy": "XKeen"},
		}, true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidateSettings(tc.cfg)
			if tc.wantErr && err == nil {
				t.Error("expected an error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestReadSettingsMissingFile(t *testing.T) {
	cfg, err := ReadSettings(filepath.Join(t.TempDir(), "xkeen.json"))
	if err != nil {
		t.Fatalf("ReadSettings: %v", err)
	}
	if len(cfg) != 0 {
		t.Errorf("cfg = %v, want empty", cfg)
	}
}

func TestWriteSettingsRoundtripAndBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xkeen.json")
	if err := os.WriteFile(path, []byte("{\n}\n"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cfg := map[string]interface{}{
		"xkeen": map[string]interface{}{"gh_proxy": "https://ghfast.top"},
	}
	if err := WriteSettings(path, cfg); err != nil {
		t.Fatalf("WriteSettings: %v", err)
	}

	got, err := ReadSettings(path)
	if err != nil {
		t.Fatalf("ReadSettings: %v", err)
	}
	section := got["xkeen"].(map[string]interface{})
	if section["gh_proxy"] != "https://ghfast.top" {
		t.Errorf("gh_proxy = %v", section["gh_proxy"])
	}

	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf("backup missing: %v", err)
	}
}

func TestWriteSettingsRefusesInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xkeen.json")
	original := `{"xkeen":{"gh_proxy":"https://gh-proxy.com"}}`
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	broken := map[string]interface{}{
		"xkeen": map[string]interface{}{"policy": []interface{}{map[string]interface{}{"port": "1181"}}},
	}
	if err := WriteSettings(path, broken); err == nil {
		t.Fatal("expected a refusal")
	}

	body, _ := os.ReadFile(path)
	if string(body) != original {
		t.Error("file was modified despite the refusal")
	}
}

func TestValidateListPorts(t *testing.T) {
	// The shipped file: commented examples plus a hint line
	shipped := "#80\n#443\n#596:599\n\n# (Раскомментируйте) единичные порты и диапазоны\n"
	if err := ValidateList(shipped, ListPorts); err != nil {
		t.Errorf("shipped file rejected: %v", err)
	}

	if err := ValidateList("80\n443\n596:599\n", ListPorts); err != nil {
		t.Errorf("valid ports rejected: %v", err)
	}

	for _, bad := range []string{"0", "65536", "abc", "600:500", "80:"} {
		if err := ValidateList(bad, ListPorts); err == nil {
			t.Errorf("ValidateList(%q) accepted an invalid entry", bad)
		}
	}
}

func TestValidateListIPs(t *testing.T) {
	shipped := "#192.168.0.0/16\n#2001:db8::/32\n\n# Добавьте необходимые IP\n"
	if err := ValidateList(shipped, ListIPs); err != nil {
		t.Errorf("shipped file rejected: %v", err)
	}

	if err := ValidateList("192.168.0.0/16\n2001:db8::/32\n10.0.0.1/32\n", ListIPs); err != nil {
		t.Errorf("valid entries rejected: %v", err)
	}

	// A bare address is what ipset rejects, so the panel must catch it first
	if err := ValidateList("10.0.0.1", ListIPs); err == nil {
		t.Error("bare address accepted")
	}
	if err := ValidateList("10.0.0.1/33", ListIPs); err == nil {
		t.Error("out-of-range prefix accepted")
	}
	if err := ValidateList("2001:db8::/129", ListIPs); err == nil {
		t.Error("out-of-range IPv6 prefix accepted")
	}
}

func TestListEntriesSkipCommentsAndPortListCoversRanges(t *testing.T) {
	list := "#80\n\n 27015 \n596:599 # игра\n# 443\n"
	if got := ListEntries(list); len(got) != 2 || got[0] != "27015" || got[1] != "596:599" {
		t.Fatalf("entries = %q", got)
	}
	for port, want := range map[int]bool{27015: true, 596: true, 598: true, 599: true, 600: false, 80: false, 443: false} {
		if got := PortListCovers(list, port); got != want {
			t.Errorf("PortListCovers(%d) = %v, want %v", port, got, want)
		}
	}
	if !PortListCovers("1:65535\n", 443) {
		t.Error("a range over every port does not cover 443")
	}
}

func TestPortAllowListMustKeepTheWebPorts(t *testing.T) {
	// A filled port_proxying list sends every other port past the core.
	for _, list := range []string{"27015\n", "443\n", "80\n50000:50030\n", "#443\n80\n", "81:442\n"} {
		if err := CheckListPolicy("port_proxying", list); err == nil {
			t.Errorf("a list that sends sites past the core was accepted: %q", list)
		}
	}
	for _, list := range []string{"80\n443\n", "80\n443\n50000:50030\n", "1:65535\n", "",
		"#80\n#443\n\n# (Раскомментируйте) единичные порты и диапазоны\n"} {
		if err := CheckListPolicy("port_proxying", list); err != nil {
			t.Errorf("%q refused: %v", list, err)
		}
	}
	for _, name := range []string{"port_exclude", "ip_exclude"} {
		if err := CheckListPolicy(name, "27015\n"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDefaultProxyPortsFillOnlyAnUntouchedRouter(t *testing.T) {
	shipped := "#80\n#443\n#596:599\n\n# (Раскомментируйте) единичные порты и диапазоны"
	fresh := func(t *testing.T, proxying, exclude string) (Runtime, string) {
		dir := t.TempDir()
		for name, content := range map[string]string{"port_proxying.lst": proxying, "port_exclude.lst": exclude} {
			if content != "-" {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
					t.Fatal(err)
				}
			}
		}
		return Runtime{XkeenJSON: filepath.Join(dir, "xkeen.json")}, filepath.Join(dir, "port_proxying.lst")
	}

	// The shipped file, and no file at all: the defaults are written.
	for _, start := range []string{shipped, "-"} {
		rt, path := fresh(t, start, "-")
		if written, err := ApplyDefaultProxyPorts(rt); err != nil || !written {
			t.Fatalf("%q: written = %v, err = %v", start, written, err)
		}
		data, _ := os.ReadFile(path)
		if got := ListEntries(string(data)); strings.Join(got, ",") != "80,443,596:599,50000:50030" {
			t.Fatalf("%q: entries = %q", start, got)
		}
		if start != "-" && !strings.HasPrefix(string(data), shipped+"\n") {
			t.Errorf("the shipped examples were lost: %q", data)
		}
		if err := ValidateList(string(data), ListPorts); err != nil {
			t.Errorf("the written list does not validate: %v", err)
		}
		// A second run changes nothing.
		if written, err := ApplyDefaultProxyPorts(rt); err != nil || written {
			t.Errorf("the defaults were written twice: %v %v", written, err)
		}
	}

	// The owner already chose ports, either way: nothing is touched.
	for _, lists := range [][2]string{{"443\n80\n8443\n", "-"}, {shipped, "27015\n"}} {
		rt, path := fresh(t, lists[0], lists[1])
		if ProxyPortsUnset(rt) {
			t.Fatalf("%q: chosen ports were not seen", lists)
		}
		if written, err := ApplyDefaultProxyPorts(rt); err != nil || written {
			t.Fatalf("%q: written = %v, err = %v", lists, written, err)
		}
		if data, _ := os.ReadFile(path); string(data) != lists[0] {
			t.Errorf("%q: the owner's list was rewritten: %q", lists, data)
		}
	}
}

func TestValidateListReportsLineNumber(t *testing.T) {
	err := ValidateList("80\n443\nnope\n", ListPorts)
	if err == nil || !strings.Contains(err.Error(), "строка 3") {
		t.Errorf("error = %v, want it to point at line 3", err)
	}
}

func TestListPath(t *testing.T) {
	rt := Runtime{XkeenJSON: "/opt/etc/xkeen/xkeen.json"}

	path, kind, err := ListPath(rt, "port_proxying")
	if err != nil {
		t.Fatalf("ListPath: %v", err)
	}
	if path != filepath.FromSlash("/opt/etc/xkeen/port_proxying.lst") {
		t.Errorf("path = %q", path)
	}
	if kind != ListPorts {
		t.Errorf("kind = %q, want ports", kind)
	}

	if _, _, err := ListPath(rt, "../../etc/passwd"); err == nil {
		t.Error("unknown list name accepted — the name must not be a path")
	}
}
