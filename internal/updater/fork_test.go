package updater

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Choices made for another source of updates, or a file that cannot be read,
// leave this panel on its own defaults: stable releases, installed automatically.
func TestForeignOrCorruptPreferencesFallBackToDefaults(t *testing.T) {
	for _, raw := range []string{
		`{"auto":true,"auto_set":true,"channel":"preview","skip":"v9.0.0"}`,
		`{"auto":true,"auto_set":true,"channel":"preview","skip":"v9.0.0","repository":"Dearonski/xkeen-panel"}`,
		`{"auto":true,"auto_set":true,"channel":"preview","repository":"Sgadmer/xkeen-panel",BROKEN}`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "update.json"), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		opts := Options{Current: "v3.0.0-beta.1", DataDir: dir}
		u := New(opts)
		if state := u.State(); state.Auto || state.Channel != "stable" || state.Skip != "" {
			t.Fatalf("%s: foreign preferences were inherited: %+v", raw, state)
		}
		if err := u.SetAuto(true); err != nil {
			t.Fatal(err)
		}
		if !New(opts).State().Auto {
			t.Fatal("the owner's choice for this source was not retained")
		}
	}
}

func TestForkUpdatesStayInOwnRepository(t *testing.T) {
	u := New(Options{Current: "v2.2.0", BinPath: "/opt/sbin/xkeen-panel", DataDir: t.TempDir()})
	if u.State().Auto || u.State().Channel != "stable" || u.State().Repository != "Sgadmer/xkeen-panel" {
		t.Fatal("fresh fork update policy is incorrect")
	}
	for _, raw := range []string{
		"https://api.github.com/repos/Sgadmer/xkeen-panel/releases?per_page=100",
		"https://github.com/Sgadmer/xkeen-panel/releases/download/v2.2.0/xkeen-panel-aarch64",
	} {
		if !trustedUpdateURL(raw, DefaultRepo) {
			t.Fatal("rejected own release")
		}
	}
	for _, raw := range []string{
		"https://github.com/Dearonski/xkeen-panel/releases/download/v2.2.0/xkeen-panel-aarch64",
		"http://github.com/Sgadmer/xkeen-panel/releases/download/v2.2.0/xkeen-panel-aarch64",
		"https://github.com.attacker.invalid/Sgadmer/xkeen-panel/releases/download/v2.2.0/xkeen-panel-aarch64",
		"https://user@github.com/Sgadmer/xkeen-panel/releases/download/v2.2.0/xkeen-panel-aarch64",
		"https://api.github.com/repos/Dearonski/xkeen-panel/releases?per_page=100",
		"https://api.github.com/repos/Sgadmer/xkeen-panel/releases/latest",
		"https://api.github.com/repos/Sgadmer/xkeen-panel/releases?per_page=100&redirect=elsewhere",
	} {
		if trustedUpdateURL(raw, DefaultRepo) {
			t.Fatal("accepted unrelated release")
		}
	}
}

func TestUpdateDoesNotReplaceBinaryWithoutRecoveryMarker(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake binary is a POSIX script")
	}
	h := newHarness(t, "v2.2.0", fakeRelease{tag: "v2.2.1"})
	if _, err := h.u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.dataDir, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.u.install(context.Background(), *h.u.latest); err == nil {
		t.Fatal("update ignored missing recovery state")
	}
	if h.binContent(t) != "old binary" {
		t.Fatal("old binary was lost")
	}
}
