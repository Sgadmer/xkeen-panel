package updater

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"xkeen-panel/internal/releasesig"
)

const testAsset = "xkeen-panel-aarch64"

// fakeRelease serves a GitHub-shaped latest release whose "binary" is a shell
// script answering -version, which is all the smoke test needs.
type fakeRelease struct {
	tag      string
	reported string // what the binary prints for -version
	sums     string // SHA256SUMS body; "" = computed, "-" = no file in the release
	sig      string // SHA256SUMS.sig body; "" = made with the test key, "-" = no file in the release
	beta     bool   // published as a prerelease
}

// The release key of the tests. Its public half replaces the embedded keys.
var testReleaseKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

func (f fakeRelease) sumsBody() string {
	if f.sums != "" {
		return f.sums
	}
	sum := sha256.Sum256(f.binary())
	return hex.EncodeToString(sum[:]) + "  " + testAsset + "\nffff  xkeen-panel-mipsel\n"
}

func (f fakeRelease) binary() []byte {
	reported := f.reported
	if reported == "" {
		reported = f.tag
	}
	return []byte("#!/bin/sh\necho " + reported + "\n")
}

// serveReleases answers like GitHub for a repository holding these releases,
// in the order given: the updater must not rely on the order of the list.
func serveReleases(t *testing.T, rels ...fakeRelease) *httptest.Server {
	t.Helper()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/owner/repo/releases" {
			var list []string
			for _, f := range rels {
				base := srv.URL + "/dl/" + f.tag + "/"
				assets := fmt.Sprintf(`{"name":%q,"browser_download_url":%q}`, testAsset, base+testAsset)
				if f.sums != "-" {
					assets += fmt.Sprintf(`,{"name":"SHA256SUMS","browser_download_url":%q}`, base+"SHA256SUMS")
				}
				if f.sig != "-" {
					assets += fmt.Sprintf(`,{"name":%q,"browser_download_url":%q}`, releasesig.Asset, base+releasesig.Asset)
				}
				list = append(list, fmt.Sprintf(`{"tag_name":%q,"body":"notes","html_url":"https://example/rel","prerelease":%t,"assets":[%s]}`, f.tag, f.beta, assets))
			}
			fmt.Fprint(w, "["+strings.Join(list, ",")+"]")
			return
		}
		for _, f := range rels {
			switch strings.TrimPrefix(r.URL.Path, "/dl/"+f.tag+"/") {
			case testAsset:
				w.Write(f.binary())
				return
			case "SHA256SUMS":
				fmt.Fprint(w, f.sumsBody())
				return
			case releasesig.Asset:
				if f.sig != "" {
					fmt.Fprint(w, f.sig)
					return
				}
				fmt.Fprintln(w, releasesig.Sign(testReleaseKey, f.tag, []byte(f.sumsBody())))
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

type harness struct {
	u        *Updater
	bin      string
	dataDir  string
	url      string
	restarts atomic.Int32
}

// force puts a release in front of the updater as if a check had accepted it:
// what the installation itself refuses must not depend on the check.
func (h *harness) force(rel fakeRelease) {
	base := h.url + "/dl/" + rel.tag + "/"
	release := Release{Tag: rel.tag, assetURL: base + testAsset}
	if rel.sums != "-" {
		release.sumsURL = base + "SHA256SUMS"
	}
	if rel.sig != "-" {
		release.sigURL = base + releasesig.Asset
	}
	h.u.mu.Lock()
	h.u.latest = &release
	h.u.mu.Unlock()
}

func newHarness(t *testing.T, current string, rels ...fakeRelease) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{bin: filepath.Join(dir, "xkeen-panel"), dataDir: filepath.Join(dir, "data")}

	if err := os.WriteFile(h.bin, []byte("old binary"), 0755); err != nil {
		t.Fatal(err)
	}

	srv := serveReleases(t, rels...)
	h.url = srv.URL
	h.u = New(Options{
		Current:  current,
		BinPath:  h.bin,
		DataDir:  h.dataDir,
		AutoHour: 4,
		Repo:     "owner/repo",
		APIBase:  srv.URL,
		Client:   srv.Client(),
		Restart: func() error {
			h.restarts.Add(1)
			return nil
		},
	})
	h.u.asset = testAsset
	h.u.keys = []ed25519.PublicKey{testReleaseKey.Public().(ed25519.PublicKey)}
	// Short enough not to outlive the test run; by then the temp dir is gone and the guard exits
	h.u.guardDelay = 3 * time.Second
	return h
}

func (h *harness) binContent(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(h.bin)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestParseSemver(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		want semver
	}{
		{"v1.2.3", true, semver{major: 1, minor: 2, patch: 3}},
		{"1.10.0", true, semver{major: 1, minor: 10}},
		{"v1.2.0-5-gabc123-dirty", true, semver{major: 1, minor: 2, suffix: "-5-gabc123-dirty"}},
		{"dev", false, semver{}},
		{"v1.2", false, semver{}},
		{"", false, semver{}},
	}
	for _, c := range cases {
		got, ok := parseSemver(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("parseSemver(%q) = %+v, %v; want %+v, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestNewer(t *testing.T) {
	v := func(s string) semver { r, _ := parseSemver(s); return r }

	cases := []struct {
		current, release string
		want             bool
	}{
		{"v1.2.0", "v1.3.0", true},
		{"v1.9.0", "v1.10.0", true},
		{"v1.3.0", "v1.3.0", false},
		{"v1.3.1", "v1.3.0", false},
		{"v2.0.0", "v1.99.99", false},
		{"v1.3.0-4-gabc", "v1.3.0", false},
		{"v1.3.0-4-gabc", "v1.3.1", true},
	}
	for _, c := range cases {
		if got := newer(v(c.current), v(c.release)); got != c.want {
			t.Errorf("newer(%s, %s) = %v, want %v", c.current, c.release, got, c.want)
		}
	}
}

func TestAssetName(t *testing.T) {
	cases := map[[2]string]string{
		{"linux", "arm64"}:  "xkeen-panel-aarch64",
		{"linux", "mipsle"}: "xkeen-panel-mipsel",
		{"linux", "amd64"}:  "",
		{"darwin", "arm64"}: "",
	}
	for in, want := range cases {
		if got := AssetName(in[0], in[1]); got != want {
			t.Errorf("AssetName(%s, %s) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestCheckFindsNewerRelease(t *testing.T) {
	h := newHarness(t, "v1.3.0", fakeRelease{tag: "v1.3.1"})

	state, err := h.u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !state.Available || state.Latest == nil || state.Latest.Tag != "v1.3.1" || state.Latest.Notes != "notes" {
		t.Errorf("state = %+v, want v1.3.1 available with notes", state)
	}
	// Automatic updates are switched on by the first-run wizard, not by a default.
	if state.Auto || state.Channel != "stable" {
		t.Errorf("auto = %v, channel = %q; want the stable channel and no automatic updates until chosen", state.Auto, state.Channel)
	}
}

// The list to pick from holds signed releases of the channel only, newest
// first, whatever order GitHub returns them in.
func TestVersionsListSignedReleasesOfTheChannel(t *testing.T) {
	rels := []fakeRelease{
		{tag: "v1.3.0"},
		{tag: "v1.4.0-beta.1", beta: true},
		{tag: "v1.3.2", sig: "-"}, // published, not signed yet
		{tag: "v1.3.1"},
		{tag: "v1.2.0"},
	}
	tags := func(state State) string {
		var list []string
		for _, version := range state.Versions {
			list = append(list, version.Tag)
		}
		return strings.Join(list, " ")
	}
	h := newHarness(t, "v1.3.0", rels...)

	state, err := h.u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := tags(state); got != "v1.3.1 v1.3.0 v1.2.0" || state.Latest == nil || state.Latest.Tag != "v1.3.1" || !state.Available {
		t.Fatalf("stable: versions = %q, state = %+v", got, state)
	}

	if err := h.u.SetChannel("preview"); err != nil {
		t.Fatal(err)
	}
	if state := h.u.State(); state.Channel != "preview" || state.Latest != nil || len(state.Versions) != 0 || !state.LastCheck.IsZero() {
		t.Fatalf("the stable list outlived the channel change: %+v", state)
	}
	state, err = h.u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := tags(state); got != "v1.4.0-beta.1 v1.3.1 v1.3.0 v1.2.0" || state.Latest.Tag != "v1.4.0-beta.1" || !state.Versions[0].Prerelease {
		t.Fatalf("preview: versions = %q, state = %+v", got, state)
	}

	reloaded := New(Options{Current: "v1.3.0", BinPath: h.bin, DataDir: h.dataDir, Repo: "owner/repo"})
	if reloaded.State().Channel != "preview" {
		t.Error("the chosen channel did not survive a restart")
	}
	if err := h.u.SetChannel("nightly"); err == nil {
		t.Error("an unknown channel was accepted")
	}
}

func TestApplyVersionRefusesWhatIsNotListed(t *testing.T) {
	h := newHarness(t, "v1.3.0", fakeRelease{tag: "v1.3.0"}, fakeRelease{tag: "v1.3.2", sig: "-"}, fakeRelease{tag: "v1.4.0-beta.1", beta: true})
	if _, err := h.u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, tag := range map[string]string{"empty": "", "running": "v1.3.0", "unsigned": "v1.3.2", "other channel": "v1.4.0-beta.1", "unknown": "v9.9.9"} {
		if err := h.u.ApplyVersion(tag); err == nil {
			t.Errorf("%s: version %q was accepted for installation", name, tag)
		}
	}
	assertUntouched(t, h)
}

// Going back to an older version is the owner's decision: the automatic update
// must not undo it the next night.
func TestApplyVersionInstallsOlderReleaseAndKeepsIt(t *testing.T) {
	requirePOSIXSmokeTest(t)
	h := newHarness(t, "v1.3.1", fakeRelease{tag: "v1.3.1"}, fakeRelease{tag: "v1.3.0"})
	if _, err := h.u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := h.u.ApplyVersion("v1.3.0"); err != nil {
		t.Fatal(err)
	}
	if got := h.u.State().Installing; got != "v1.3.0" {
		t.Errorf("installing = %q, want the picked version", got)
	}
	waitFor(t, "restart", func() bool { return h.restarts.Load() == 1 })

	if got := h.binContent(t); !strings.Contains(got, "echo v1.3.0") {
		t.Errorf("binary = %q, want the picked release", got)
	}
	older := New(Options{Current: "v1.3.0", BinPath: h.bin, DataDir: h.dataDir, AutoHour: 4, Repo: "owner/repo"})
	if got := older.State().Skip; got != "v1.3.1" {
		t.Errorf("skip = %q; the automatic update would put v1.3.1 back", got)
	}
}

// A build put on the router past the updater leaves nothing to skip once it
// is not behind the skipped release.
func TestStaleSkipIsDroppedAtStart(t *testing.T) {
	for current, want := range map[string]string{"v1.3.0": "v1.3.1", "v1.3.1": "", "v1.4.0": ""} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "update.json"), []byte(`{"auto":true,"auto_set":true,"repository":"owner/repo","skip":"v1.3.1"}`), 0600); err != nil {
			t.Fatal(err)
		}
		if got := New(Options{Current: current, DataDir: dir, Repo: "owner/repo"}).State().Skip; got != want {
			t.Errorf("running %s: skip = %q, want %q", current, got, want)
		}
	}
}

func TestCheckSameVersionIsNotAvailable(t *testing.T) {
	h := newHarness(t, "v1.3.1", fakeRelease{tag: "v1.3.1"})

	state, _ := h.u.Check(context.Background())
	if state.Available {
		t.Error("the running release is offered as an update")
	}
}

func TestDevBuildNeverUpdates(t *testing.T) {
	h := newHarness(t, "dev", fakeRelease{tag: "v9.0.0"})

	state, _ := h.u.Check(context.Background())
	if state.Supported || state.Available {
		t.Errorf("state = %+v, want a dev build unsupported", state)
	}
	if err := h.u.Apply(); err == nil {
		t.Error("a dev build replaced itself")
	}
}

func TestApplyInstallsAndRestarts(t *testing.T) {
	requirePOSIXSmokeTest(t)
	h := newHarness(t, "v1.3.0", fakeRelease{tag: "v1.3.1"})
	if _, err := h.u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := h.u.Apply(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "restart", func() bool { return h.restarts.Load() == 1 })

	if got := h.binContent(t); !strings.Contains(got, "echo v1.3.1") {
		t.Errorf("binary = %q, want the release", got)
	}
	if prev, _ := os.ReadFile(h.bin + ".prev"); string(prev) != "old binary" {
		t.Errorf(".prev = %q, want the old binary kept for rollback", prev)
	}
	if _, err := os.Stat(h.u.pendingPath()); err != nil {
		t.Error("no pending marker — the guard could not tell a failed start")
	}
}

func TestApplyRejectsBadChecksum(t *testing.T) {
	h := newHarness(t, "v1.3.0", fakeRelease{tag: "v1.3.1", sums: strings.Repeat("0", 64) + "  " + testAsset + "\n"})
	h.u.Check(context.Background())

	if err := h.u.Apply(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "failure", func() bool { return h.u.State().ApplyError != "" })

	assertUntouched(t, h)
	if !strings.Contains(h.u.State().ApplyError, "контрольная сумма") {
		t.Errorf("error = %q, want a checksum mismatch", h.u.State().ApplyError)
	}
}

func TestApplyRefusesReleaseWithoutSums(t *testing.T) {
	rel := fakeRelease{tag: "v1.3.1", sums: "-"}
	h := newHarness(t, "v1.3.0", rel)
	h.u.Check(context.Background())
	h.force(rel)

	h.u.Apply()
	waitFor(t, "failure", func() bool { return h.u.State().ApplyError != "" })

	assertUntouched(t, h)
}

// A stable release is published by CI first and signed afterwards. Until its
// checksums and signature are in place it is not offered at all.
func TestIncompleteStableReleaseIsNotOffered(t *testing.T) {
	for name, rel := range map[string]fakeRelease{
		"no signature": {tag: "v1.3.1", sig: "-"},
		"no checksums": {tag: "v1.3.1", sums: "-"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "v1.3.0", rel)
			state, err := h.u.Check(context.Background())
			if err != nil || state.Available || state.Latest != nil {
				t.Fatalf("state = %+v, err = %v; want nothing offered", state, err)
			}
			if err := h.u.Apply(); err == nil {
				t.Error("an incomplete release was accepted for installation")
			}
			assertUntouched(t, h)
		})
	}
}

// Whoever controls the repository can publish a binary together with matching
// checksums. Without the signature of a release key neither is trusted.
func TestApplyRefusesReleaseNotSignedByAReleaseKey(t *testing.T) {
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	valid := fakeRelease{tag: "v1.3.1"}
	for name, rel := range map[string]fakeRelease{
		"no signature":       {tag: "v1.3.1", sig: "-"},
		"empty signature":    {tag: "v1.3.1", sig: "\n"},
		"another key":        {tag: "v1.3.1", sig: releasesig.Sign(stranger, "v1.3.1", []byte(valid.sumsBody())) + "\n"},
		"another version":    {tag: "v1.3.1", sig: releasesig.Sign(testReleaseKey, "v1.3.0", []byte(valid.sumsBody())) + "\n"},
		"replaced checksums": {tag: "v1.3.1", sig: releasesig.Sign(testReleaseKey, "v1.3.1", []byte("0000  "+testAsset+"\n")) + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "v1.3.0", rel)
			h.u.Check(context.Background())
			h.force(rel)

			h.u.Apply()
			waitFor(t, "failure", func() bool { return h.u.State().ApplyError != "" })

			assertUntouched(t, h)
			if !strings.Contains(h.u.State().ApplyError, "подпис") {
				t.Errorf("error = %q, want it to name the signature", h.u.State().ApplyError)
			}
		})
	}
}

// The embedded keys are what a real build trusts: a release signed with the
// key of the tests must not pass for them.
func TestEmbeddedKeysDoNotTrustTheTestKey(t *testing.T) {
	h := newHarness(t, "v1.3.0", fakeRelease{tag: "v1.3.1"})
	keys, err := releasesig.Trusted()
	if err != nil || len(keys) == 0 {
		t.Fatalf("embedded keys: %v", err)
	}
	h.u.keys = keys
	h.u.Check(context.Background())

	h.u.Apply()
	waitFor(t, "failure", func() bool { return h.u.State().ApplyError != "" })
	assertUntouched(t, h)
}

// A binary that runs but is not the release it claims to be — wrong asset,
// stale cache — must not replace a working panel.
func TestApplyRejectsVersionMismatch(t *testing.T) {
	requirePOSIXSmokeTest(t)
	h := newHarness(t, "v1.3.0", fakeRelease{tag: "v1.3.1", reported: "v1.2.0"})
	h.u.Check(context.Background())

	h.u.Apply()
	waitFor(t, "failure", func() bool { return h.u.State().ApplyError != "" })

	assertUntouched(t, h)
}

func assertUntouched(t *testing.T, h *harness) {
	t.Helper()
	if got := h.binContent(t); got != "old binary" {
		t.Errorf("binary = %q, want the old one untouched", got)
	}
	for _, path := range []string{h.bin + ".new", h.bin + ".prev"} {
		if _, err := os.Stat(path); err == nil {
			t.Errorf("%s left behind", filepath.Base(path))
		}
	}
	if h.restarts.Load() != 0 {
		t.Error("panel restarted after a failed install")
	}
	if h.u.State().Updating {
		t.Error("still marked as updating")
	}
}

// The guard is what saves a router whose new binary never comes up: nothing
// else is left running to notice.
func TestGuardRollsBackUnconfirmedUpdate(t *testing.T) {
	requirePOSIXSmokeTest(t)
	h := newHarness(t, "v1.3.0", fakeRelease{tag: "v1.3.1"})
	h.u.guardDelay = time.Second
	h.u.Check(context.Background())

	h.u.Apply()
	waitFor(t, "install", func() bool { return h.restarts.Load() == 1 })
	waitFor(t, "guard rollback", func() bool {
		_, err := os.Stat(h.u.failedPath())
		return err == nil
	})

	if got := h.binContent(t); got != "old binary" {
		t.Errorf("binary = %q, want the old one restored", got)
	}

	// The old version comes back up and must not try the same release again
	old := New(Options{Current: "v1.3.0", BinPath: h.bin, DataDir: h.dataDir, AutoHour: 4})
	old.Startup(context.Background(), func() bool { return true })

	state := old.State()
	if state.FailedStart != "v1.3.1" || state.Skip != "v1.3.1" {
		t.Errorf("state = %+v, want v1.3.1 recorded as failed and skipped", state)
	}
}

func TestGuardLeavesConfirmedUpdate(t *testing.T) {
	requirePOSIXSmokeTest(t)
	h := newHarness(t, "v1.3.0", fakeRelease{tag: "v1.3.1"})
	h.u.guardDelay = time.Second
	h.u.Check(context.Background())

	h.u.Apply()
	waitFor(t, "install", func() bool { return h.restarts.Load() == 1 })

	next := New(Options{Current: "v1.3.1", BinPath: h.bin, DataDir: h.dataDir})
	next.confirmAfter = 10 * time.Millisecond
	next.Startup(context.Background(), func() bool { return true })
	waitFor(t, "confirmation", func() bool {
		_, err := os.Stat(next.pendingPath())
		return os.IsNotExist(err)
	})

	time.Sleep(1500 * time.Millisecond)
	if got := h.binContent(t); !strings.Contains(got, "v1.3.1") {
		t.Errorf("binary = %q, want the confirmed release kept", got)
	}
}

func requirePOSIXSmokeTest(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("This smoke test executes its temporary POSIX shell binary; run it natively on Linux, not as a Windows executable")
	}
}

func TestStartupDoesNotConfirmUnhealthyPanel(t *testing.T) {
	h := newHarness(t, "v1.3.1", fakeRelease{tag: "v1.3.1"})
	if err := writeJSON(h.u.pendingPath(), pendingMarker{From: "v1.3.0", To: "v1.3.1"}); err != nil {
		t.Fatal(err)
	}

	h.u.confirmAfter = 10 * time.Millisecond
	h.u.Startup(context.Background(), func() bool { return false })
	time.Sleep(100 * time.Millisecond)

	if _, err := os.Stat(h.u.pendingPath()); err != nil {
		t.Error("an unresponsive panel confirmed its own update")
	}
}

func TestSetAutoPersists(t *testing.T) {
	h := newHarness(t, "v1.3.0", fakeRelease{tag: "v1.3.0"})
	if err := h.u.SetAuto(false); err != nil {
		t.Fatal(err)
	}

	reloaded := New(Options{Current: "v1.3.0", BinPath: h.bin, DataDir: h.dataDir, Repo: "owner/repo"})
	if reloaded.State().Auto {
		t.Error("automatic updates came back on after a restart")
	}
}

// update.json written before automatic updates became the default holds
// "auto": false for everyone who never touched the switch.
// An update of the panel never changes automatic updates: what the file says
// stays, and a router without the file keeps them off.
func TestPanelUpdateKeepsTheAutoSetting(t *testing.T) {
	for raw, want := range map[string]bool{
		``: false,
		`{"auto":false,"repository":"owner/repo","previous":"v1.2.0"}`: false,
		`{"auto":true,"repository":"owner/repo"}`:                      true,
		`{"auto":false,"auto_set":true,"repository":"owner/repo"}`:     false,
		`{"auto":true,"auto_set":true,"repository":"owner/repo"}`:      true,
	} {
		dir := t.TempDir()
		if raw != "" {
			if err := os.WriteFile(filepath.Join(dir, "update.json"), []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if got := New(Options{Current: "v1.3.0", DataDir: dir, Repo: "owner/repo"}).State().Auto; got != want {
			t.Errorf("%q: auto = %v, want %v", raw, got, want)
		}
	}
}

// The first-run wizard turns automatic updates on, once.
func TestWizardOffersAutoUpdatesOnce(t *testing.T) {
	opts := Options{Current: "v1.3.0", DataDir: t.TempDir(), Repo: "owner/repo"}
	u := New(opts)
	if !u.AutoOffered() {
		t.Fatal("a fresh install does not offer automatic updates")
	}
	if err := u.SetAutoDefault(true); err != nil {
		t.Fatal(err)
	}
	if u = New(opts); !u.State().Auto || u.AutoOffered() {
		t.Fatal("the wizard's choice was not kept")
	}

	// The owner switches them off; the wizard, run again, leaves that alone.
	if err := u.SetAuto(false); err != nil {
		t.Fatal(err)
	}
	if u.AutoOffered() {
		t.Fatal("the offer came back after the owner's choice")
	}
	if err := u.SetAutoDefault(true); err != nil {
		t.Fatal(err)
	}
	if New(opts).State().Auto {
		t.Fatal("the wizard undid the owner's choice")
	}

	// Declined in the wizard: off, and not offered again.
	declined := Options{Current: "v1.3.0", DataDir: t.TempDir(), Repo: "owner/repo"}
	u = New(declined)
	if err := u.SetAutoDefault(false); err != nil {
		t.Fatal(err)
	}
	if u = New(declined); u.State().Auto || u.AutoOffered() {
		t.Fatal("a declined offer was not remembered")
	}

	locked := New(Options{Current: "v1.3.0", DataDir: t.TempDir(), Locked: true})
	if locked.AutoOffered() || locked.SetAutoDefault(true) != ErrLocked {
		t.Fatal("a build without updates offered them")
	}
}

func TestShouldAutoApply(t *testing.T) {
	night := time.Date(2026, 10, 2, 4, 15, 0, 0, time.Local)

	cases := []struct {
		name  string
		setup func(u *Updater)
		at    time.Time
		want  bool
	}{
		{"in the window", func(u *Updater) {}, night, true},
		{"outside the window", func(u *Updater) {}, night.Add(3 * time.Hour), false},
		{"turned off", func(u *Updater) { u.settings.Auto = false }, night, false},
		{"skipped release", func(u *Updater) { u.settings.Skip = "v1.3.1" }, night, false},
		{"failed tonight already", func(u *Updater) { u.attempted["v1.3.1"] = night.Add(-30 * time.Minute) }, night, false},
		{"failed yesterday", func(u *Updater) { u.attempted["v1.3.1"] = night.Add(-24 * time.Hour) }, night, true},
		{"core restarting", func(u *Updater) { u.busy = func() bool { return true } }, night, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, "v1.3.0", fakeRelease{tag: "v1.3.1"})
			h.u.settings.Auto = true
			if _, err := h.u.Check(context.Background()); err != nil {
				t.Fatal(err)
			}
			c.setup(h.u)
			if got := h.u.shouldAutoApply(c.at); got != c.want {
				t.Errorf("shouldAutoApply = %v, want %v", got, c.want)
			}
		})
	}
}
