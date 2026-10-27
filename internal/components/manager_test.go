package components

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"xkeen-panel/internal/xkeen"
)

func testManager(t *testing.T) (*Manager, xkeen.Runtime) {
	t.Helper()
	root := t.TempDir()
	path := func(p string) string { return filepath.Join(root, p) }
	rt := xkeen.Runtime{Installed: true, Generation: 2, Core: xkeen.CoreXray, Version: "2.0 Stable", CoreBin: path("opt/sbin/xray"), Dispatcher: path("opt/sbin/xkeen"), InitScript: path("opt/etc/init.d/S05xkeen"), XrayConfDir: path("opt/etc/xray/configs"), RoutingFile: path("opt/etc/xray/configs/05_routing.json"), XkeenJSON: path("opt/etc/xkeen/xkeen.json")}
	for _, dir := range []string{rt.XrayConfDir, filepath.Dir(rt.Dispatcher), filepath.Dir(rt.InitScript), filepath.Dir(rt.XkeenJSON), path("opt/etc/xkeen-panel/data"), path("opt/etc/xray/dat")} {
		if e := os.MkdirAll(dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	writeTest(t, rt.CoreBin, []byte("fixture-core"))
	writeTest(t, rt.Dispatcher, []byte("\n -auto)\n -dns)\n -pr)\n -ipv6)\n -extmsg)\n -cbk)\n -dgc)\n"))
	writeTest(t, rt.InitScript, []byte("start_auto=on\nproxy_dns=off\nproxy_router=off\nipv6_support=on\nextended_msg=off\nbackup=on\n"))
	writeTest(t, rt.XkeenJSON, []byte("{}\n"))
	writeTest(t, rt.RoutingFile, []byte(`{"routing":{"rules":[{"outboundTag":"direct"}]}}`))
	m := New(Options{Root: root, DataDir: path("opt/etc/xkeen-panel/data"), Runtime: func() xkeen.Runtime { return rt }, GOOS: "linux", GOARCH: "arm64", TestHTTP: true, Firmware: func() string { return "5.1" }, Validate: func(context.Context, string) error { return nil }, Restart: func(context.Context) error { return nil }, FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
	return m, rt
}
func writeTest(t *testing.T, path string, body []byte) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, body, 0700); e != nil {
		t.Fatal(e)
	}
}
func waitJob(t *testing.T, m *Manager) Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		j := *m.job
		m.mu.Unlock()
		if j.Finished != nil {
			return j
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return Job{}
}

func geoServer(t *testing.T, m *Manager, body []byte, digest string) *atomic.Int32 {
	t.Helper()
	counter := &atomic.Int32{}
	var address string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/payload" {
			counter.Add(1)
			_, _ = w.Write(body)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/repos/") {
			_ = json.NewEncoder(w).Encode(githubRelease{Version: "2026.10.27", Assets: []Asset{{Name: "dlc.dat", Size: int64(len(body)), Digest: digest, URL: address + "/payload"}}})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	address = server.URL
	m.apiBase = address
	return counter
}
func digestOf(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestComponentsCatalogFiltersStableAndPrereleaseAndCaches(t *testing.T) {
	m, _ := testManager(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode([]githubRelease{{Version: "2.1", Name: "Stable"}, {Version: "2.2-beta", Prerelease: true}, {Version: "draft", Draft: true}})
	}))
	defer server.Close()
	m.apiBase = server.URL
	stable, e := m.Releases(context.Background(), "xkeen", "stable")
	if e != nil || len(stable) != 1 || stable[0].Version != "2.1" {
		t.Fatalf("stable: %+v %v", stable, e)
	}
	_, _ = m.Releases(context.Background(), "xkeen", "stable")
	if calls.Load() != 1 {
		t.Fatal("release catalog not cached")
	}
	beta, e := m.Releases(context.Background(), "xkeen", "prerelease")
	if e != nil || len(beta) != 1 || beta[0].Version != "2.2-beta" {
		t.Fatalf("prerelease: %+v %v", beta, e)
	}
	for _, request := range []PlanRequest{{Component: "../../bin"}, {Component: "xray", Version: "v26;echo-secret"}, {Component: "xray", Version: "../main"}} {
		if _, e = m.Preview(context.Background(), request); e == nil {
			t.Fatal("accepted unsafe release identifier")
		}
	}
}

func TestComponentsProductionRejectsExternalURLsAndUnsafeRedirect(t *testing.T) {
	m, _ := testManager(t)
	m.opts.TestHTTP = false
	for _, address := range []string{"http://github.com/a", "https://evil.example/file", "https://github.com:444/a", "https://name:secret@github.com/a"} {
		req, _ := http.NewRequest("GET", address, nil)
		if m.allowedURL(req.URL) {
			t.Errorf("allowed %s", address)
		}
	}
	r := Release{Version: "2.1", Assets: []Asset{{Name: "xkeen.tar.gz", Size: 1, Digest: digestOf([]byte("a")), URL: "https://github.com/attacker/repo/releases/download/2.1/xkeen.tar.gz"}}}
	if _, e := m.resolveArtifact(context.Background(), "jameszeroX/XKeen", r, "xkeen.tar.gz", "xkeen"); e == nil {
		t.Fatal("accepted artifact from other repository")
	}
}

func TestComponentsGeodataPersistAndValidate(t *testing.T) {
	m, _ := testManager(t)
	valid := GeoSettings{Sources: []string{"geoip-v2fly", "geosite-v2fly"}, Auto: true, Day: 1, Hour: 6, Minute: 15}
	if e := m.SetGeodata(valid); e != nil {
		t.Fatal(e)
	}
	copy := New(m.opts)
	if !copy.geo.Auto || len(copy.geo.Sources) != 2 || copy.geo.Minute != 15 {
		t.Fatal("schedule did not persist")
	}
	for _, bad := range []GeoSettings{{Sources: []string{"unknown"}}, {Auto: true}, {Sources: []string{"geoip-v2fly", "geoip-v2fly"}}, {Hour: 24}, {Day: 7}, {Minute: 60}} {
		if e := m.SetGeodata(bad); e == nil {
			t.Fatal("accepted invalid geodata settings")
		}
	}
	cron := m.path("/opt/var/spool/cron/crontabs/root")
	writeTest(t, cron, []byte("0 4 * * * /opt/sbin/xkeen -ug\n"))
	if e := m.SetGeodata(valid); e == nil {
		t.Fatal("accepted conflicting native cron schedule")
	}
}

func TestComponentsGeodataApplyPreservesConfigAndCreatesVerifiedRollback(t *testing.T) {
	m, rt := testManager(t)
	body := []byte("synthetic-geodata-for-tests")
	geoServer(t, m, body, digestOf(body))
	if e := m.SetGeodata(GeoSettings{Sources: []string{"geosite-v2fly"}, Day: -1}); e != nil {
		t.Fatal(e)
	}
	old := []byte("previous-geodata")
	target := filepath.Join(filepath.Dir(rt.XrayConfDir), "dat", "geosite_v2fly.dat")
	writeTest(t, target, old)
	config, _ := os.ReadFile(rt.RoutingFile)
	var restarts atomic.Int32
	m.opts.Restart = func(context.Context) error { restarts.Add(1); return nil }
	plan, e := m.Preview(context.Background(), PlanRequest{Component: "geodata"})
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(plan)
	if bytes.Contains(encoded, []byte("/payload")) || bytes.Contains(encoded, []byte(rt.XrayConfDir)) {
		t.Fatal("preview disclosed internal/download state")
	}
	if _, e = m.Apply(plan.ID); e != nil {
		t.Fatal(e)
	}
	job := waitJob(t, m)
	if job.Error != "" || job.Phase != "complete" || job.BackupID == "" {
		t.Fatalf("job: %+v", job)
	}
	got, _ := os.ReadFile(target)
	after, _ := os.ReadFile(rt.RoutingFile)
	if !bytes.Equal(got, body) || !bytes.Equal(after, config) || restarts.Load() != 1 {
		t.Fatal("apply changed config or failed to restart/preserve selection")
	}
	if _, e = m.Rollback(job.BackupID); e != nil {
		t.Fatal(e)
	}
	rollback := waitJob(t, m)
	got, _ = os.ReadFile(target)
	if rollback.Error != "" || !bytes.Equal(got, old) {
		t.Fatalf("rollback failed: %+v", rollback)
	}
}

func TestComponentsRejectChecksumBeforeMutation(t *testing.T) {
	m, rt := testManager(t)
	body := []byte("wrong-body")
	geoServer(t, m, body, digestOf([]byte("other-body")))
	_ = m.SetGeodata(GeoSettings{Sources: []string{"geosite-v2fly"}, Day: -1})
	target := filepath.Join(filepath.Dir(rt.XrayConfDir), "dat", "geosite_v2fly.dat")
	writeTest(t, target, []byte("old"))
	plan, e := m.Preview(context.Background(), PlanRequest{Component: "geodata"})
	if e != nil {
		t.Fatal(e)
	}
	_, _ = m.Apply(plan.ID)
	job := waitJob(t, m)
	got, _ := os.ReadFile(target)
	if job.Error == "" || string(got) != "old" || job.BackupID != "" {
		t.Fatal("checksum failure mutated live data")
	}
}

func TestComponentsFailedValidationRestoresDataAndSelection(t *testing.T) {
	m, rt := testManager(t)
	body := []byte("rejected-geodata")
	geoServer(t, m, body, digestOf(body))
	_ = m.SetGeodata(GeoSettings{Sources: []string{"geosite-v2fly"}, Day: -1})
	target := filepath.Join(filepath.Dir(rt.XrayConfDir), "dat", "geosite_v2fly.dat")
	writeTest(t, target, []byte("old"))
	m.opts.Validate = func(context.Context, string) error {
		got, _ := os.ReadFile(target)
		if bytes.Equal(got, body) {
			return fmt.Errorf("private config must not leak")
		}
		return nil
	}
	var restarts atomic.Int32
	m.opts.Restart = func(context.Context) error { restarts.Add(1); return nil }
	plan, e := m.Preview(context.Background(), PlanRequest{Component: "geodata"})
	if e != nil {
		t.Fatal(e)
	}
	_, _ = m.Apply(plan.ID)
	job := waitJob(t, m)
	got, _ := os.ReadFile(target)
	if job.Error == "" || !job.RolledBack || string(got) != "old" || restarts.Load() != 1 || strings.Contains(job.Error, "private") {
		t.Fatalf("rollback did not restore usable prior state: %+v", job)
	}
}

func TestComponentsHTTPSFailureRestoresPreviousPayloadAndSelection(t *testing.T) {
	m, rt := testManager(t)
	body := []byte("new-geodata")
	geoServer(t, m, body, digestOf(body))
	_ = m.SetGeodata(GeoSettings{Sources: []string{"geosite-v2fly"}, Day: -1})
	target := filepath.Join(filepath.Dir(rt.XrayConfDir), "dat", "geosite_v2fly.dat")
	writeTest(t, target, []byte("working-geodata"))
	beforeConfig, _ := os.ReadFile(rt.RoutingFile)
	var restarts atomic.Int32
	m.opts.Restart = func(context.Context) error {
		got, _ := os.ReadFile(target)
		if restarts.Add(1) == 1 {
			if !bytes.Equal(got, body) {
				t.Error("HTTPS acceptance did not run against the newly installed payload")
			}
			return fmt.Errorf("HTTPS failed: PRIVATE_ENDPOINT_MARKER")
		}
		if string(got) != "working-geodata" {
			t.Error("recovery restarted before restoring the prior payload")
		}
		return nil
	}
	plan, e := m.Preview(context.Background(), PlanRequest{Component: "geodata"})
	if e != nil {
		t.Fatal(e)
	}
	_, _ = m.Apply(plan.ID)
	job := waitJob(t, m)
	got, _ := os.ReadFile(target)
	afterConfig, _ := os.ReadFile(rt.RoutingFile)
	if job.Error == "" || !job.RolledBack || restarts.Load() != 2 || string(got) != "working-geodata" || !bytes.Equal(beforeConfig, afterConfig) || strings.Contains(job.Error, "PRIVATE_ENDPOINT_MARKER") {
		t.Fatalf("failed HTTPS did not restore prior payload and runtime selection: %+v", job)
	}
}

func TestComponentsRejectStalePreviewAndInsufficientSpace(t *testing.T) {
	m, rt := testManager(t)
	body := []byte("synthetic-geodata")
	counter := geoServer(t, m, body, digestOf(body))
	_ = m.SetGeodata(GeoSettings{Sources: []string{"geosite-v2fly"}, Day: -1})
	plan, e := m.Preview(context.Background(), PlanRequest{Component: "geodata"})
	if e != nil {
		t.Fatal(e)
	}
	writeTest(t, rt.RoutingFile, []byte(`{"routing":{"rules":[]}}`))
	_, _ = m.Apply(plan.ID)
	job := waitJob(t, m)
	if job.Error == "" || counter.Load() != 0 {
		t.Fatal("stale preview downloaded/applied")
	}
	m.opts.FreeBytes = func(string) (uint64, error) { return 1, nil }
	if _, e = m.Preview(context.Background(), PlanRequest{Component: "geodata"}); e == nil {
		t.Fatal("ignored insufficient storage")
	}
}

func TestComponentsRollbackRejectsNewerConfigAndTamperedPaths(t *testing.T) {
	m, rt := testManager(t)
	backup, e := m.captureBackup("geodata", "test")
	if e != nil {
		t.Fatal(e)
	}
	if e = m.markBackupCurrent(backup.ID); e != nil {
		t.Fatal(e)
	}
	writeTest(t, rt.RoutingFile, []byte("new user settings"))
	if _, e = m.Rollback(backup.ID); e == nil {
		t.Fatal("rollback accepted changed config")
	}
	path := filepath.Join(m.backupRoot(), backup.ID, "manifest.json")
	raw, _ := os.ReadFile(path)
	var doc backupDocument
	_ = json.Unmarshal(raw, &doc)
	doc.Entries[0].Path = filepath.Join(t.TempDir(), "not-owned")
	raw, _ = json.Marshal(doc)
	writeTest(t, path, raw)
	if _, e = m.readBackup(backup.ID); e == nil {
		t.Fatal("accepted arbitrary path in backup manifest")
	}
}

func TestComponentsSettingsDiscoveryAndIPv6Restoration(t *testing.T) {
	m, rt := testManager(t)
	settings := m.Settings()
	if len(settings) < 6 {
		t.Fatal("missing settings")
	}
	s, ok := m.setting("dns")
	if !ok || !s.Supported || s.Enabled {
		t.Fatal("DNS setting misdetected")
	}
	s, ok = m.setting("autostart")
	if !ok || !s.Supported || !s.Enabled {
		t.Fatal("autostart misdetected")
	}
	path := m.path("/proc/sys/net/ipv6/conf/all/disable_ipv6")
	writeTest(t, path, []byte("0\n"))
	backup, e := m.captureBackup("settings", "ipv6")
	if e != nil {
		t.Fatal(e)
	}
	writeTest(t, path, []byte("1\n"))
	writeTest(t, rt.InitScript, []byte("changed"))
	if e = m.restoreBackup(backup); e != nil {
		t.Fatal(e)
	}
	got, _ := os.ReadFile(path)
	if strings.TrimSpace(string(got)) != "0" {
		t.Fatal("live IPv6 was not restored")
	}
	if e = m.restoreKernelIPv6(map[string]string{filepath.Join(t.TempDir(), "outside"): "1"}); e == nil {
		t.Fatal("accepted unsafe sysctl path")
	}
}

func TestComponentsArchiveRejectsTraversalAndLinks(t *testing.T) {
	m, _ := testManager(t)
	work := t.TempDir()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	f, _ := z.Create("../xray")
	_, _ = f.Write([]byte("bad"))
	_ = z.Close()
	writeTest(t, filepath.Join(work, "0"), b.Bytes())
	if e := m.preparePayload(context.Background(), Plan{Component: "xray"}, work); e == nil {
		t.Fatal("accepted ZIP traversal")
	}
	b.Reset()
	gz := gzip.NewWriter(&b)
	tarball := tar.NewWriter(gz)
	_ = tarball.WriteHeader(&tar.Header{Name: "_xkeen/evil", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0777})
	_ = tarball.Close()
	_ = gz.Close()
	writeTest(t, filepath.Join(work, "0"), b.Bytes())
	if e := m.preparePayload(context.Background(), Plan{Component: "xkeen"}, work); e == nil {
		t.Fatal("accepted TAR symlink")
	}
}

func TestComponentsVersionCompatibility(t *testing.T) {
	if !supportedXkeenTag("2.1") || !supportedXkeenTag("v2.1-beta") || supportedXkeenTag("2.2") || supportedXkeenTag("1.1.3") || xkeenHasTokenSupport("2.0") || !xkeenHasTokenSupport("2.1") {
		t.Fatal("incorrect adapter/token compatibility")
	}
	if !firmwareNeedsToken("5.2") || firmwareNeedsToken("5.1.4") {
		t.Fatal("incorrect firmware compatibility")
	}
}

func TestComponentsUnknownFirmwareRejectsTokenlessXKeen(t *testing.T) {
	m, _ := testManager(t)
	m.opts.Firmware = func() string { return "" }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(githubRelease{Version: "2.0", Assets: []Asset{}})
	}))
	defer server.Close()
	m.apiBase = server.URL
	if _, e := m.Preview(context.Background(), PlanRequest{Component: "xkeen", Version: "2.0"}); e == nil || !strings.Contains(e.Error(), "KeeneticOS") {
		t.Fatalf("unknown firmware allowed downgrade: %v", e)
	}
}

func TestComponentsXkeenPoststageCannotEnableUnrequestedGeoIPSET(t *testing.T) {
	m, _ := testManager(t)
	backup, e := m.captureBackup("xkeen", "2.1")
	if e != nil {
		t.Fatal(e)
	}
	ipset := filepath.Join(filepath.Dir(m.runtime().XkeenJSON), "ipset")
	if e = os.MkdirAll(ipset, 0700); e != nil {
		t.Fatal(e)
	}
	if e = m.verifyXkeenPreserved(backup); e != nil {
		t.Fatalf("empty guard directory was rejected: %v", e)
	}
	writeTest(t, filepath.Join(ipset, "ru_exclude_ipv4.lst"), []byte("192.0.2.0/24\n"))
	if e = m.verifyXkeenPreserved(backup); e == nil {
		t.Fatal("unrequested RU bypass list was accepted")
	}
}

func TestComponentsInterruptedOperationRecoversOnRestart(t *testing.T) {
	m, rt := testManager(t)
	old, _ := os.ReadFile(rt.RoutingFile)
	backup, e := m.captureBackup("geodata", "before")
	if e != nil {
		t.Fatal(e)
	}
	job := Job{ID: randomID(), Component: "geodata", Version: "fixture", Phase: "apply", Started: time.Now()}
	if e = m.writePending(pendingOperation{BackupID: backup.ID, Job: job, WasRunning: true}); e != nil {
		t.Fatal(e)
	}
	writeTest(t, rt.RoutingFile, []byte("interrupted-change"))
	restarted := New(m.opts)
	if restarted.State().Job == nil {
		t.Fatal("lost interrupted job marker")
	}
	restarted.Recover(context.Background())
	done := restarted.State().Job
	got, _ := os.ReadFile(rt.RoutingFile)
	if done == nil || !done.RolledBack || !bytes.Equal(got, old) {
		t.Fatalf("recovery failed: %+v", done)
	}
	if _, e = os.Stat(m.pendingPath()); !os.IsNotExist(e) {
		t.Fatal("recovery marker not cleared")
	}
}

func TestComponentsCoreStoppedStaysStoppedAndPanicRestores(t *testing.T) {
	m, rt := testManager(t)
	body := []byte("synthetic-geo-new")
	geoServer(t, m, body, digestOf(body))
	_ = m.SetGeodata(GeoSettings{Sources: []string{"geosite-v2fly"}, Day: -1})
	target := filepath.Join(filepath.Dir(rt.XrayConfDir), "dat", "geosite_v2fly.dat")
	writeTest(t, target, []byte("old"))
	m.opts.Running = func() bool { return false }
	var restarts atomic.Int32
	m.opts.Restart = func(context.Context) error { restarts.Add(1); return nil }
	plan, e := m.Preview(context.Background(), PlanRequest{Component: "geodata"})
	if e != nil {
		t.Fatal(e)
	}
	_, _ = m.Apply(plan.ID)
	done := waitJob(t, m)
	if done.Error != "" || restarts.Load() != 0 {
		t.Fatal("stopped core was started")
	}
	m.opts.Validate = func(context.Context, string) error { panic("fixture panic") }
	plan, e = m.Preview(context.Background(), PlanRequest{Component: "geodata"})
	if e != nil {
		t.Fatal(e)
	}
	_, _ = m.Apply(plan.ID)
	done = waitJob(t, m)
	got, _ := os.ReadFile(target)
	if !done.RolledBack || !bytes.Equal(got, body) {
		t.Fatalf("panic rollback failed: %+v", done)
	}
}
