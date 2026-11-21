package components

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"xkeen-panel/internal/xkeen"
)

type mihomoFixture struct {
	m       *Manager
	rt      xkeen.Runtime
	files   map[string][]byte // served release assets by name
	digests map[string]string // overrides of the published SHA-256
	tag     string
	pre     bool
	accept  error // what the configuration test of a new core answers
	free    uint64
}

func mihomoManager(t *testing.T) *mihomoFixture {
	t.Helper()
	root := t.TempDir()
	path := func(p string) string { return filepath.Join(root, p) }
	f := &mihomoFixture{files: map[string][]byte{}, digests: map[string]string{}, tag: "v1.19.99", free: 1 << 40}
	f.rt = xkeen.Runtime{Installed: true, Generation: 2, Core: xkeen.CoreMihomo, CoreBin: path("opt/sbin/mihomo"), Dispatcher: path("opt/sbin/xkeen"),
		XrayConfDir: path("opt/etc/xray/configs"), MihomoConf: path("opt/etc/mihomo/config.yaml"), XkeenJSON: path("opt/etc/xkeen/xkeen.json")}
	for _, dir := range []string{filepath.Dir(f.rt.CoreBin), path("opt/etc/xray/dat"), filepath.Dir(f.rt.MihomoConf), path("data")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	var address string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if name, ok := strings.CutPrefix(r.URL.Path, "/files/"); ok {
			if body, found := f.files[name]; found {
				_, _ = w.Write(body)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/repos/") {
			release := githubRelease{Version: f.tag, Prerelease: f.pre}
			for name, body := range f.files {
				digest := digestOf(body)
				if forced := f.digests[name]; forced != "" {
					digest = forced
				}
				release.Assets = append(release.Assets, Asset{Name: name, Size: int64(len(body)), Digest: digest, URL: address + "/files/" + name})
			}
			_ = json.NewEncoder(w).Encode(release)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	address = server.URL
	f.m = New(Options{Root: root, DataDir: path("data"), Runtime: func() xkeen.Runtime { return f.rt }, GOOS: "linux", GOARCH: "arm64", TestHTTP: true,
		APIBase: address, Validate: func(context.Context, string) error { return f.accept }, FreeBytes: func(string) (uint64, error) { return f.free, nil }})
	return f
}

func protoVarint(v uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	return buf[:binary.PutUvarint(buf, v)]
}

func protoBytes(field int, payload []byte) []byte {
	return append(append(protoVarint(uint64(field<<3|2)), protoVarint(uint64(len(payload)))...), payload...)
}

// refilterDat builds a GeoSite or GeoIP file with one "refilter" section.
func refilterDat(domains bool, count int) []byte {
	entry := protoBytes(1, []byte("refilter"))
	for i := 0; i < count; i++ {
		var item []byte
		if domains {
			item = append(append(protoVarint(1<<3), 2), protoBytes(2, []byte(fmt.Sprintf("site%d.example.org", i)))...)
		} else {
			item = append(protoBytes(1, []byte{203, 0, byte(i / 256), byte(i % 256)}), append(protoVarint(2<<3), 32)...)
		}
		entry = append(entry, protoBytes(2, item)...)
	}
	return protoBytes(1, entry)
}

func TestRefilterIsDownloadedCheckedAndReplacedAsAPair(t *testing.T) {
	f := mihomoManager(t)
	dat := filepath.Join(filepath.Dir(f.rt.XrayConfDir), "dat")
	site, ip := filepath.Join(dat, "geosite_refilter.dat"), filepath.Join(dat, "geoip_refilter.dat")
	oldSite, oldIP := refilterDat(true, 150), refilterDat(false, 20)
	writeTest(t, site, oldSite)
	writeTest(t, ip, oldIP)
	read := func(path string) []byte {
		t.Helper()
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	intact := func(reason string) {
		t.Helper()
		if !bytes.Equal(read(site), oldSite) || !bytes.Equal(read(ip), oldIP) {
			t.Fatalf("%s: the installed list changed", reason)
		}
		left, _ := filepath.Glob(filepath.Join(dat, ".panel-refilter-*"))
		if len(left) != 0 {
			t.Fatalf("%s: a work folder was left behind", reason)
		}
	}
	ctx := context.Background()

	// A list half the size of the installed one is a broken upload.
	f.files["geosite.dat"], f.files["geoip.dat"] = refilterDat(true, 120), refilterDat(false, 9)
	if _, _, err := f.m.refilterUpdate(ctx); err == nil {
		t.Fatal("a list that lost more than half of its networks was installed")
	}
	intact("short list")
	f.files["geoip.dat"] = []byte("not a geodata file")
	if _, _, err := f.m.refilterUpdate(ctx); err == nil {
		t.Fatal("an unreadable file was installed")
	}
	intact("unreadable file")
	// The published checksum decides: a file that does not match is not even looked at.
	f.files["geoip.dat"] = refilterDat(false, 30)
	f.digests["geoip.dat"] = "sha256:" + strings.Repeat("0", 64)
	if _, _, err := f.m.refilterUpdate(ctx); err == nil {
		t.Fatal("a file with a wrong checksum was installed")
	}
	intact("wrong checksum")
	delete(f.digests, "geoip.dat")

	f.tag = "25.11.2026"
	version, changed, err := f.m.refilterUpdate(ctx)
	if err != nil || !changed || version != "25.11.2026" {
		t.Fatalf("a good list was not installed: %q %v %v", version, changed, err)
	}
	if !bytes.Equal(read(site), f.files["geosite.dat"]) || !bytes.Equal(read(ip), f.files["geoip.dat"]) {
		t.Fatal("the files are not the downloaded ones")
	}
	if !bytes.Equal(read(site+mihomoPrevSuffix), oldSite) || !bytes.Equal(read(ip+mihomoPrevSuffix), oldIP) {
		t.Fatal("the previous list was not kept")
	}
	// The same release again changes nothing.
	if _, changed, err = f.m.refilterUpdate(ctx); err != nil || changed {
		t.Fatalf("an identical list was installed again: %v %v", changed, err)
	}
}

func TestRefilterRefreshIsDailyAndTheOwnersChoice(t *testing.T) {
	f := mihomoManager(t)
	info := f.m.RefilterInfo()
	if !info.Supported || !info.Auto || info.FilesChangedAt != "" {
		t.Fatalf("a new installation: %+v", info)
	}
	dat := filepath.Join(filepath.Dir(f.rt.XrayConfDir), "dat")
	writeTest(t, filepath.Join(dat, "geosite_refilter.dat"), refilterDat(true, 150))
	writeTest(t, filepath.Join(dat, "geoip_refilter.dat"), refilterDat(false, 20))
	old := time.Now().Add(-9 * 24 * time.Hour)
	if err := os.Chtimes(filepath.Join(dat, "geoip_refilter.dat"), old, old); err != nil {
		t.Fatal(err)
	}
	// The older file tells how fresh the pair is.
	changed, err := time.Parse(time.RFC3339, f.m.RefilterInfo().FilesChangedAt)
	if err != nil || changed.Sub(old).Abs() > 2*time.Second {
		t.Fatalf("age of the files: %v %v", changed, err)
	}
	due := func(now time.Time) bool {
		f.m.mu.Lock()
		defer f.m.mu.Unlock()
		tasks := f.m.mihomoLoad()
		auto := tasks.saved.RefilterAuto == nil || *tasks.saved.RefilterAuto
		checked, _ := time.Parse(time.RFC3339, tasks.saved.RefilterChecked)
		wait := refilterInterval
		if tasks.saved.RefilterError != "" {
			wait = refilterRetry
		}
		return auto && !tasks.refilterBusy && now.Sub(checked) >= wait
	}
	now := time.Now()
	if !due(now) {
		t.Fatal("a list that was never checked is not due")
	}
	f.m.mu.Lock()
	f.m.mihomoLoad().saved.RefilterChecked = stamp(now)
	f.m.mu.Unlock()
	if due(now.Add(23*time.Hour)) || !due(now.Add(25*time.Hour)) {
		t.Fatal("the list is checked once a day")
	}
	f.m.mu.Lock()
	f.m.mihomoLoad().saved.RefilterError = "источник недоступен"
	f.m.mu.Unlock()
	if due(now.Add(5*time.Hour)) || !due(now.Add(7*time.Hour)) {
		t.Fatal("a failed check is repeated after six hours")
	}
	if info = f.m.SetRefilterAuto(false); info.Auto || due(now.Add(48*time.Hour)) {
		t.Fatal("the owner switched the refresh off")
	}
	// The choice survives a restart of the panel.
	again := New(Options{DataDir: f.m.opts.DataDir, Runtime: func() xkeen.Runtime { return f.rt }, GOOS: "linux", GOARCH: "arm64", TestHTTP: true})
	if again.RefilterInfo().Auto {
		t.Fatal("the saved choice was lost")
	}
	// On a router with Xray the block list belongs to the geodata transactions.
	f.rt.Core = xkeen.CoreXray
	if _, err := f.m.StartRefilterUpdate(); err == nil || f.m.RefilterInfo().Supported {
		t.Fatal("the Mihomo refresh ran on an Xray router")
	}
}

func TestMihomoAssetNames(t *testing.T) {
	for arch, want := range map[string]string{"arm64": "mihomo-linux-arm64-v1.19.3.gz", "mipsle": "mihomo-linux-mipsle-softfloat-v1.19.3.gz", "amd64": ""} {
		if got := mihomoAsset(arch, "v1.19.3"); got != want {
			t.Errorf("%s: %q, want %q", arch, got, want)
		}
	}
}

func gz(t *testing.T, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func fakeCore(version string) []byte {
	return []byte("#!/bin/sh\necho \"Mihomo Meta " + version + " linux arm64 with go1.26 test\"\n")
}

// A new core replaces the file on disk only after it has run and accepted the
// configuration, and the previous one stays for a way back.
func TestMihomoCoreInstallAndRollback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake core is a POSIX script")
	}
	f := mihomoManager(t)
	bin := f.rt.CoreBin
	writeTest(t, bin, fakeCore("v1.19.1"))
	ctx := context.Background()
	version := func(path string) string { return f.m.coreVersion(ctx, path) }
	untouched := func(reason string) {
		t.Helper()
		if version(bin) != "v1.19.1" {
			t.Fatalf("%s: the installed core changed to %q", reason, version(bin))
		}
		if _, err := os.Stat(bin + mihomoPrevSuffix); err == nil {
			t.Fatalf("%s: a previous copy appeared", reason)
		}
		left, _ := filepath.Glob(filepath.Join(filepath.Dir(bin), ".panel-mihomo-*"))
		if len(left) != 0 {
			t.Fatalf("%s: a work folder was left behind", reason)
		}
	}
	asset := mihomoAsset("arm64", "v1.19.99")

	f.files[asset] = gz(t, fakeCore("v1.19.50")) // not the version it claims to be
	if _, err := f.m.coreInstall(ctx, "v1.19.99"); err == nil {
		t.Fatal("a binary reporting another version was installed")
	}
	untouched("wrong version")
	f.files[asset] = []byte("not an archive")
	if _, err := f.m.coreInstall(ctx, "v1.19.99"); err == nil {
		t.Fatal("a broken archive was installed")
	}
	untouched("broken archive")
	f.files[asset] = gz(t, fakeCore("v1.19.99"))
	f.accept = errors.New("config refused")
	if _, err := f.m.coreInstall(ctx, "v1.19.99"); err == nil {
		t.Fatal("a core that refused the configuration was installed")
	}
	untouched("refused configuration")
	f.accept, f.free = nil, 1<<20
	if _, err := f.m.coreInstall(ctx, "v1.19.99"); err == nil {
		t.Fatal("installed without room for the previous copy")
	}
	untouched("no room")
	f.free, f.pre = 1<<40, true
	if _, err := f.m.coreInstall(ctx, "v1.19.99"); err == nil {
		t.Fatal("a prerelease was installed")
	}
	untouched("prerelease")
	f.pre = false
	if _, err := f.m.StartCoreInstall("v1.19"); err == nil {
		t.Fatal("a malformed version was accepted")
	}

	previous, err := f.m.coreInstall(ctx, "v1.19.99")
	if err != nil || previous != "v1.19.1" || version(bin) != "v1.19.99" || version(bin+mihomoPrevSuffix) != "v1.19.1" {
		t.Fatalf("install: previous %q, now %q, kept %q, %v", previous, version(bin), version(bin+mihomoPrevSuffix), err)
	}
	if _, err = f.m.coreInstall(ctx, "v1.19.99"); err == nil {
		t.Fatal("the installed version was installed again")
	}
	f.m.mu.Lock()
	f.m.mihomoLoad().saved.CorePrevious = previous
	f.m.mihomoSave()
	f.m.mu.Unlock()
	info := f.m.CoreInfo(ctx)
	if !info.Supported || info.Installed != "v1.19.99" || info.Previous != "v1.19.1" || info.Staged {
		t.Fatalf("after the install: %+v", info)
	}
	// The way back is checked the same way before anything moves.
	f.accept = errors.New("config refused")
	if _, err = f.m.CoreRollback(ctx); err == nil || version(bin) != "v1.19.99" {
		t.Fatal("rolled back to a core that refuses the configuration")
	}
	f.accept = nil
	info, err = f.m.CoreRollback(ctx)
	if err != nil || info.Installed != "v1.19.1" || info.Previous != "" || version(bin) != "v1.19.1" {
		t.Fatalf("rollback: %+v %v", info, err)
	}
	if _, err = f.m.CoreRollback(ctx); err == nil {
		t.Fatal("rolled back twice")
	}

	// The latest stable release is what the check reports.
	f.tag = "v1.20.0"
	if info, err = f.m.CoreCheck(ctx); err != nil || info.Latest != "v1.20.0" || info.CheckedAt == "" {
		t.Fatalf("check: %+v %v", info, err)
	}
	f.pre = true
	if _, err = f.m.CoreCheck(ctx); err == nil {
		t.Fatal("a prerelease was offered as the latest version")
	}
}
