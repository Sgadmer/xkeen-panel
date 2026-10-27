package updater

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type lockedTransportSpy struct{ calls atomic.Int32 }

func (spy *lockedTransportSpy) RoundTrip(*http.Request) (*http.Response, error) {
	spy.calls.Add(1)
	return nil, errors.New("unexpected updater network request")
}

type lockedFileSnapshot struct {
	Data string
	Mode fs.FileMode
}

func captureLockedFiles(t *testing.T, root string) map[string]lockedFileSnapshot {
	t.Helper()
	result := map[string]lockedFileSnapshot{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[relative] = lockedFileSnapshot{Data: string(data), Mode: info.Mode()}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestLockedUpdaterBlocksAllActionsWithoutIO(t *testing.T) {
	for _, version := range []string{"dev", "v2.1.0", "v99.0.0"} {
		t.Run(version, func(t *testing.T) {
			root := t.TempDir()
			dataDir := filepath.Join(root, "data")
			bin := filepath.Join(root, "panel")
			if err := os.Mkdir(dataDir, 0700); err != nil {
				t.Fatal(err)
			}
			for path, body := range map[string]string{
				bin: "custom code", bin + ".prev": "previous code", bin + ".new": "existing candidate",
				filepath.Join(dataDir, "update.json"):         `{"auto":true,"locked":false,"previous":"v1.0.0"}`,
				filepath.Join(dataDir, "update-pending.json"): `{"from":"v1.0.0","to":"` + version + `"}`,
				filepath.Join(dataDir, "update-failed.json"):  `{"from":"v1.0.0","to":"` + version + `"}`,
			} {
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := captureLockedFiles(t, root)
			spy := &lockedTransportSpy{}
			var restarts, publishes atomic.Int32
			opts := Options{Locked: true, Current: version, BinPath: bin, DataDir: dataDir, Client: &http.Client{Transport: spy},
				Restart: func() error { restarts.Add(1); return nil }, Publish: func(State) { publishes.Add(1) }}
			u := New(opts)
			opts.Locked = false // Options are copied; mutating the caller cannot unlock.
			u.asset = testAsset // Prove the lock also holds on an otherwise supported platform.
			u.settings = Settings{Auto: true, Previous: "v1.0.0"}
			u.latest = &Release{Tag: "v100.0.0", assetURL: "https://example.invalid/binary", sumsURL: "https://example.invalid/sums"}
			state, err := u.Check(context.Background())
			if !errors.Is(err, ErrLocked) || !state.Locked || state.Supported || state.Auto || state.Available || state.Previous != "" || state.Latest != nil || state.Reason != ErrLocked.Error() {
				t.Fatal("locked state exposed an updater action or wrong error")
			}
			if !state.LastCheck.IsZero() {
				t.Fatal("blocked Check recorded an attempted network check")
			}
			actions := []struct {
				name string
				run  func() error
			}{
				{"apply", u.Apply}, {"rollback", u.Rollback},
				{"enable-auto", func() error { return u.SetAuto(true) }}, {"disable-auto", func() error { return u.SetAuto(false) }},
				{"install", func() error { return u.install(context.Background(), *u.latest) }},
				{"download", func() error { return u.download(context.Background(), u.latest.assetURL, u.newPath(), "sum") }},
				{"smoke-test", func() error { return u.smokeTest(context.Background(), u.binPath, u.current) }},
				{"guard", u.startGuard}, {"rollback-binary", u.rollbackBinary},
			}
			for _, action := range actions {
				if err := action.run(); !errors.Is(err, ErrLocked) {
					t.Fatalf("%s was not blocked by immutable policy", action.name)
				}
			}
			if _, err := u.get(context.Background(), "https://example.invalid/release", ""); !errors.Is(err, ErrLocked) {
				t.Fatal("network gateway bypassed immutable policy")
			}
			if spy.calls.Load() != 0 || restarts.Load() != 0 || publishes.Load() != 0 {
				t.Fatal("blocked actions issued network/restart/publish side effects")
			}
			if !reflect.DeepEqual(before, captureLockedFiles(t, root)) {
				t.Fatal("blocked action changed binary, backup, markers or settings")
			}
		})
	}
}

func TestLockedUpdaterBackgroundAndRecoveryIgnoreEditableSettings(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "panel")
	dataDir := filepath.Join(root, "data")
	if err := os.Mkdir(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("custom code"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin+".prev", []byte("old code"), 0600); err != nil {
		t.Fatal(err)
	}
	spy := &lockedTransportSpy{}
	var restarts, healthy, busy, logs atomic.Int32
	u := New(Options{Locked: true, Current: "v2.1.0", BinPath: bin, DataDir: dataDir, Client: &http.Client{Transport: spy}, AutoHour: 4,
		Restart: func() error { restarts.Add(1); return nil }, Busy: func() bool { busy.Add(1); return false }, Log: func(string, ...interface{}) { logs.Add(1) }})
	if err := writeJSON(u.settingsPath(), map[string]interface{}{"auto": true, "locked": false, "previous": "v1.0.0"}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(u.pendingPath(), pendingMarker{From: "v1.0.0", To: u.current}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(u.failedPath(), pendingMarker{From: "v1.0.0", To: u.current}); err != nil {
		t.Fatal(err)
	}
	before := captureLockedFiles(t, root)
	u.asset = testAsset
	u.settings = Settings{Auto: true, Previous: "v1.0.0"}
	u.latest = &Release{Tag: "v9.0.0", assetURL: "https://example.invalid/binary", sumsURL: "https://example.invalid/sums"}
	u.confirmAfter = 0
	u.Startup(context.Background(), func() bool { healthy.Add(1); return true })
	u.tick(context.Background(), time.Date(2026, 10, 27, 4, 0, 0, 0, time.Local))
	u.runApply(*u.latest)
	if u.shouldAutoApply(time.Date(2026, 10, 27, 4, 0, 0, 0, time.Local)) {
		t.Fatal("editable auto/version metadata unlocked automatic install")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("locked background updater did not return immediately")
	}
	// An accidentally spawned startup-confirmation goroutine would remove the
	// pending marker after confirmAfter=0; give it a bounded chance to run.
	time.Sleep(20 * time.Millisecond)
	if spy.calls.Load() != 0 || restarts.Load() != 0 || healthy.Load() != 0 || busy.Load() != 0 || logs.Load() != 0 {
		t.Fatal("locked startup/background path executed an updater callback")
	}
	if !reflect.DeepEqual(before, captureLockedFiles(t, root)) {
		t.Fatal("locked startup/recovery changed persisted files")
	}
	reloaded := New(Options{Locked: true, Current: "v3.0.0", BinPath: bin, DataDir: dataDir})
	state := reloaded.State()
	if !state.Locked || state.Auto || state.Available || state.Supported || !strings.Contains(state.Reason, "заблокированы") {
		t.Fatal("editing settings or changing release version bypassed the compiled lock")
	}
}
