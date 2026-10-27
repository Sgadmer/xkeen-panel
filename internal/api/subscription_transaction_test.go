package api

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/monitor"
	"xkeen-panel/internal/xkeen"
)

const transactionOldURI = "vless://11111111-2222-3333-4444-555555555555@old.example:443?type=tcp"
const transactionNewURI = "vless://66666666-7777-8888-9999-000000000000@new.example:443?type=tcp"

func transactionHandlers(t *testing.T) (*Handlers, models.SubscriptionData, []models.Server) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "configs")
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	oldConfig := `// original config
{"outbounds":[{"protocol":"vless","tag":"vless-reality","settings":{"address":"old.example","port":443,"id":"11111111-2222-3333-4444-555555555555"},"streamSettings":{"network":"tcp","sockopt":{"mark":255}}},{"protocol":"freedom","tag":"direct"}]}`
	routing := `// preserve original rules
{"routing":{"rules":[{"type":"field","domain":["domain:ru"],"outboundTag":"direct"},{"type":"field","outboundTag":"vless-reality"}]}}`
	outPath := filepath.Join(dir, "04_outbounds.json")
	routingPath := filepath.Join(dir, "05_routing.json")
	if err := os.WriteFile(outPath, []byte(oldConfig), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(routingPath, []byte(routing), 0600); err != nil {
		t.Fatal(err)
	}
	sub := xkeen.NewSubscriptionManager(dataDir)
	previous := models.SubscriptionData{URL: "https://old.example/sub", Servers: []models.Server{{ID: 0, Name: "NL", Country: "NL", Protocol: "vless", RawURI: transactionOldURI}}, ActiveID: 0}
	if err := sub.RestoreData(previous); err != nil {
		t.Fatal(err)
	}
	previous = sub.GetData()
	pool := xkeen.NewPoolStore(dataDir)
	cfg := &models.Config{DataDir: dataDir, OutboundsFile: outPath, RoutingFile: routingPath, XrayConfigDir: dir, XrayAPIAddr: "127.0.0.1:10085", ProbeAddr: "127.0.0.1:10086", PoolMaxNodes: 32}
	detector := xkeen.NewDetector(root, "", "", dir, routingPath, "", "")
	watchdog := monitor.NewWatchdog(cfg, sub, detector)
	watchdog.SetPoolStore(pool)
	h := NewHandlers(cfg, sub, watchdog, detector, pool, nil)
	fresh := []models.Server{{ID: 0, Name: "FI", Country: "FI", Protocol: "vless", RawURI: transactionNewURI, Latency: 25, ProbeKind: "https", LastChecked: time.Now()}}
	return h, previous, fresh
}

func runPreparedTransaction(h *Handlers, fresh []models.Server) (map[string]interface{}, error) {
	return h.withSubscriptionTransaction(func(snapshot *subscriptionApplySnapshot) (map[string]interface{}, error) {
		if err := h.subscription.RestoreData(models.SubscriptionData{URL: "https://new.example/sub", Servers: fresh, ActiveID: 0}); err != nil {
			return nil, err
		}
		response := map[string]interface{}{}
		if err := h.applySubscription(fresh, response, snapshot); err != nil {
			return nil, err
		}
		return response, nil
	})
}

func assertTransactionRestored(t *testing.T, h *Handlers, previous models.SubscriptionData, files map[string][]byte, modes map[string]os.FileMode) {
	t.Helper()
	if !reflect.DeepEqual(h.subscription.GetData(), previous) {
		t.Fatal("previous subscription was not restored")
	}
	if h.pool.Get() != (xkeen.PoolState{}) {
		t.Fatal("failed import left new pool state")
	}
	if h.watchdog.ProbeAddress() != "" {
		t.Fatal("failed import left a runtime probe for the rejected config")
	}
	for path, want := range files {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != string(want) {
			t.Fatalf("file was not restored: %s", filepath.Base(path))
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != modes[path] {
			t.Fatal("previous permissions were not restored")
		}
	}
	for _, name := range []string{"00_api.json", "00_panel_probe.json"} {
		if _, err := os.Stat(filepath.Join(h.detector.Runtime().XrayConfDir, name)); !os.IsNotExist(err) {
			t.Fatalf("new managed file survived rollback: %s", name)
		}
	}
	for _, path := range []string{h.config.OutboundsFile + ".bak", h.config.RoutingFile + ".bak"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("failed import changed the previous backup state")
		}
	}
	if _, err := os.Stat(filepath.Join(h.config.DataDir, "pool.json")); !os.IsNotExist(err) {
		t.Fatal("new pool state file survived rollback")
	}
}

func originalTransactionFiles(t *testing.T, h *Handlers) (map[string][]byte, map[string]os.FileMode) {
	t.Helper()
	files := map[string][]byte{}
	modes := map[string]os.FileMode{}
	for _, path := range []string{h.config.OutboundsFile, h.config.RoutingFile, filepath.Join(h.config.DataDir, "subscription.json")} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		files[path] = data
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		modes[path] = info.Mode().Perm()
	}
	return files, modes
}

func TestSubscriptionApplyProbeFailureRestoresAllManagedState(t *testing.T) {
	h, previous, fresh := transactionHandlers(t)
	files, modes := originalTransactionFiles(t, h)
	h.config.ProbeAddr = "invalid-address"
	restarted := false
	h.restartCore = func(string) (string, error) { restarted = true; return "", nil }
	response, err := runPreparedTransaction(h, fresh)
	if err == nil || response != nil {
		t.Fatal("failed probe setup reported import success")
	}
	if restarted {
		t.Fatal("invalid probe configuration reached production restart")
	}
	assertTransactionRestored(t, h, previous, files, modes)
}

func TestSubscriptionApplyRestartFailureDoesNotCommit(t *testing.T) {
	h, previous, fresh := transactionHandlers(t)
	files, modes := originalTransactionFiles(t, h)
	calls := 0
	h.restartCore = func(string) (string, error) { calls++; return "", errors.New("simulated restart failure") }
	response, err := runPreparedTransaction(h, fresh)
	if err == nil || response != nil || calls != 1 {
		t.Fatalf("restart failure committed: response=%v error=%v calls=%d", response, err, calls)
	}
	assertTransactionRestored(t, h, previous, files, modes)
}

func TestSubscriptionRollbackPreservesUnrelatedNewJSON(t *testing.T) {
	h, _, _ := transactionHandlers(t)
	unrelated := filepath.Join(h.detector.Runtime().XrayConfDir, "99_unrelated.json")
	_, err := h.withSubscriptionTransaction(func(*subscriptionApplySnapshot) (map[string]interface{}, error) {
		if err := os.WriteFile(unrelated, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		return nil, errors.New("reject import")
	})
	if err == nil {
		t.Fatal("expected rejected transaction")
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("rollback deleted an unrelated file")
	}
}

func TestManualPreferenceRotationRequiresUniqueLogicalServer(t *testing.T) {
	previous := models.Server{ID: 0, Name: "FI-A", Country: "FI", Protocol: "vless", RawURI: transactionOldURI}
	rotated := models.Server{ID: 1, Name: "FI-A", Country: "FI", Protocol: "vless", RawURI: transactionNewURI}
	snapshot := subscriptionApplySnapshot{data: models.SubscriptionData{Servers: []models.Server{previous}}, pool: xkeen.PoolState{PinManual: true, PinnedNode: xkeen.NodeKeyOfServer(previous)}}
	got, err := snapshot.manualPreference([]models.Server{rotated})
	if err != nil || got == nil || got.RawURI != transactionNewURI {
		t.Fatal("unique rotated manual node was not preserved")
	}
	ambiguous := rotated
	ambiguous.RawURI = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@other.example:443?type=tcp"
	if _, err := snapshot.manualPreference([]models.Server{rotated, ambiguous}); err == nil {
		t.Fatal("ambiguous manual replacement was accepted")
	}
	failed := rotated
	failed.ProbeKind = "https"
	failed.Latency = -1
	if _, err := snapshot.manualPreference([]models.Server{failed}); err == nil {
		t.Fatal("failed rotated manual tunnel was accepted")
	}
	rotated.Country = "NL"
	if _, err := snapshot.manualPreference([]models.Server{rotated}); err == nil {
		t.Fatal("manual choice moved to another country")
	}
}
