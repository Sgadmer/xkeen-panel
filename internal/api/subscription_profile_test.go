package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/monitor"
	"xkeen-panel/internal/xkeen"
)

func TestSubscriptionNewSourceFailureRestoresPreviousManualChoice(t *testing.T) {
	h, previous, fresh := transactionHandlers(t)
	old := xkeen.PoolState{Enabled: true, PinnedTag: "manual", PinnedNode: xkeen.NodeKeyOfServer(previous.Servers[0]), PinManual: true, PinCountry: "NL", PinNote: "Owner selection"}
	if err := h.pool.Set(old); err != nil {
		t.Fatal(err)
	}
	files, _ := originalTransactionFiles(t, h)
	h.config.ProbeAddr = "invalid-address"
	restarted := false
	h.restartCore = func(string) (string, error) { restarted = true; return "", nil }
	response, err := runPreparedTransaction(h, fresh)
	if err == nil || response != nil || restarted {
		t.Fatal("failed new-source preparation reached runtime or committed")
	}
	if strings.Contains(err.Error(), "выбранный вручную сервер исчез") {
		t.Fatal("new provider URL was rejected only because the old provider pin disappeared")
	}
	if h.pool.Get() != old || !reflect.DeepEqual(h.subscription.GetData(), previous) {
		t.Fatal("failed new provider import cleared the previous manual preference")
	}
	for path, want := range files {
		got, readErr := os.ReadFile(path)
		if readErr != nil || string(got) != string(want) {
			t.Fatal("new-source rollback changed managed files")
		}
	}
}

func TestSubscriptionNewSourceSuccessReplacesMissingOldManualNode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake core/dispatcher are POSIX shell executables; run on native Linux")
	}
	h, previous, fresh := transactionHandlers(t)
	root := filepath.Dir(h.config.DataDir)
	calls := filepath.Join(root, "fake-core-calls.log")
	write := func(relative, body string) {
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write("opt/etc/init.d/S05xkeen", "#!/bin/sh\nname_client=\"xray\"\n")
	write("opt/sbin/xkeen", "#!/bin/sh\necho \"$@\" >> '"+calls+"'\nexit 0\n")
	write("opt/sbin/xray", "#!/bin/sh\necho \"$@\" >> '"+calls+"'\nif [ \"$1\" = api ] && [ \"$2\" = bi ]; then printf 'Selecting Override:\\n 1 sub-1\\nSelects:\\n 1 sub-1\\n'; fi\nexit 0\n")
	detector := xkeen.NewDetector(root, "", "", h.config.XrayConfigDir, h.config.RoutingFile, "", "")
	watchdog := monitor.NewWatchdog(h.config, h.subscription, detector)
	watchdog.SetPoolStore(h.pool)
	h = NewHandlers(h.config, h.subscription, watchdog, detector, h.pool, nil)
	state, err := xkeen.EnablePool(detector.Runtime(), h.config.OutboundsFile, previous.Servers, xkeen.PoolOptions{APIAddr: h.config.XrayAPIAddr})
	if err != nil {
		t.Fatal(err)
	}
	state.PinnedTag = "sub-1"
	state.PinnedNode = xkeen.NodeKeyOfServer(previous.Servers[0])
	state.PinManual = true
	state.PinCountry = "NL"
	state.PinNote = "Previous provider choice"
	if err := h.pool.Set(state); err != nil {
		t.Fatal(err)
	}
	detector.InvalidateTopology()
	h.restartCore = func(string) (string, error) { return "synthetic restart", nil }
	response, err := runPreparedTransaction(h, fresh)
	if err != nil || response == nil {
		t.Fatalf("valid new provider was rejected because old manual server disappeared: %v", err)
	}
	got := h.pool.Get()
	if got.PinManual || got.PinnedNode != xkeen.NodeKeyOfServer(fresh[0]) || got.PinnedTag != "sub-1" || got.PinCountry != "" {
		t.Fatal("new provider did not clear old manual intent and select its valid node")
	}
	if got.PinNote != "" {
		t.Fatal("new provider kept a stale pin explanation from the previous subscription")
	}
	if h.subscription.GetData().URL != "https://new.example/sub" {
		t.Fatal("successful new provider URL was not committed")
	}
	active := h.subscription.GetActiveServer()
	if active == nil || active.RawURI != fresh[0].RawURI {
		t.Fatal("active subscription entry still belongs to old provider")
	}
	log, err := os.ReadFile(calls)
	if err != nil || !strings.Contains(string(log), "api bo -s 127.0.0.1:10085 -b balancer sub-1") {
		t.Fatal("new provider was not applied through the fake core override API")
	}
}

func TestPublicServersHideWholeProviderProfiles(t *testing.T) {
	private := models.Server{Name: "Public name", RawURI: "https://private.invalid/SECRET_TOKEN", RawOutbound: json.RawMessage(`{"password":"SECRET_OUTBOUND"}`), RawProfile: json.RawMessage(`{"outbounds":[{"password":"SECRET_PROFILE"}]}`)}
	data, err := json.Marshal(publicServers([]models.Server{private}))
	if err != nil || strings.Contains(string(data), "SECRET_") || strings.Contains(string(data), "raw_uri") || strings.Contains(string(data), "raw_outbound") || strings.Contains(string(data), "raw_profile") {
		t.Fatal("public server response exposed provider credentials or profiles")
	}
	if !strings.Contains(string(data), "Public name") {
		t.Fatal("public server display fields were removed")
	}
}
