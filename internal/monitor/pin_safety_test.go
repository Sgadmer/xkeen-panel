package monitor

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestInactiveWatchdogPreservesManualIntent(t *testing.T) {
	initial := xkeen.PoolState{Enabled: true, PinnedTag: "manual", PinnedNode: "removed-node", PinManual: true, PinCountry: "FI"}
	w, store := pooledWatchdog(t, initial)
	w.superviseP(xkeen.Runtime{}, poolTopology)
	w.rotateExit(xkeen.Runtime{}, poolTopology)
	if got := store.Get(); got != initial {
		t.Fatalf("inactive watchdog changed the owner's choice: %+v", got)
	}
}

func TestInactiveWatchdogDoesNotCreateAutomaticPin(t *testing.T) {
	initial := xkeen.PoolState{Enabled: true}
	w, store := pooledWatchdog(t, initial)
	w.superviseP(xkeen.Runtime{}, poolTopology)
	if got := store.Get(); got != initial {
		t.Fatalf("inactive watchdog created an automatic choice: %+v", got)
	}
}

func TestReapplyDoesNotReplaceUnknownManualPreference(t *testing.T) {
	w, store, _ := routerWatchdog(t, []models.Server{{Name: "NL", Protocol: "vless", RawURI: nlURI}})
	initial := xkeen.PoolState{Enabled: true, PinManual: true, PinnedTag: "manual", PinnedNode: "unknown-manual-node", PinCountry: "FI"}
	if err := store.Set(initial); err != nil {
		t.Fatal(err)
	}
	if err := w.ReapplySelection(); err == nil {
		t.Fatal("unknown manual preference was replaced automatically")
	}
	if store.Get() != initial {
		t.Fatal("failed restoration changed manual preference")
	}
}

func TestPinServerRejectsRemovedCatalogEntryBeforeMutation(t *testing.T) {
	nl := models.Server{Name: "NL", Protocol: "vless", RawURI: nlURI}
	w, store, _ := routerWatchdog(t, []models.Server{nl})
	initial := xkeen.PoolState{Enabled: true, PinnedTag: "sub-1", PinnedNode: xkeen.NodeKeyOfServer(nl), PinManual: true}
	if err := store.Set(initial); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(w.config.OutboundsFile)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.PinServer(models.Server{Name: "FI", Protocol: "vless", RawURI: fiURI}, true, "")
	if err == nil {
		t.Fatal("stale catalog entry was accepted")
	}
	after, _ := os.ReadFile(w.config.OutboundsFile)
	if string(before) != string(after) || store.Get() != initial {
		t.Fatal("rejected stale selection changed configuration or saved pin")
	}
}

func TestPinServerFailedOverrideKeepsPreviousSavedChoice(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake Xray is a POSIX shell executable")
	}
	nl := models.Server{Name: "NL", Protocol: "vless", RawURI: nlURI}
	fi := models.Server{Name: "FI", Protocol: "vless", RawURI: fiURI, Country: "FI"}
	w, store, calls := routerWatchdog(t, []models.Server{nl, fi})
	initial := xkeen.PoolState{Enabled: true, PinnedTag: "sub-1", PinnedNode: xkeen.NodeKeyOfServer(nl), PinManual: true}
	if err := store.Set(initial); err != nil {
		t.Fatal(err)
	}
	config, err := xkeen.ReadOutboundsConfig(w.config.OutboundsFile)
	if err != nil {
		t.Fatal(err)
	}
	second, err := xkeen.BuildServerOutbound(fi, "sub-2", nil)
	if err != nil {
		t.Fatal(err)
	}
	config["outbounds"] = append(config["outbounds"].([]interface{}), second)
	if err := xkeen.WriteOutboundsConfig(w.config.OutboundsFile, config); err != nil {
		t.Fatal(err)
	}
	w.detector.InvalidateTopology()
	body := "#!/bin/sh\necho \"$@\" >> " + calls + "\nif [ \"$2\" = bi ]; then printf 'Selecting Override:\\n 1 sub-1\\nSelects:\\n 1 sub-1\\n'; exit 0; fi\nif [ \"$2\" = bo ]; then exit 1; fi\n"
	if err := os.WriteFile(w.detector.Runtime().CoreBin, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := w.PinServer(fi, true, ""); err == nil {
		t.Fatal("failed override reported success")
	}
	if store.Get() != initial {
		t.Fatal("failed override replaced the saved choice")
	}
	if got := w.subscription.GetActiveServer(); got == nil || got.RawURI != nlURI {
		t.Fatal("failed override changed the active subscription entry")
	}
	if !strings.Contains(readCalls(t, calls), "api bo -s 127.0.0.1:10085 -b balancer sub-2") {
		t.Fatal("test did not reach the failing override")
	}
}

func TestSelectBestUsesHTTPSAndAcceptsHysteria(t *testing.T) {
	outbound := map[string]interface{}{"protocol": "hysteria", "settings": map[string]interface{}{"version": 2, "address": "hy.example", "port": 443}, "streamSettings": map[string]interface{}{"network": "hysteria", "security": "tls", "hysteriaSettings": map[string]interface{}{"version": 2, "auth": "test-only"}}}
	raw, _ := json.Marshal(outbound)
	hy := models.Server{ID: 1, Name: "FI HY2", Country: "FI", Protocol: "hysteria2", RawURI: "xray-json://test-hy", RawOutbound: raw, Latency: -1}
	w, _, _ := routerWatchdog(t, []models.Server{{ID: 0, Name: "NL", Country: "NL", Protocol: "vless", RawURI: nlURI}, hy})
	called := false
	w.probeServers = func(_ xkeen.Runtime, candidates []models.Server, options xkeen.ProbeOptions) ([]models.Server, error) {
		called = true
		if len(candidates) != 1 || candidates[0].Protocol != "hysteria2" {
			t.Fatal("HY2 was filtered before its HTTPS probe")
		}
		candidates[0].Latency = 35
		candidates[0].ProbeKind = "https"
		candidates[0].LastChecked = time.Now()
		return candidates, nil
	}
	best, err := w.selectBest()
	if err != nil || !called || best.Protocol != "hysteria2" {
		t.Fatalf("best=%+v err=%v", best, err)
	}
}
