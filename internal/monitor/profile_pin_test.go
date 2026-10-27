package monitor

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestReapplySameProviderProfileDoesNotRestartOrRewrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake Xray/dispatcher are POSIX shell executables; run on native Linux")
	}
	raw := json.RawMessage(`{"remarks":"Synthetic provider","outbounds":[{"protocol":"vless","tag":"a","settings":{"address":"one.invalid","port":443,"id":"11111111-2222-3333-4444-555555555555"}},{"protocol":"vless","tag":"b","settings":{"address":"two.invalid","port":443,"id":"22222222-3333-4444-5555-666666666666"}}],"routing":{"balancers":[{"tag":"auto","selector":["a","b"],"strategy":{"type":"leastPing"}}],"rules":[{"type":"field","network":"tcp,udp","balancerTag":"auto"}]},"observatory":{"subjectSelector":["a","b"],"probeInterval":"5m"}}`)
	profile := models.Server{ID: 1, Name: "Synthetic provider", Protocol: "xray-profile", RawProfile: raw, ProbeKind: "https", Latency: 10}
	profile.RawURI = xkeen.ProfileIdentity(profile)
	w, store, calls := routerWatchdog(t, []models.Server{{ID: 0, Name: "NL", Protocol: "vless", RawURI: nlURI}, profile})
	rt := w.detector.Runtime()
	if err := os.WriteFile(filepath.Join(rt.XrayConfDir, "03_inbounds.json"), []byte(`{"inbounds":[{"tag":"redirect","protocol":"dokodemo-door","port":12345,"settings":{"network":"tcp,udp","followRedirect":true}}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rt.Dispatcher, []byte("#!/bin/sh\necho \"$@\" >> '"+calls+"'\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := xkeen.SetManualOutbound(rt, w.config.OutboundsFile, profile); err != nil {
		t.Fatal(err)
	}
	w.detector.InvalidateTopology()
	if err := store.Set(xkeen.PoolState{Enabled: true, BalancerTag: "balancer", Selector: "sub-", PinnedTag: xkeen.ManualTag, PinnedNode: xkeen.NodeKeyOfServer(profile), PinManual: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.subscription.SetActiveByRawURI(profile.RawURI); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(w.config.OutboundsFile)
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, err := os.ReadFile(xkeen.ProfileStatePath(w.config.OutboundsFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(calls, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := w.ReapplySelection(); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := os.ReadFile(w.config.OutboundsFile)
	stateAfter, _ := os.ReadFile(xkeen.ProfileStatePath(w.config.OutboundsFile))
	if !bytes.Equal(before, after) || !bytes.Equal(stateBefore, stateAfter) {
		t.Fatal("reapplying the identical profile rewrote files/baseline")
	}
	log := readCalls(t, calls)
	if strings.Contains(log, "-restart") || strings.Contains(log, "-configtest") || strings.Contains(log, "api ado") || strings.Contains(log, "api rmo") {
		t.Fatal("same-profile reapply restarted/rebuilt the runtime")
	}
	if strings.Count(log, "api bo -s 127.0.0.1:10085 -b balancer manual") != 3 {
		t.Fatal("test did not reach three stable override reapplications")
	}
}
