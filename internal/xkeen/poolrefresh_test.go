package xkeen

import (
	"os"
	"path/filepath"
	"testing"

	"xkeen-panel/internal/models"
)

func TestRefreshPoolKeepsManualMemberThroughFailedProbe(t *testing.T) {
	rt, path := liveConfDir(t)
	list := poolServers()
	state, err := EnablePool(rt, path, list, PoolOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// The pin means "keep this endpoint"; subscription refresh can reorder IDs
	// and the HTTPS probe can fail even when the owner still wants that node.
	selected := list[1]
	selected.ID = 77
	selected.ProbeKind = "https"
	selected.Latency = -1
	state.PinManual = true
	state.PinnedNode = NodeKeyOfServer(selected)
	layout, err := ReadPoolLayout(path, state.Selector)
	if err != nil {
		t.Fatal(err)
	}
	ep, _ := endpointOfServer(selected)
	state.PinnedTag, _ = layout.tagOf(ep)
	if state.PinnedTag == "" {
		t.Fatal("fixture lacks pinned member")
	}
	sel := PoolSelection{MaxNodes: 1}
	if _, err = RefreshPool(rt, path, "", []models.Server{selected, list[0]}, state, sel); err != nil {
		t.Fatal(err)
	}
	if ok, err := PoolMatchesSubscription(path, []models.Server{selected}, state.Selector); !ok || err != nil {
		t.Fatal("manual member evicted", err)
	}
	state.PinManual = false
	if _, err = RefreshPool(rt, path, "", []models.Server{selected, list[0]}, state, sel); err != nil {
		t.Fatal(err)
	}
	if ok, err := PoolMatchesSubscription(path, []models.Server{list[0]}, state.Selector); !ok || err != nil {
		t.Fatal("automatic pool retained failing node", err)
	}
}

// A rotated server leaves the pool pointing at an endpoint that no longer
// answers, which is exactly how a pool takes the whole VPN down.
func TestRefreshPoolPicksUpRotatedServer(t *testing.T) {
	rt, outboundsPath := liveConfDir(t)

	state, err := EnablePool(rt, outboundsPath, poolServers(), PoolOptions{})
	if err != nil {
		t.Fatalf("EnablePool: %v", err)
	}

	rotated := []models.Server{
		{Name: "NL", Protocol: "vless", RawURI: "vless://99999999-8888-7777-6666-555555555555@new.example:443?type=raw&security=reality&pbk=KEY"},
		{Name: "DE", Protocol: "vless", RawURI: wsURI},
	}

	// No dispatcher in the fixture, so the live path is unavailable and the
	// restart is a no-op — the file content is what matters here
	result, err := RefreshPool(rt, outboundsPath, "", rotated, state, PoolSelection{})
	if err != nil {
		t.Fatalf("RefreshPool: %v", err)
	}
	if !result.Changed {
		t.Fatal("rotation not detected — the pool would keep the dead endpoint")
	}

	matches, err := PoolMatchesSubscription(outboundsPath, rotated, DefaultPoolSelector)
	if err != nil {
		t.Fatalf("PoolMatchesSubscription: %v", err)
	}
	if !matches {
		t.Error("pool still differs from the subscription after a refresh")
	}
}

// Rewriting an unchanged pool would mean a restart for nothing.
func TestRefreshPoolNoopWhenUnchanged(t *testing.T) {
	rt, outboundsPath := liveConfDir(t)

	state, err := EnablePool(rt, outboundsPath, poolServers(), PoolOptions{})
	if err != nil {
		t.Fatalf("EnablePool: %v", err)
	}

	before, _ := os.ReadFile(outboundsPath)

	result, err := RefreshPool(rt, outboundsPath, "", poolServers(), state, PoolSelection{})
	if err != nil {
		t.Fatalf("RefreshPool: %v", err)
	}
	if result.Changed || result.Restarted {
		t.Errorf("result = %+v, want an untouched pool", result)
	}

	after, _ := os.ReadFile(outboundsPath)
	if string(before) != string(after) {
		t.Error("config was rewritten despite no change")
	}
}

func TestRefreshPoolReportsAddedAndRemoved(t *testing.T) {
	rt, outboundsPath := liveConfDir(t)

	state, err := EnablePool(rt, outboundsPath, poolServers(), PoolOptions{})
	if err != nil {
		t.Fatalf("EnablePool: %v", err)
	}

	result, err := RefreshPool(rt, outboundsPath, "", poolServers()[:1], state, PoolSelection{})
	if err != nil {
		t.Fatalf("RefreshPool: %v", err)
	}

	if len(result.Removed) != 1 || result.Removed[0] != "sub-2" {
		t.Errorf("Removed = %v, want [sub-2]", result.Removed)
	}
	if len(result.Added) != 0 {
		t.Errorf("Added = %v, want none", result.Added)
	}
}

// The first api block the panel wrote bound its port through a dokodemo-door
// inbound and a routing rule, and never actually listened — `xray api` failed
// with "failed to dial". Such a file has to be migrated in place.
func TestEnsureAPIConfigMigratesOldBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), apiConfigFile)
	old := `{"api":{"tag":"api","services":["RoutingService"]},
		"inbounds":[{"tag":"api-in","listen":"127.0.0.1","port":10085,"protocol":"dokodemo-door"}],
		"routing":{"rules":[{"inboundTag":["api-in"],"outboundTag":"api"}]}}`
	if err := os.WriteFile(path, []byte(old), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	upgraded, err := ensureAPIConfig(path, "127.0.0.1:10085")
	if err != nil {
		t.Fatalf("ensureAPIConfig: %v", err)
	}
	if !upgraded {
		t.Fatal("migration not reported")
	}

	var cfg map[string]interface{}
	if err := ReadJSONC(path, &cfg); err != nil {
		t.Fatalf("read: %v", err)
	}

	api := cfg["api"].(map[string]interface{})
	if api["listen"] != "127.0.0.1:10085" {
		t.Errorf("listen = %v, want the api address — without it Xray binds nothing", api["listen"])
	}
	if !hasService(api["services"], "HandlerService") {
		t.Errorf("services = %v, want HandlerService for hot pool updates", api["services"])
	}
	// The inbound would otherwise be picked up by XKeen's transparent-port scan
	if _, still := cfg["inbounds"]; still {
		t.Error("obsolete inbound left behind")
	}
	if _, still := cfg["routing"]; still {
		t.Error("obsolete routing rule left behind")
	}

	// Second call must be a no-op
	if again, _ := ensureAPIConfig(path, "127.0.0.1:10085"); again {
		t.Error("already-migrated block reported as changed")
	}
}

func TestEnsureAPIConfigIgnoresForeignBlock(t *testing.T) {
	if upgraded, err := ensureAPIConfig("", "127.0.0.1:10085"); upgraded || err != nil {
		t.Errorf("upgraded=%v err=%v, want a no-op when the panel does not own the file", upgraded, err)
	}
}

func TestEnsureAPIConfigSkipsDisabledPool(t *testing.T) {
	if upgraded, err := EnsureAPIConfig(PoolState{Enabled: false, APIFile: "/nope"}, "127.0.0.1:10085"); upgraded || err != nil {
		t.Errorf("upgraded=%v err=%v, want a no-op without a pool", upgraded, err)
	}
}

func TestNewPoolWritesHandlerService(t *testing.T) {
	rt, outboundsPath := liveConfDir(t)

	state, err := EnablePool(rt, outboundsPath, poolServers(), PoolOptions{APIAddr: "127.0.0.1:10085"})
	if err != nil {
		t.Fatalf("EnablePool: %v", err)
	}

	var cfg map[string]interface{}
	if err := ReadJSONC(state.APIFile, &cfg); err != nil {
		t.Fatalf("read api config: %v", err)
	}

	api := cfg["api"].(map[string]interface{})
	services := api["services"].([]interface{})
	found := map[string]bool{}
	for _, s := range services {
		found[s.(string)] = true
	}
	if !found["RoutingService"] || !found["HandlerService"] {
		t.Errorf("services = %v, want RoutingService and HandlerService", services)
	}
	if api["listen"] != "127.0.0.1:10085" {
		t.Errorf("listen = %v, want Xray to bind the port itself", api["listen"])
	}
	if _, present := cfg["inbounds"]; present {
		t.Error("a listening api block needs no dokodemo-door inbound")
	}
}
