package cardcontroller

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

// With a real core: a card keeps its server when the provider reissues the
// parameters, and returns to the previous ones when the refresh is rolled back.
func TestMihomoSelectionFollowsReissuedServer(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("MIHOMO_TEST_BINARY is required for a real core test")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controllerAddr := listener.Addr().String()
	listener.Close()
	base := map[string]interface{}{"external-controller": controllerAddr, "secret": "synthetic-controller-secret", "mode": "rule", "profile": map[string]bool{"store-selected": true}, "rules": []string{"MATCH,DIRECT"}}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	proc := exec.CommandContext(ctx, core, "-d", dir, "-f", path)
	if err = proc.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); proc.Wait() }()
	issued := models.Server{Name: "NY", SourceID: "S", RawURI: "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:9989?type=tcp"}
	reissued := issued
	reissued.RawURI = "vless://ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:9990?type=tcp"
	servers := []models.Server{issued}
	c := New(path, dir, xkeen.Runtime{Core: xkeen.CoreMihomo, XrayConfDir: filepath.Join(dir, "configs")}, func() []models.Server { return servers })
	c.validate = func(ctx context.Context, p string) error {
		return exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", p).Run()
	}
	c.prepare = func(xkeen.Runtime, string, models.Server) (xkeen.CardProxy, error) {
		return xkeen.CardProxy{Port: 59999, UUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", ServerName: "test.invalid", Fingerprint: "ac37b1fd7ada133aa3e6881661add159942aea366767920056ad51be65d6c83a"}, nil
	}
	p, err := c.read()
	if err != nil {
		t.Fatal(err)
	}
	for !p.api.ruleMode(ctx) {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(20 * time.Millisecond)
	}
	from, to := xkeen.ServiceTargetID(issued), xkeen.ServiceTargetID(reissued)
	if from == "" || to == "" || from == to {
		t.Fatal("fixture servers have no distinct identities")
	}
	if _, err = c.apply(ctx, "claude", from, nil); err != nil {
		t.Fatal(err)
	}
	claude := func() xkeen.ServiceRouteView {
		t.Helper()
		view, err := c.View(ctx)
		if err != nil || !view.Active {
			t.Fatalf("card routes are not active: %v", err)
		}
		return view.Services[0]
	}
	// The provider reissued the parameters. Without the reported change the
	// card cannot find its server and blocks.
	servers = []models.Server{reissued}
	if err = c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if card := claude(); card.Target != from || !card.Blocked {
		t.Fatalf("a card without its server must block: %+v", card)
	}
	rebound, err := c.ReconcileMoves(ctx, []xkeen.TargetMove{{SourceID: "S", From: from, To: to}})
	if err != nil || rebound != 1 {
		t.Fatalf("selection did not follow the reissued server: %d %v", rebound, err)
	}
	if card := claude(); card.Target != to || card.Blocked {
		t.Fatalf("card lost its server: %+v", card)
	}
	if saved, err := c.read(); err != nil || saved.assigned["claude"] != to {
		t.Fatal("moved selection was not saved")
	}
	// A failed refresh restores the catalogue; the selection returns with it.
	servers = []models.Server{issued}
	rebound, err = c.ReconcileMoves(ctx, []xkeen.TargetMove{{SourceID: "S", From: to, To: from}})
	if err != nil || rebound != 1 {
		t.Fatalf("selection did not return to the restored server: %d %v", rebound, err)
	}
	if card := claude(); card.Target != from || card.Blocked {
		t.Fatalf("card lost its restored server: %+v", card)
	}
	// The replaced worker had no open connection, so nothing waits for it; the
	// worker of the current choice is the one that stays.
	c.mu.Lock()
	waiting, current, pending := len(c.retired), c.liveWorkers[from], len(c.pending)
	c.mu.Unlock()
	if waiting != 0 || !current || pending != 0 {
		t.Fatalf("after a reissue: %d retired workers, current kept=%v, %d pending", waiting, current, pending)
	}
}

func TestRebindTargetsFollowsVanishedAndOwnedSelections(t *testing.T) {
	a, b, c, d := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
	fixture := func() profile {
		return profile{
			doc:      map[string]interface{}{defaultSourceKey: "S", replacementKey: a},
			assigned: map[string]string{"claude": a, "openai": c, "steam": directTarget, defaultID: a},
			pools: []MultiPool{{ID: d, PoolSpec: PoolSpec{Name: "Mine", SourceIDs: []string{}, Countries: []string{},
				Members: []PoolMember{{SourceID: "S", TargetID: a}, {SourceID: "S", TargetID: b}, {SourceID: "T", TargetID: a}}}}},
		}
	}
	moves := []xkeen.TargetMove{{SourceID: "S", From: a, To: b}}

	p := fixture()
	if n := rebindTargets(&p, moves, map[string]bool{b: true, c: true}); n != 3 {
		t.Fatalf("moved %d selections, want the card, the common route and one pool member", n)
	}
	if !reflect.DeepEqual(p.assigned, map[string]string{"claude": b, "openai": c, "steam": directTarget, defaultID: b}) || p.doc[replacementKey] != b {
		t.Fatalf("selections did not follow the reissued server: %v", p.assigned)
	}
	want := []PoolMember{{SourceID: "S", TargetID: b}, {SourceID: "T", TargetID: a}}
	if !reflect.DeepEqual(p.pools[0].Members, want) || p.doc[poolsKey] == nil {
		t.Fatalf("pool members did not follow their own source: %v", p.pools[0].Members)
	}

	// Another subscription still offers exactly the chosen parameters. The
	// card keeps them; selections that name the refreshed source follow it.
	p = fixture()
	rebindTargets(&p, moves, map[string]bool{a: true, b: true, c: true})
	if p.assigned["claude"] != a || p.assigned[defaultID] != b {
		t.Fatalf("shared server handled wrongly: %v", p.assigned)
	}

	// The common route belongs to another source and stays with it.
	p = fixture()
	p.doc[defaultSourceKey] = "T"
	rebindTargets(&p, moves, map[string]bool{b: true, c: true})
	if p.assigned[defaultID] != a || p.doc[replacementKey] != a {
		t.Fatal("common route followed a source it does not use")
	}

	// Two sources reissued the same parameters differently: do not guess.
	p = fixture()
	delete(p.doc, defaultSourceKey)
	conflicting := append([]xkeen.TargetMove{{SourceID: "T", From: a, To: c}}, moves...)
	rebindTargets(&p, conflicting, map[string]bool{b: true, c: true})
	if p.assigned["claude"] != a || p.assigned[defaultID] != a {
		t.Fatalf("ambiguous change was guessed: %v", p.assigned)
	}

	// A move to parameters the catalogue does not hold is ignored.
	p = fixture()
	if n := rebindTargets(&p, moves, map[string]bool{c: true}); n != 0 || p.assigned["claude"] != a {
		t.Fatal("followed a move to a missing server")
	}
}

func TestDetachProviderGroupsBlocksInsteadOfRefusing(t *testing.T) {
	group := func(name, kind string, proxies []interface{}, use ...interface{}) map[string]interface{} {
		g := map[string]interface{}{"name": name, "type": kind, "proxies": proxies}
		if len(use) > 0 {
			g["use"] = use
		}
		return g
	}
	doc := map[string]interface{}{
		"proxy-providers": map[string]interface{}{
			"gone": map[string]interface{}{"type": "http", "url": "https://example.com/sub"},
			"kept": map[string]interface{}{"type": "file", "path": "kept.yaml"},
		},
		"proxy-groups": []interface{}{
			group("Manual", "select", []interface{}{"Auto", "DIRECT"}, "gone"),
			group("OwnerBlock", "select", []interface{}{"DIRECT", "REJECT"}, "gone"),
			group("Chosen", "select", []interface{}{"DIRECT"}, "gone", "kept"),
			group("Auto", "url-test", []interface{}{"DIRECT"}, "gone"),
			group("Mixed", "fallback", []interface{}{"DIRECT"}, "gone", "kept"),
			group("Other", "select", []interface{}{"DIRECT"}),
		},
	}
	live := map[string]selector{
		"Manual":     {Type: "Selector", Now: "node-gone", All: []string{"Auto", "DIRECT", "node-gone"}},
		"OwnerBlock": {Type: "Selector", Now: "node-gone", All: []string{"DIRECT", "REJECT", "node-gone"}},
		"Chosen":     {Type: "Selector", Now: "DIRECT", All: []string{"DIRECT", "node-gone", "node-kept"}},
		"Auto":       {Type: "URLTest", Now: "node-gone", All: []string{"DIRECT", "node-gone"}},
		"Mixed":      {Type: "Fallback", Now: "node-gone", All: []string{"DIRECT", "node-gone", "node-kept"}},
		"Other":      {Type: "Selector", Now: "DIRECT", All: []string{"DIRECT"}},
		"DIRECT":     {Type: "Direct"},
	}
	affected, reselect, err := detachProviderGroups(profile{doc: doc}, []string{"gone"}, map[string]bool{"node-gone": true}, live)
	if err != nil {
		t.Fatalf("removal was refused: %v", err)
	}
	if !reflect.DeepEqual(reselect, []string{"Manual", "OwnerBlock"}) || !reflect.DeepEqual(affected, map[string]bool{"Manual": true, "OwnerBlock": true, "Chosen": true, "Auto": true, "Mixed": true}) {
		t.Fatalf("wrong groups handled: %v %v", affected, reselect)
	}
	groups := map[string]map[string]interface{}{}
	for _, raw := range list(doc["proxy-groups"]) {
		groups[str(object(raw)["name"])] = object(raw)
	}
	check := func(name string, proxies, use []string) {
		t.Helper()
		g := groups[name]
		if !reflect.DeepEqual(namesOf(g["proxies"]), proxies) || !reflect.DeepEqual(namesOf(g["use"]), use) {
			t.Fatalf("%s: proxies %v, providers %v", name, g["proxies"], g["use"])
		}
	}
	// The chosen server is removed: block first, keep the other options. The
	// added REJECT is marked; a REJECT the owner listed keeps its meaning.
	check("Manual", []string{"REJECT", "Auto", "DIRECT"}, nil)
	check("OwnerBlock", []string{"REJECT", "DIRECT"}, nil)
	if groups["Manual"][removedSelectionKey] != true || groups["OwnerBlock"][removedSelectionKey] != nil {
		t.Fatal("added and deliberate REJECT members are not told apart")
	}
	if !reflect.DeepEqual(blockAfterRemoval(groups["Manual"]), []string{"Auto", "DIRECT"}) || !reflect.DeepEqual(blockAfterRemoval(groups["OwnerBlock"]), []string{"REJECT", "DIRECT"}) {
		t.Fatal("wrong members considered a deliberate block")
	}
	// Removing a second subscription from an already marked group keeps one REJECT.
	again := map[string]interface{}{"name": "Manual2", "type": "select", "use": []interface{}{"kept"}, "proxies": groups["Manual"]["proxies"], removedSelectionKey: true}
	if _, _, err := detachProviderGroups(profile{doc: map[string]interface{}{"proxy-providers": map[string]interface{}{}, "proxy-groups": []interface{}{again}}}, []string{"kept"}, map[string]bool{"node-kept": true},
		map[string]selector{"Manual2": {Type: "Selector", Now: "node-kept", All: []string{"REJECT", "Auto", "DIRECT", "node-kept"}}}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(namesOf(again["proxies"]), []string{"REJECT", "Auto", "DIRECT"}) || again[removedSelectionKey] != true {
		t.Fatalf("repeated removal changed the marked group wrongly: %v", again["proxies"])
	}
	// A mark without its REJECT is stale and is dropped.
	stale := map[string]interface{}{"proxies": []interface{}{"Auto"}, removedSelectionKey: true}
	if blockAfterRemoval(stale); stale[removedSelectionKey] != nil {
		t.Fatal("stale mark survived")
	}
	// A deliberate DIRECT and a group that still has servers are left alone.
	check("Chosen", []string{"DIRECT"}, []string{"kept"})
	check("Mixed", []string{"DIRECT"}, []string{"kept"})
	// An automatic group left with only a direct exit must not use it.
	check("Auto", []string{"REJECT"}, nil)
	check("Other", []string{"DIRECT"}, nil)
	for _, name := range []string{"Manual", "Chosen", "Auto", "Mixed"} {
		if groups[name]["empty-fallback"] != "REJECT" {
			t.Fatalf("%s can fall back to a direct exit when empty", name)
		}
	}
	providers := object(doc["proxy-providers"])
	if _, present := providers["gone"]; present || providers["kept"] == nil {
		t.Fatal("wrong provider removed")
	}

	delete(live, "Mixed")
	if _, _, err := detachProviderGroups(profile{doc: doc}, []string{"kept"}, map[string]bool{"node-kept": true}, live); err == nil {
		t.Fatal("changed a group whose live members were not confirmed")
	}
}
