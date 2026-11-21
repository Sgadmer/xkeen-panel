package xkeen

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"xkeen-panel/internal/models"
)

func TestCatalogUsesSavedSourceNamesForServiceRoutes(t *testing.T) {
	sm := NewSubscriptionManager(t.TempDir())
	const sourceName = "🛰️  Мой VPN 🧑‍🚀"
	servers := poolServers()[:2]
	servers[0].SourceID, servers[0].SourceName = "mine", "Мой VPN"
	servers[1].SourceID, servers[1].SourceName = "unlisted", "Старый источник ✨"
	data := models.SubscriptionData{CatalogVersion: 1, Servers: servers, Sources: []models.SubscriptionSource{{ID: "mine", Name: sourceName}}}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sm.filePath(), raw, 0600); err != nil {
		t.Fatal(err)
	}
	rt, _, _, _ := profileApplyBaseline(t)
	check := func(want string) {
		t.Helper()
		view, err := ReadServiceRoutes(rt, sm.GetServers())
		if err != nil || len(view.Targets) != 2 {
			t.Fatalf("read service routes: %v, %d targets", err, len(view.Targets))
		}
		if !reflect.DeepEqual(view.Targets[0].Sources, []string{want}) || !reflect.DeepEqual(view.Targets[1].Sources, []string{"Старый источник ✨"}) {
			t.Fatalf("unexpected service source names: %v, %v", view.Targets[0].Sources, view.Targets[1].Sources)
		}
	}
	if err := sm.Load(); err != nil {
		t.Fatal(err)
	}
	check(sourceName)
	const renamed = "🌏 Новое имя ✨"
	if err := sm.RenameSource("mine", renamed); err != nil {
		t.Fatal(err)
	}
	check(renamed)
	if err := sm.RestoreData(data); err != nil {
		t.Fatal(err)
	}
	check(sourceName)
}

func TestSourcesPreserveOwnershipSelectionAndStableIDs(t *testing.T) {
	ctx := context.Background()
	sm := loadSub(t, []models.Server{{ID: 4, Name: "old A", RawURI: uriA}, {ID: 8, Name: "old B", RawURI: uriB, Active: true, CountryOverride: "FI"}}, 1)
	dir := sm.dataDir
	sources := sm.GetSources()
	if len(sources) != 1 || sources[0].ID != "legacy" || sm.GetActiveServer().ID != 8 {
		t.Fatal("legacy migration lost source or selection")
	}
	add, err := sm.AddSource(ctx, SourceInput{Name: "Другой источник", Kind: "file", Content: body(uriB, uriC)})
	if err != nil {
		t.Fatal(err)
	}
	if len(add) != 2 || add[0].ID <= 8 || add[0].SourceID == "legacy" || sm.GetServers()[2].CountryOverride != "" || len(sm.GetServers()) != 4 {
		t.Fatal("overlapping source took ownership or country settings of first")
	}
	id := add[0].SourceID
	if err := sm.RenameSource(id, "Переименованный"); err != nil {
		t.Fatal(err)
	}
	if sm.GetServers()[2].SourceName != "Переименованный" {
		t.Fatal("server provenance stale after rename")
	}
	if _, err := sm.SetActive(add[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := sm.DeleteSource("legacy"); err != nil {
		t.Fatal(err)
	}
	if s := sm.GetActiveServer(); s == nil || s.ID != add[0].ID || s.SourceID != id {
		t.Fatal("removing first source displaced active overlapping endpoint")
	}
	if _, err := sm.SetActive(8); err == nil {
		t.Fatal("stale removed server ID aliased another endpoint")
	}
	reloaded := NewSubscriptionManager(dir)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	beforeRestart, _ := json.Marshal(sm.GetData())
	afterRestart, _ := json.Marshal(reloaded.GetData())
	if string(beforeRestart) != string(afterRestart) {
		t.Fatal("catalog state changed after restart")
	}
	if err := reloaded.DeleteSource(id); err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Load(); err != nil || reloaded.GetData().CatalogVersion != 1 || len(reloaded.GetSources()) != 0 || len(reloaded.GetServers()) != 0 {
		t.Fatal("empty catalog resurrected deleted sources")
	}
	again, err := reloaded.AddSource(ctx, SourceInput{Name: "Новый", Kind: "server", Content: uriB})
	if err != nil || again[0].ID <= add[1].ID {
		t.Fatal("server ID reused after last source removal")
	}
}

// A provider that reissues keys on every download must not wipe what the
// panel measured: the pools ranked by delay would be rebuilt each time.
func TestReissuedServerKeepsItsMeasuredDelay(t *testing.T) {
	ctx := context.Background()
	const (
		reissued = "vless://99999999-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp&security=reality&sni=example.com&fp=chrome&pbk=KEY&sid=cd&flow=xtls-rprx-vision"
		moved    = "vless://99999999-2222-3333-4444-555555555555@5.6.7.8:443?type=tcp&security=reality&sni=example.com&fp=chrome&pbk=KEY&sid=ef&flow=xtls-rprx-vision"
	)
	srv, change := subServer(t, body(realityURI+"#NY"))
	sm := NewSubscriptionManager(t.TempDir())
	added, err := sm.AddSource(ctx, SourceInput{Name: "Provider", Kind: "subscription", URL: srv.URL + "/token"})
	if err != nil || len(added) != 1 {
		t.Fatalf("first import: %v, %d servers", err, len(added))
	}
	id, checked := added[0].SourceID, time.Now().Add(-time.Minute).Truncate(time.Second)
	measure := func(latency int, problem string) {
		sm.mu.Lock()
		defer sm.mu.Unlock()
		s := &sm.data.Servers[0]
		s.Latency, s.ProbeKind, s.LastChecked, s.CheckError = latency, "https", checked, problem
	}
	refresh := func(uri string) models.Server {
		t.Helper()
		change(body(uri + "#NY"))
		fresh, err := sm.RefreshSource(ctx, id)
		if err != nil || len(fresh) != 1 || fresh[0].ID != added[0].ID {
			t.Fatalf("refresh lost the server: %v %+v", err, fresh)
		}
		return fresh[0]
	}

	measure(42, "")
	if got := refresh(reissued); got.Latency != 42 || got.ProbeKind != "https" || !got.LastChecked.Equal(checked) {
		t.Fatalf("new keys on the same address dropped the measurement: %+v", got)
	}
	// A failure may have been caused by the very keys that were replaced.
	measure(-1, "нет ответа")
	if got := refresh(realityURI); got.ProbeKind != "" || got.CheckError != "" || !got.LastChecked.IsZero() {
		t.Fatalf("a failed check outlived the reissue: %+v", got)
	}
	// Another address is another path: its delay is unknown.
	measure(42, "")
	if got := refresh(moved); got.Latency == 42 || got.ProbeKind != "" || !got.LastChecked.IsZero() {
		t.Fatalf("a measurement followed the server to another address: %+v", got)
	}
}

func TestRefreshKeepsServerWhoseParametersChangedUnderItsName(t *testing.T) {
	ctx := context.Background()
	const (
		first    = realityURI + "#NY"
		reissued = "vless://99999999-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp&security=reality&sni=example.com&fp=chrome&pbk=KEY&sid=cd&flow=xtls-rprx-vision#NY"
		other    = wsURI + "#Berlin"
	)
	srv, change := subServer(t, body(first, other))
	sm := NewSubscriptionManager(t.TempDir())
	added, err := sm.AddSource(ctx, SourceInput{Name: "Provider", Kind: "subscription", URL: srv.URL + "/token"})
	if err != nil || len(added) != 2 || len(sm.TakeTargetMoves()) != 0 {
		t.Fatalf("first import: %v, %d servers", err, len(added))
	}
	id, before := added[0].SourceID, ServiceTargetID(added[0])
	if before == "" || added[0].Name != "NY" {
		t.Fatal("fixture has no named target identity")
	}
	if err := sm.SetCountryOverride(added[0].ID, "US"); err != nil {
		t.Fatal(err)
	}
	change(body(reissued, other))
	fresh, err := sm.RefreshSource(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	after := ServiceTargetID(fresh[0])
	if after == "" || after == before || fresh[0].ID != added[0].ID || fresh[0].CountryOverride != "US" || fresh[1].ID != added[1].ID {
		t.Fatalf("reissued parameters replaced the server instead of updating it: %+v", fresh[0])
	}
	moves := sm.TakeTargetMoves()
	if len(moves) != 1 || moves[0] != (TargetMove{SourceID: id, From: before, To: after}) {
		t.Fatalf("unexpected identity changes: %+v", moves)
	}
	// The journal may name the reissued settings, never their values.
	fields := strings.Join(sm.ChangedFields(), " ")
	if !strings.Contains(fields, "shortId") || strings.Contains(fields, "99999999") || strings.Contains(fields, "sni") || len(sm.ChangedFields()) != 2 {
		t.Fatalf("changed settings reported wrongly: %q", fields)
	}
	if len(sm.TakeTargetMoves()) != 0 {
		t.Fatal("identity changes handed over twice")
	}

	// Two entries share the name now. Neither can claim the previous server.
	twin := strings.Replace(reissued, "99999999", "88888888", 1)
	another := strings.Replace(reissued, "99999999", "77777777", 1)
	change(body(twin, another, other))
	fresh, err = sm.RefreshSource(ctx, id)
	if err != nil || len(fresh) != 3 {
		t.Fatalf("ambiguous refresh: %v, %d servers", err, len(fresh))
	}
	if fresh[0].ID == added[0].ID || fresh[1].ID == added[0].ID || fresh[0].CountryOverride != "" || len(sm.TakeTargetMoves()) != 0 {
		t.Fatal("ambiguous name was treated as the previous server")
	}

	// A different link through the older single-source call is another provider.
	legacy := NewSubscriptionManager(t.TempDir())
	one, _ := subServer(t, body(first))
	two, _ := subServer(t, body(reissued))
	old, err := legacy.UpdateURL(one.URL + "/a")
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := legacy.UpdateURL(two.URL + "/b")
	if err != nil || replaced[0].ID == old[0].ID || len(legacy.TakeTargetMoves()) != 0 {
		t.Fatalf("another provider inherited a server by name: %v", err)
	}
	// An explicit replacement of the link continues the same subscription.
	back, err := legacy.ReplaceSourceURL(ctx, "legacy", one.URL+"/a")
	if err != nil || back[0].ID != replaced[0].ID || len(legacy.TakeTargetMoves()) != 1 {
		t.Fatalf("replacing the link lost the server: %v", err)
	}
	if _, err := legacy.ReplaceSourceURL(ctx, "legacy", one.URL+"/a"); err == nil {
		t.Fatal("accepted the current link as a replacement")
	}
	if _, err := legacy.ReplaceSourceURL(ctx, "missing", two.URL+"/b"); !errors.Is(err, ErrSourceNotFound) {
		t.Fatal("replaced the link of a missing source")
	}
}

func TestRemoteSourcesRefreshIndependentlyAndKeepSecretsPrivate(t *testing.T) {
	ctx := context.Background()
	var failed atomic.Bool
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failed.Load() {
			http.Error(w, "private-upstream", 503)
			return
		}
		_, _ = w.Write([]byte(body(uriA, uriB)))
	}))
	defer first.Close()
	second, change := subServer(t, body(uriB))
	sm := NewSubscriptionManager(t.TempDir())
	url1 := first.URL + "/private-first"
	url2 := second.URL + "/private-second"
	before, err := sm.AddSource(ctx, SourceInput{Name: "First", Kind: "subscription", URL: url1})
	if err != nil {
		t.Fatal(err)
	}
	identity := readTestSubscriptionClient(t, sm).HWID
	later, err := sm.AddSource(ctx, SourceInput{Name: "Second", Kind: "subscription", URL: url2})
	if err != nil || readTestSubscriptionClient(t, sm).HWID != identity {
		t.Fatal("second subscription changed device identity")
	}
	if _, err := sm.AddSource(ctx, SourceInput{Name: "Third", Kind: "subscription", URL: url1}); err == nil {
		t.Fatal("duplicate source URL accepted")
	}
	change(body(uriC, uriB))
	failed.Store(true)
	_, err = sm.Refresh()
	if err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("failed source was hidden or leaked its URL")
	}
	all := sm.GetServers()
	if len(all) != 4 || !reflect.DeepEqual(all[:2], before) || all[3].ID != later[0].ID || all[3].SourceID != later[0].SourceID {
		t.Fatal("one provider failure prevented independent refresh or changed previous IDs")
	}
	list, _ := json.Marshal(sm.GetSources())
	if strings.Contains(string(list), "private") || strings.Contains(string(list), identity) || strings.Contains(string(list), uriA) {
		t.Fatal("source summary leaked private data")
	}
	if _, err := sm.RefreshSource(ctx, "missing"); !errors.Is(err, ErrSourceNotFound) {
		t.Fatal("missing source refreshed a different provider")
	}
}
