package xkeen

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"xkeen-panel/internal/models"
)

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
