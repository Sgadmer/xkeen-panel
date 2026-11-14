package cardcontroller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestServicePoolSamplesOncePerSnapshot(t *testing.T) {
	generation := strings.Repeat("e", 64)
	tag := nodePrefix + allPoolID + "-" + generation
	first, second := poolServer("first", "DE", "10001"), poolServer("second", "SE", "10002")
	first.Name, first.SourceName = "🇷🇺 → 🇩🇪", "First source"
	second.Name = "Stockholm"
	p := profile{doc: map[string]interface{}{"proxies": []interface{}{map[string]interface{}{"name": tag, "type": "vless", "server": "127.0.0.1", "port": 11001}}}}
	live := map[string]selector{
		cardPrefix + "youtube": {Type: "Selector", Now: tag}, cardPrefix + defaultID: {Type: "Selector", Now: tag},
		tag: {Type: "Vless"}, "by-flow": {Type: "LoadBalance", Now: "DIRECT"},
		"cycle":          {Type: "Selector", Now: "cycle"},
		"secret://value": {Type: "HTTP"},
	}
	member := xkeen.ServiceTargetID(first)
	samples := 0
	snapshot := func() *workerSnapshot {
		return newWorkerSnapshot(context.Background(), xkeen.Runtime{}, p, func() []models.Server { return []models.Server{first, second} },
			func(_ context.Context, _ xkeen.Runtime, gen string, port int) string {
				if gen != generation || port != 11001 {
					t.Fatalf("unexpected worker %s:%d", gen, port)
				}
				samples++
				return member
			})
	}
	missing := func(string) selector { return selector{} }
	w := snapshot()
	for _, group := range []string{cardPrefix + "youtube", cardPrefix + defaultID} {
		got := w.current(group, live, missing)
		if got.Pool != "Все локации" || got.Kind != "server" || got.Name != first.Name || got.Country != "DE" || got.Source != first.SourceName {
			t.Fatalf("%s: %+v", group, got)
		}
		if strings.Join(got.DeclaredCountryPath, "/") != "RU/DE" {
			t.Fatalf("lost the selected worker's declared path: %+v", got)
		}
	}
	if samples != 1 {
		t.Fatalf("%d observations shared between two cards", samples)
	}
	member = xkeen.ServiceTargetID(second)
	if got := snapshot().current(cardPrefix+"youtube", live, missing); got.Name != second.Name || got.Country != "SE" {
		t.Fatalf("old selection reused: %+v", got)
	}
	member = ""
	if got := snapshot().current(cardPrefix+"youtube", live, missing); got.Pool == "" || got.Kind != "unknown" || got.Name != "" || got.Country != "" {
		t.Fatalf("fabricated observation: %+v", got)
	}
	for _, group := range []string{"by-flow", "cycle", "secret://value"} {
		if got := w.current(group, live, missing); got.Kind != "unknown" || got.Name != "" {
			t.Fatalf("%s: %+v", group, got)
		}
	}
}

func TestServicePoolCountryComesFromBuiltinIdentity(t *testing.T) {
	customID := strings.Repeat("c", 64)
	p := profile{pools: []MultiPool{{ID: customID, PoolSpec: PoolSpec{Name: "NL"}}}}
	w := newWorkerSnapshot(context.Background(), xkeen.Runtime{}, p, nil, nil)
	for _, tt := range []struct{ id, country string }{{customID, ""}, {scopeHash("country:NL"), "NL"}} {
		tag := nodePrefix + tt.id + "-" + strings.Repeat("e", 64)
		live := map[string]selector{tag: {Type: "Vless"}}
		got := w.current(tag, live, nil)
		if got.Pool != "NL" || got.PoolCountry != tt.country {
			t.Fatalf("pool %s: got %+v, want country %q", tt.id, got, tt.country)
		}
	}
}

func TestConditionalCardsFollowActiveVPNBranch(t *testing.T) {
	endpoint := "Oslo"
	main := cardPrefix + defaultID
	own := cardPrefix + "openai-inherited"
	rules := []liveRule{{Type: "DomainSuffix", Payload: "fixture.test", Proxy: own}, {Type: "RuleSet", Payload: refilterSites, Proxy: main}, {Type: "Match", Proxy: "DIRECT"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/proxies":
			json.NewEncoder(w).Encode(map[string]interface{}{"proxies": map[string]selector{main: {Type: "Selector", Now: "Fast"}, "Fast": {Type: "URLTest", Now: endpoint}, endpoint: {Type: "Vless"}, own: {Type: "Selector", Now: "DIRECT"}, "DIRECT": {Type: "Direct"}}})
		case "/configs":
			json.NewEncoder(w).Encode(map[string]string{"mode": "rule"})
		case "/rules":
			json.NewEncoder(w).Encode(map[string]interface{}{"rules": rules})
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	hash := strings.Repeat("c", 64)
	body, err := json.Marshal(map[string]interface{}{"mode": "rule", "secret": "fixture", "external-controller": strings.TrimPrefix(server.URL, "http://"),
		stateKey: map[string]string{}, refilterKey: map[string]interface{}{"enabled": true, "domain_behavior": "domain", "site_hash": hash, "ip_hash": hash, "domains": 1, "prefixes": 1},
		"rules": []string{"DOMAIN-SUFFIX,fixture.test," + own, "RULE-SET," + refilterSites + "," + main, "MATCH,DIRECT"}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	c := New(path, dir, xkeen.Runtime{Core: xkeen.CoreMihomo, XrayConfDir: filepath.Join(dir, "configs")}, func() []models.Server { return nil })
	for _, want := range []string{"Oslo", "Stockholm"} {
		endpoint = want
		view, err := c.View(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		matched := 0
		for _, s := range view.Services {
			switch s.ID {
			case "youtube":
				matched++
				if s.InheritedRoute.Kind != "conditional" || s.CurrentRoute == nil || s.CurrentRoute.Kind != "server" || s.CurrentRoute.Name != want || s.CurrentRoute.Pool != "Fast" {
					t.Fatalf("incorrect Re:filter VPN branch: %+v", s)
				}
			case "openai":
				matched++
				if s.InheritedRoute.Kind != "conditional" || s.CurrentRoute == nil || s.CurrentRoute.Kind != "direct" {
					t.Fatalf("conditional fallback ignored: %+v", s)
				}
			}
		}
		if matched != 2 {
			t.Fatal("missing fixture cards")
		}
	}
	rules[1].Extra.Disabled = true
	view, err := c.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range view.Services {
		if s.ID == "youtube" && s.CurrentRoute != nil {
			t.Fatal("disabled VPN rule reported as active")
		}
	}
}
