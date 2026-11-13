package cardcontroller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestViewFollowsInheritedGroupOnEachRead(t *testing.T) {
	var selection atomic.Int32
	var providerReads atomic.Int32
	first, second := "North", "West"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/configs":
			json.NewEncoder(w).Encode(map[string]string{"mode": "rule"})
		case "/rules":
			json.NewEncoder(w).Encode(map[string]any{"rules": []liveRule{
				{Type: "DomainSuffix", Proxy: "Discord"}, {Type: "DomainSuffix", Proxy: "ChatGPT"}, {Type: "Match", Proxy: "DIRECT"},
			}})
		case "/proxies":
			pick := first
			if selection.Load() != 0 {
				pick = second
			}
			json.NewEncoder(w).Encode(map[string]any{"proxies": map[string]selector{
				"Discord":  {Type: "Selector", Now: "Auto"},
				"ChatGPT":  {Type: "Selector", Now: second},
				"Auto":     {Type: "URLTest", Now: pick, All: []string{first, second}},
				"Telegram": {Type: "Selector", Now: "DIRECT"},
				"DIRECT":   {Type: "Direct"},
			}})
		case "/providers/proxies":
			providerReads.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"providers": map[string]any{"subscription": map[string]any{
				"proxies": []map[string]string{{"name": first, "type": "Hysteria2"}, {"name": second, "type": "Vless"}},
			}}})
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg, err := json.Marshal(map[string]string{"mode": "rule", "secret": "fixture", "external-controller": strings.TrimPrefix(server.URL, "http://")})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, cfg, 0600); err != nil {
		t.Fatal(err)
	}
	c := New(path, dir, xkeen.Runtime{Core: xkeen.CoreXray, XrayConfDir: filepath.Join(dir, "configs")}, func() []models.Server { return nil })
	for i, want := range []string{first, second} {
		selection.Store(int32(i))
		view, err := c.View(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		byID := map[string]*xkeen.InheritedRoute{}
		for _, s := range view.Services {
			byID[s.ID] = s.InheritedRoute
		}
		d := byID["discord"]
		if d == nil || d.Group != "Discord" || d.Kind != "server" || d.Endpoint != want || d.Strategy != "url-test" || !reflect.DeepEqual(d.Via, []string{"Auto"}) || !reflect.DeepEqual(d.Members, []string{first, second}) {
			t.Fatalf("incorrect automatic service route on read %d: %+v", i, d)
		}
		g := byID["openai"]
		if g == nil || g.Kind != "server" || g.Endpoint != second || g.Strategy != "" || len(g.Via) != 0 {
			t.Fatalf("incorrect manual service group: %+v", g)
		}
		if g := byID["telegram"]; g == nil || g.Kind != "unknown" || g.Group != "" {
			t.Fatalf("unused group displayed as active: %+v", g)
		}
		if providerReads.Load() != int32(i+1) {
			t.Fatalf("unexpected provider lookups: %d", providerReads.Load())
		}
	}
}

func TestInheritedRouteAmbiguousAndTerminalGroups(t *testing.T) {
	missing := func(string) selector { return selector{} }
	live := map[string]selector{
		"group":  {Type: "Selector", Now: "next"},
		"DIRECT": {Type: "Direct"},
		"REJECT": {Type: "Reject"},
		"PASS":   {Type: "Pass"},
	}
	for _, test := range []struct {
		target         selector
		kind, strategy string
	}{
		{selector{Type: "Selector", Now: "DIRECT"}, "direct", ""},
		{selector{Type: "Fallback", Now: "REJECT", All: []string{"REJECT"}}, "reject", "fallback"},
		{selector{Type: "Selector", Now: "PASS"}, "unknown", ""},
		{selector{Type: "Selector", Now: "group"}, "unknown", ""},
		{selector{Type: "Selector", Now: "missing"}, "unknown", ""},
		{selector{Type: "URLTest"}, "unknown", "url-test"},
		{selector{Type: "LoadBalance", Now: "DIRECT", All: []string{"DIRECT", "REJECT"}}, "unknown", "load-balance"},
	} {
		live["next"] = test.target
		got := inheritedRoute("group", live, nil, missing)
		if got.Kind != test.kind || got.Strategy != test.strategy || got.Endpoint != "" {
			t.Errorf("%+v: %+v", test.target, got)
		}
	}
}
