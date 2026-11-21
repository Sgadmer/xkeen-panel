package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/cardcontroller"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/monitor"
	"xkeen-panel/internal/xkeen"
)

func TestSourceLinkReplacementKeepsServersAndLeavesNativeProviderAlone(t *testing.T) {
	const (
		issued   = "vless://11111111-2222-3333-4444-555555555555@192.0.2.1:443?type=tcp&security=reality&sni=example.com&fp=chrome&pbk=KEY&sid=ab&flow=xtls-rprx-vision#NY"
		reissued = "vless://99999999-2222-3333-4444-555555555555@192.0.2.2:443?type=tcp&security=reality&sni=example.com&fp=chrome&pbk=KEY&sid=cd&flow=xtls-rprx-vision#NY"
	)
	root := t.TempDir()
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer core.Close()
	serve := func(body string) string {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		t.Cleanup(server.Close)
		return server.URL + "/secret-token"
	}
	retired, moved, native := serve(issued), serve(reissued), serve(issued)
	u, _ := url.Parse(core.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	// The profile's own provider downloads the third link by itself.
	profile := map[string]interface{}{"mode": "rule", "external-controller": net.JoinHostPort(host, port), "secret": "test-secret", "rules": []string{"MATCH,REJECT"},
		"proxy-providers": map[string]interface{}{"owned": map[string]interface{}{"type": "http", "url": native, "path": "owned.yaml"}}}
	data, _ := json.Marshal(profile)
	path := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	manager := xkeen.NewSubscriptionManager(root)
	initPath := filepath.Join(root, "S05xkeen")
	if err := os.WriteFile(initPath, []byte("name_client=mihomo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	detector := xkeen.NewDetector(root, "", initPath, "", "", path, "")
	cfg := &models.Config{DataDir: root}
	h := NewHandlers(cfg, manager, monitor.NewWatchdog(cfg, manager, detector), detector, xkeen.NewPoolStore(root))
	h.Cards = cardcontroller.New(path, root, xkeen.Runtime{Core: xkeen.CoreMihomo}, manager.GetServers)
	ids := map[string]string{}
	for name, link := range map[string]string{"Moved provider": retired, "Profile provider": native} {
		added, err := manager.AddSource(context.Background(), xkeen.SourceInput{Kind: "subscription", Name: name, URL: link})
		if err != nil {
			t.Fatal(err)
		}
		ids[name] = added[0].SourceID
	}
	manager.TakeTargetMoves()
	find := func(source string) models.Server {
		for _, s := range manager.GetServers() {
			if s.SourceID == source {
				return s
			}
		}
		t.Fatal("source lost its server")
		return models.Server{}
	}
	before := find(ids["Moved provider"])
	if err := manager.SetCountryOverride(before.ID, "US"); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Post("/sources/{id}/url", h.HandleReplaceSourceURL)
	request := func(id, body string, want int) string {
		t.Helper()
		out := httptest.NewRecorder()
		router.ServeHTTP(out, httptest.NewRequest("POST", "/sources/"+id+"/url", strings.NewReader(body)))
		if out.Code != want || strings.Contains(out.Body.String(), "secret-token") || strings.Contains(out.Body.String(), "-2222-3333") {
			t.Fatalf("replace link of %s: status %d, body %s", id, out.Code, out.Body.String())
		}
		return out.Body.String()
	}
	link := func(value string) string {
		encoded, _ := json.Marshal(map[string]string{"url": value})
		return string(encoded)
	}
	request(ids["Moved provider"], link(moved), 200)
	after := find(ids["Moved provider"])
	if after.ID != before.ID || after.CountryOverride != "US" || after.Address != "192.0.2.2" || xkeen.ServiceTargetID(after) == xkeen.ServiceTargetID(before) {
		t.Fatalf("replacing the link did not continue the same server: %+v", after)
	}
	// The same link again, a link another source already uses, and bad input.
	request(ids["Moved provider"], link(moved), 400)
	request(ids["Moved provider"], link(native), 400)
	request(ids["Moved provider"], `{"url":"`+retired+`","name":"x"}`, 400)
	request("missing", link(retired), 404)
	// A source that the profile downloads on its own is not rewritten here.
	if body := request(ids["Profile provider"], link(retired), 400); !strings.Contains(body, "Mihomo") {
		t.Fatalf("native provider refusal does not explain itself: %s", body)
	}
	if kept := find(ids["Profile provider"]); kept.Address != "192.0.2.1" {
		t.Fatal("a refused replacement changed the catalogue")
	}
}

func TestSourceHTTPFailedRefreshDoesNotBlockOtherSource(t *testing.T) {
	root := t.TempDir()
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer core.Close()
	u, _ := url.Parse(core.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	profile := map[string]interface{}{"mode": "rule", "external-controller": net.JoinHostPort(host, port), "secret": "test-secret", "rules": []string{"MATCH,REJECT"}}
	data, _ := json.Marshal(profile)
	path := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	manager := xkeen.NewSubscriptionManager(root)
	initPath := filepath.Join(root, "S05xkeen")
	if err := os.WriteFile(initPath, []byte("name_client=mihomo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	detector := xkeen.NewDetector(root, "", initPath, "", "", path, "")
	cfg := &models.Config{DataDir: root}
	wd := monitor.NewWatchdog(cfg, manager, detector)
	h := NewHandlers(cfg, manager, wd, detector, xkeen.NewPoolStore(root))
	h.Cards = cardcontroller.New(path, root, xkeen.Runtime{Core: xkeen.CoreMihomo}, manager.GetServers)
	// Only native provider refresh uses Mihomo HTTP in this unmanaged profile.
	// Its URL map is empty, and no card routes have been activated.
	var failing, changed atomic.Bool
	serve := func(first bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if first && failing.Load() {
				http.Error(w, "upstream-secret", 503)
				return
			}
			if !first && changed.Load() {
				_, _ = w.Write([]byte(transactionOldURI + "\n" + transactionNewURI))
				return
			}
			_, _ = w.Write([]byte(transactionOldURI))
		}))
	}
	bad, good := serve(true), serve(false)
	defer bad.Close()
	defer good.Close()
	for _, s := range []xkeen.SourceInput{{Kind: "subscription", Name: "First", URL: bad.URL + "/secret-token"}, {Kind: "subscription", Name: "Second", URL: good.URL + "/secret-token"}} {
		if _, err := manager.AddSource(context.Background(), s); err != nil {
			t.Fatal(err)
		}
	}
	failing.Store(true)
	changed.Store(true)
	if detector.Runtime().Core != xkeen.CoreMihomo {
		t.Fatal("fixture did not initialize a Mihomo runtime")
	}
	resp, err := h.refreshSources(context.Background())
	if err == nil || resp["updated_sources"] != 1 || strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "upstream-secret") {
		t.Fatalf("wrong refresh result %v %v", resp["updated_sources"], err)
	}
	sources := manager.GetSources()
	if sources[0].ServerCount != 1 || sources[1].ServerCount != 2 {
		t.Fatal("partial refresh corrupted independent sources")
	}
	router := chi.NewRouter()
	router.Get("/sources", h.HandleSources)
	router.Put("/sources/{id}", h.HandleRenameSource)
	router.Delete("/sources/{id}", h.HandleDeleteSource)
	router.Post("/sources/{id}/refresh", h.HandleRefreshSource)
	request := func(method, path, body string, want int) {
		t.Helper()
		out := httptest.NewRecorder()
		router.ServeHTTP(out, httptest.NewRequest(method, path, strings.NewReader(body)))
		if out.Code != want || strings.Contains(out.Body.String(), "secret-token") || strings.Contains(out.Body.String(), "11111111-2222") {
			t.Fatalf("wrong %s %s response, status %d", method, path, out.Code)
		}
	}
	request("GET", "/sources", "", 200)
	request("PUT", "/sources/"+sources[1].ID, `{"name":"Second renamed"}`, 200)
	request("POST", "/sources/missing/refresh", "", 404)
	request("DELETE", "/sources/"+sources[0].ID, "", 200)
	if got := manager.GetSources(); len(got) != 1 || got[0].Name != "Second renamed" || got[0].ServerCount != 2 {
		t.Fatal("deletion changed surviving selection")
	}
}
