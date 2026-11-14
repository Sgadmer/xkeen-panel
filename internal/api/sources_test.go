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
