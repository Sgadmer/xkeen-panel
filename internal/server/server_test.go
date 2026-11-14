package server

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"xkeen-panel/internal/api"
	"xkeen-panel/internal/auth"
	"xkeen-panel/internal/cardcontroller"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/monitor"
	"xkeen-panel/internal/sse"
	"xkeen-panel/internal/updater"
	"xkeen-panel/internal/xkeen"
)

func TestMihomoPanelKeepsSettingsAndNavigation(t *testing.T) {
	dir := t.TempDir()
	cfg := &models.Config{DataDir: dir}
	cfg.SetRuntime([]string{"RU"}, 3600)
	user := auth.NewUserManager(dir)
	if err := user.CreatePendingUser("test", "synthetic-password", "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := user.ConfirmSetup(); err != nil {
		t.Fatal(err)
	}
	token, err := auth.GenerateToken("test", user.GetUser().JWTSecret)
	if err != nil {
		t.Fatal(err)
	}

	sub := xkeen.NewSubscriptionManager(dir)
	detector := xkeen.NewDetector(dir, "", "", "", "", "", "")
	wd := monitor.NewWatchdog(cfg, sub, detector)
	reset := make(chan struct{}, 1)
	settings := api.NewPanelSettingsHandler(cfg, reset)
	frontend := fstest.MapFS{
		"index.html":    {Data: []byte("dashboard")},
		"manifest.json": {Data: []byte("manifest")},
	}
	s := New(cfg, user, sub, wd, detector, xkeen.NewPoolStore(dir), nil,
		sse.NewEventBus(), updater.New(updater.Options{DataDir: dir}), settings, frontend)
	s.Cards = cardcontroller.New(dir+"/missing.yaml", dir, xkeen.Runtime{}, sub.GetServers)
	s.CardsHost = "127.0.0.1"

	var logs bytes.Buffer
	out := log.Writer()
	defer log.SetOutput(out)
	log.SetOutput(&logs)
	handler := s.Handler()
	ask := func(method, url, body string, signed bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, url, strings.NewReader(body))
		if signed {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/", "/settings", "/services", "/servers"} {
		w := ask("GET", path, "", false)
		if w.Code != 200 || w.Body.String() != "dashboard" {
			t.Fatalf("SPA %s: %d", path, w.Code)
		}
	}
	w := ask("GET", "/manifest.json", "", false)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "json") || w.Body.String() != "manifest" {
		t.Fatal("manifest did not serve as a static asset")
	}
	for _, path := range []string{"/api/diagnostics", "/api/panel/settings", "/api/components", "/api/devices", "/api/logs", "/api/exclusions", "/api/service-routes", "/api/servers", "/api/setup/state", "/api/account/passkey", "/api/update", "/api/events", "/api/servers/check"} {
		if w := ask("GET", path, "", false); w.Code != http.StatusUnauthorized {
			t.Fatalf("missing protected route %s (HTTP %d)", path, w.Code)
		}
	}
	for _, check := range []struct{ method, path string }{
		{"GET", "/api/access/face-id/plan?label=example"},
		{"POST", "/api/access/face-id/prepare"},
		{"POST", "/api/devices/rename"},
		{"POST", "/api/devices/forget"},
		{"POST", "/api/service-routes/auto-default"},
	} {
		if w := ask(check.method, check.path, "", false); w.Code != http.StatusUnauthorized {
			t.Fatalf("route must require panel authentication: %s %s returned %d", check.method, check.path, w.Code)
		}
	}
	for _, path := range []string{"/api/devices/rename", "/api/devices/forget"} {
		w := ask("POST", path, `{"mac":"invalid"}`, true)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "MAC") {
			t.Fatalf("authenticated request did not reach device handler: %s returned %d", path, w.Code)
		}
	}
	w = ask("GET", "/api/panel/settings", "", true)
	var saved api.PanelSettings
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &saved) != nil || saved.RefreshMinutes != 60 {
		t.Fatal("original settings not available")
	}
	w = ask("PUT", "/api/panel/settings", `{"avoid_countries":["BY"],"subscription_refresh_minutes":15}`, true)
	if w.Code != 200 {
		t.Fatalf("save settings: HTTP %d", w.Code)
	}
	select {
	case <-reset:
	default:
		t.Fatal("subscription timer was not reset")
	}
	reloaded := &models.Config{DataDir: dir}
	if err := api.LoadPanelSettings(reloaded); err != nil || reloaded.RefreshInterval().Minutes() != 15 {
		t.Fatal("settings not persisted")
	}
	w = ask("PUT", "/api/service-routes", `{"service_id":"claude","target_id":"direct"}`, true)
	if w.Code != http.StatusConflict {
		t.Fatalf("Claude accepted DIRECT or hit old API: %d", w.Code)
	}
	w = ask("GET", "/api/servers/check?token="+token, "", false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "event: done") || strings.Contains(logs.String(), token) {
		t.Fatal("authenticated stream or token redaction failed")
	}
}
