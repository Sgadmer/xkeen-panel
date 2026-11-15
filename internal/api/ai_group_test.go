package api

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/cardcontroller"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/monitor"
	"xkeen-panel/internal/xkeen"
)

func TestAIGroupUpdateRequiresExplicitUnambiguousTarget(t *testing.T) {
	dir := t.TempDir()
	h := &Handlers{config: &models.Config{DataDir: dir}, watchdog: &monitor.Watchdog{}, Cards: cardcontroller.New(filepath.Join(dir, "missing.yaml"), dir, xkeen.Runtime{}, func() []models.Server { return nil })}
	router := chi.NewRouter()
	h.MountMihomoCards(router, "127.0.0.1")
	for _, body := range []string{`{}`, `{"target_id":null}`, `{"target_id":1}`, `{"target_id":"x","service_ids":["openai"]}`, `{"target_id":"x"}{}`, `[]`} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("PUT", "/service-routes/ai-group", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatalf("invalid body was not rejected: %s (%d)", body, w.Code)
		}
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("PUT", "/service-routes/ai-group", strings.NewReader(`{"target_id":"direct"}`)))
	if w.Code != 409 {
		t.Fatal("group allowed Claude to use a direct route", w.Code)
	}
}
