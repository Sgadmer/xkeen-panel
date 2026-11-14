package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/monitor"
)

func TestMihomoServiceUpdateRequiresExplicitTarget(t *testing.T) {
	h := &Handlers{config: &models.Config{DataDir: t.TempDir()}, watchdog: &monitor.Watchdog{}}
	router := chi.NewRouter()
	h.MountMihomoCards(router, "127.0.0.1")
	for _, body := range []string{`{"service_id":"openai"}`, `{"service_id":"openai","target_id":null}`} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("PUT", "/service-routes", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatalf("omitting the target returned %d", w.Code)
		}
	}
}
