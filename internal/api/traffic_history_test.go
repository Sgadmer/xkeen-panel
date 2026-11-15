package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/trafficjournal"
)

func TestTrafficHistoryAPIDefaultOffAndValidation(t *testing.T) {
	dataDir := t.TempDir()
	h := &Handlers{History: trafficjournal.New(context.Background(), dataDir)}
	router := chi.NewRouter()
	h.MountTrafficHistory(router)
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	w := get("/traffic-history/settings")
	var status map[string]interface{}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &status) != nil || status["enabled"] != false || status["running"] != false || status["retention_hours"] != float64(24) {
		t.Fatalf("default-off status invalid: %d %s", w.Code, w.Body)
	}
	w = get("/traffic-history?limit=50")
	var page struct {
		Events []interface{}          `json:"events"`
		Status map[string]interface{} `json:"status"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Events == nil || len(page.Events) != 0 || page.Status["enabled"] != false {
		t.Fatal("disabled history did not return an empty page")
	}
	for _, body := range []string{`{"enabled":true}`, `{"enabled":true,"storage_id":"internal","path":"/etc"}`, `{"enabled":false,"unexpected":true}`, `{"max_events":1,"max_device_events":2}`} {
		w = httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("PUT", "/traffic-history/settings", strings.NewReader(body)))
		if w.Code < 400 || h.History.Status().Enabled {
			t.Fatalf("invalid setting enabled disk history: %s", body)
		}
	}
	for _, path := range []string{"/traffic-history?limit=101", "/traffic-history?limit=-1", "/traffic-history?q=%00"} {
		if w = get(path); w.Code != 400 {
			t.Fatalf("invalid query accepted: %s", path)
		}
	}
	files, err := os.ReadDir(dataDir)
	if err != nil || len(files) != 0 {
		t.Fatal("disabled/invalid history created persistent files")
	}
	if _, err = os.Stat(filepath.Join(dataDir, "traffic.sqlite")); !os.IsNotExist(err) {
		t.Fatal("a database was allocated without user activation")
	}
}
