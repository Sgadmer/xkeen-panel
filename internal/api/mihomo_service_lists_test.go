package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/cardcontroller"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestServiceListsAPIRejectsDisableWithoutController(t *testing.T) {
	h := &Handlers{}
	router := chi.NewRouter()
	h.mountServiceLists(router)
	for _, body := range []string{`{"enabled":false}`, `{}`, `{"enabled":null}`, `{"enabled":true,"extra":1}`, `{"enabled":true}{}`} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("PUT", "/routing/service-lists", strings.NewReader(body)))
		if w.Code != 400 {
			t.Errorf("invalid update %q returned %d", body, w.Code)
		}
	}
}

func TestServiceListsAPIStatusDoesNotActivateOrDownload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := []byte(`{"mode":"rule","external-controller":"127.0.0.1:1","secret":"fixture","rules":["MATCH,DIRECT"]}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{Cards: cardcontroller.New(path, dir, xkeen.Runtime{}, func() []models.Server { return nil })}
	router := chi.NewRouter()
	h.mountServiceLists(router)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/routing/service-lists", nil))
	var status struct{ Enabled, Ready bool }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &status) != nil || !status.Enabled || status.Ready {
		t.Fatal("incorrect initial status", w.Code, w.Body.String())
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(raw, after) {
		t.Fatal("reading status rewrote a running profile")
	}
}
