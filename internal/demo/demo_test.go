package demo

import (
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestDemoNeverPerformsMutationsAndContainsOnlySyntheticState(t *testing.T) {
	h := Handler(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<head></head><body>frontend</body>")}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/api/components/apply", strings.NewReader(`{"component":"xray"}`)))
	if w.Code != 403 {
		t.Fatal("demo allowed a component operation")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/settings/access", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "synthetic-demo-session") {
		t.Fatal("demo frontend unavailable")
	}
}
