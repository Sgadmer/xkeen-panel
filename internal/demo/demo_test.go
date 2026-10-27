package demo

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestSettingPreviewIsSyntheticAndDoesNotApply(t *testing.T) {
	h := Handler(fstest.MapFS{})
	getState := func() string {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/components", nil))
		var state map[string]json.RawMessage
		if json.Unmarshal(w.Body.Bytes(), &state) != nil {
			t.Fatal("invalid demo state")
		}
		return string(state["settings"])
	}
	before := getState()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/api/components/preview", strings.NewReader(`{"component":"settings","setting":"ipv6","enabled":false}`)))
	var plan struct {
		Change struct {
			ID      string   `json:"setting_id"`
			Current bool     `json:"current"`
			Desired bool     `json:"desired"`
			Effects []string `json:"effects"`
		} `json:"change"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &plan) != nil || plan.Change.ID != "ipv6" || !plan.Change.Current || plan.Change.Desired || len(plan.Change.Effects) == 0 {
		t.Fatalf("missing synthetic change confirmation: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/api/components/apply", strings.NewReader(`{"plan_id":"synthetic-preview-ipv6"}`)))
	if w.Code != 403 || getState() != before {
		t.Fatal("demo preview or apply mutated the fixture")
	}
}

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
