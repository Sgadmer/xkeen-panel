package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestManualSourceAPIRejectsUnsupportedWithoutCredentialLeak(t *testing.T) {
	h, previous, _ := transactionHandlers(t)
	secret := "private-source-never-echo"
	for _, body := range []string{`{"kind":"file","content":"` + secret + `"}`, `{"kind":"unknown","content":"` + secret + `"}`, `{"kind":"server","content":"` + secret + `"} {}`} {
		response := httptest.NewRecorder()
		h.HandleImportSource(response, httptest.NewRequest(http.MethodPost, "/api/sources/import", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), secret) {
			t.Fatal("unsupported input was accepted or disclosed")
		}
		if !reflect.DeepEqual(h.subscription.GetData(), previous) {
			t.Fatal("invalid local import replaced subscription")
		}
	}
}

func TestManualSourceAPIProbeFailureRestoresRemoteSource(t *testing.T) {
	h, previous, _ := transactionHandlers(t)
	before, err := os.ReadFile(h.config.OutboundsFile)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"kind": "server", "content": transactionNewURI})
	response := httptest.NewRecorder()
	h.HandleImportSource(response, httptest.NewRequest(http.MethodPost, "/api/sources/import", bytes.NewReader(body)))
	if response.Code == http.StatusOK {
		t.Fatal("a source without a verified HTTPS path was accepted")
	}
	after, _ := os.ReadFile(h.config.OutboundsFile)
	if !bytes.Equal(before, after) || !reflect.DeepEqual(h.subscription.GetData(), previous) {
		t.Fatal("failed probe changed previous source or routing")
	}
	if strings.Contains(response.Body.String(), transactionNewURI) || strings.Contains(response.Body.String(), "66666666-7777") {
		t.Fatal("credentials leaked into error")
	}
}

func TestSourceViewHidesKeysAndReportsManualRefreshState(t *testing.T) {
	h, _, _ := transactionHandlers(t)
	if _, err := h.subscription.ImportContent(transactionNewURI, "server"); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	h.HandleGetSubscription(response, httptest.NewRequest(http.MethodGet, "/api/subscription", nil))
	var view map[string]interface{}
	if json.Unmarshal(response.Body.Bytes(), &view) != nil || view["configured"] != true || view["source_kind"] != "server" || view["can_refresh"] != false {
		t.Fatal("manual source view is incorrect")
	}
	if strings.Contains(response.Body.String(), transactionNewURI) {
		t.Fatal("public source view leaked credential URI")
	}
	if err := h.RefreshManaged(httptest.NewRequest(http.MethodGet, "/", nil).Context()); err != nil {
		t.Fatal("hourly refresh must skip manual credentials")
	}
}
