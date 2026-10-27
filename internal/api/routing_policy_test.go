package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"xkeen-panel/internal/xkeen"
)

func TestRoutingPolicyAPIRequiresConfirmationAndPersists(t *testing.T) {
	h, _, _ := transactionHandlers(t)
	addExclusionInputs(t, h)
	rejected := httptest.NewRecorder()
	h.HandlePutRoutingPolicy(rejected, httptest.NewRequest(http.MethodPut, "/api/routing-mode", bytes.NewBufferString(`{"mode":"all"}`)))
	if rejected.Code != 400 {
		t.Fatal("changed routing without confirmation")
	}
	response := httptest.NewRecorder()
	h.HandlePutRoutingPolicy(response, httptest.NewRequest(http.MethodPut, "/api/routing-mode", bytes.NewBufferString(`{"mode":"selected","services":["youtube"],"addresses":["example.com"],"confirm_replace":true}`)))
	if response.Code != 200 {
		t.Fatalf("mode failed %s", response.Body.String())
	}
	var view struct {
		Policy xkeen.RoutingPolicy `json:"policy"`
	}
	if json.Unmarshal(response.Body.Bytes(), &view) != nil || view.Policy.Mode != "selected" {
		t.Fatal("mode response missing")
	}
	policy, err := xkeen.LoadRoutingPolicy(h.detector.Runtime())
	if err != nil || policy.Mode != "selected" {
		t.Fatal("mode not persisted")
	}
}

func TestRoutingPolicyAPIRollbackIncludesAbsentControlFile(t *testing.T) {
	h, _, _ := transactionHandlers(t)
	addExclusionInputs(t, h)
	rt := h.detector.Runtime()
	before, _ := os.ReadFile(rt.RoutingFile)
	_, err := h.withSubscriptionTransaction(func(*subscriptionApplySnapshot) (map[string]interface{}, error) {
		if err := xkeen.SetRoutingPolicy(rt, h.config.OutboundsFile, xkeen.RoutingPolicy{Mode: "all"}); err != nil {
			return nil, err
		}
		return nil, errors.New("simulate later failure")
	})
	if err == nil {
		t.Fatal("expected failed transaction")
	}
	after, _ := os.ReadFile(rt.RoutingFile)
	if !bytes.Equal(before, after) {
		t.Fatal("failed policy transaction changed old rules")
	}
	if _, err := os.Stat(xkeen.RoutingPolicyPath(rt)); !os.IsNotExist(err) {
		t.Fatal("absent control file was not rolled back")
	}
}
