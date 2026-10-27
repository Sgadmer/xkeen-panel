package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/xkeen"
)

func addExclusionInputs(t *testing.T, h *Handlers) {
	t.Helper()
	data := []byte(`{"inbounds":[{"tag":"redirect","protocol":"dokodemo-door"},{"tag":"panel-probe","protocol":"socks"}]}`)
	if err := os.WriteFile(filepath.Join(h.config.XrayConfigDir, "03_inbounds.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestExclusionsAddDeleteAndPersist(t *testing.T) {
	h, _, _ := transactionHandlers(t)
	addExclusionInputs(t, h)
	response := httptest.NewRecorder()
	h.HandleCreateExclusion(response, httptest.NewRequest(http.MethodPost, "/api/exclusions", bytes.NewBufferString(`{"value":"https://EXAMPLE.com/path?token=discard","comment":"app"}`)))
	if response.Code != http.StatusOK {
		t.Fatalf("create failed: %d %s", response.Code, response.Body.String())
	}
	entries, err := xkeen.LoadExclusions(h.config.DataDir)
	if err != nil || len(entries.Entries) != 1 || entries.Entries[0].Value != "domain:example.com" {
		t.Fatalf("invalid saved list %+v %v", entries, err)
	}
	fragment, err := os.ReadFile(xkeen.ExclusionsConfigPath(h.detector.Runtime()))
	if err != nil || bytes.Contains(fragment, []byte("token")) {
		t.Fatal("fragment retained URL path/query or was not saved")
	}
	duplicate := httptest.NewRecorder()
	h.HandleCreateExclusion(duplicate, httptest.NewRequest(http.MethodPost, "/api/exclusions", bytes.NewBufferString(`{"value":"example.com"}`)))
	if duplicate.Code != http.StatusBadRequest {
		t.Fatal("duplicate accepted")
	}
	ctx := chi.NewRouteContext()
	ctx.URLParams.Add("id", entries.Entries[0].ID)
	request := httptest.NewRequest(http.MethodDelete, "/api/exclusions/"+entries.Entries[0].ID, nil).WithContext(context.WithValue(context.Background(), chi.RouteCtxKey, ctx))
	deleted := httptest.NewRecorder()
	h.HandleDeleteExclusion(deleted, request)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete failed %s", deleted.Body.String())
	}
	entries, err = xkeen.LoadExclusions(h.config.DataDir)
	if err != nil || len(entries.Entries) != 0 {
		t.Fatal("last deletion did not persist an empty list")
	}
}

func TestExclusionsTransactionRollsBackNewAndExistingFiles(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "existing"}[existing], func(t *testing.T) {
			h, _, _ := transactionHandlers(t)
			addExclusionInputs(t, h)
			fragment := xkeen.ExclusionsConfigPath(h.detector.Runtime())
			store := xkeen.ExclusionsPath(h.config.DataDir)
			beforeRouting, _ := os.ReadFile(fragment)
			if existing {
				for _, path := range []string{store} {
					if err := os.WriteFile(path, []byte("original"), 0640); err != nil {
						t.Fatal(err)
					}
				}
			}
			_, err := h.withSubscriptionTransaction(func(*subscriptionApplySnapshot) (map[string]interface{}, error) {
				for _, path := range []string{fragment, store} {
					if err := os.WriteFile(path, []byte("rejected"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return nil, errors.New("reject staged change")
			})
			if err == nil {
				t.Fatal("transaction did not fail")
			}
			for _, path := range []string{fragment, store} {
				raw, readErr := os.ReadFile(path)
				if path == fragment {
					if readErr != nil || !bytes.Equal(raw, beforeRouting) {
						t.Fatal("routing file changed after rollback")
					}
				} else if existing {
					if readErr != nil || string(raw) != "original" {
						t.Fatal("rollback did not restore old contents")
					}
				} else if !os.IsNotExist(readErr) {
					t.Fatal("new exclusion file survived rollback")
				}
			}
		})
	}
}
