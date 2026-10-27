package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"xkeen-panel/internal/models"
)

func TestAccessQRContainsOnlyOrigin(t *testing.T) {
	h := &Handlers{config: &models.Config{}}
	r := httptest.NewRequest("GET", "http://router.example:3000/api/access", nil)
	r.Header.Set("Authorization", "Bearer PRIVATE-SESSION")
	r.Header.Set("X-Forwarded-Host", "ignored.example")
	w := httptest.NewRecorder()
	h.HandlePanelAccess(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "http://router.example:3000/") || !strings.Contains(w.Body.String(), "data:image/png;base64,") || strings.Contains(w.Body.String(), "PRIVATE-SESSION") || strings.Contains(w.Body.String(), "ignored.example") {
		t.Fatal("unsafe or invalid panel address response")
	}
}
