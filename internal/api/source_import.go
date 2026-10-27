package api

import (
	"encoding/json"
	"io"
	"net/http"
	"xkeen-panel/internal/models"
)

// HandleImportSource accepts local server links or text file content. Remote
// URLs keep using the existing subscription path and its stable HWID handling.
func (h *Handlers) HandleImportSource(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind    string `json:"kind"`
		Content string `json:"content"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 6<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(new(interface{})) != io.EOF || (req.Kind != "server" && req.Kind != "file") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "выберите ссылку сервера или файл и передайте его содержимое"})
		return
	}
	response, err := h.withSubscriptionTransaction(func(transaction *subscriptionApplySnapshot) (map[string]interface{}, error) {
		servers, err := h.subscription.ImportContent(req.Content, req.Kind)
		if err != nil {
			return nil, err
		}
		return h.verifyAndApplySource(r.Context(), servers, transaction)
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func sameSourceServers(a, b []models.Server) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].RawURI != b[i].RawURI || string(a[i].RawOutbound) != string(b[i].RawOutbound) || string(a[i].RawProfile) != string(b[i].RawProfile) {
			return false
		}
	}
	return true
}
