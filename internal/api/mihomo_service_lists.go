package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/cardcontroller"
)

func (h *Handlers) mountServiceLists(r chi.Router) {
	write := func(w http.ResponseWriter, status cardcontroller.ServiceListsStatus, err error) {
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, status)
	}
	r.Get("/routing/service-lists", func(w http.ResponseWriter, r *http.Request) {
		status, err := h.Cards.ServiceListsStatus()
		write(w, status, err)
	})
	update := func(w http.ResponseWriter, r *http.Request, enabled *bool, force bool) {
		status, err := h.Cards.UpdateServiceLists(r.Context(), enabled, force)
		write(w, status, err)
	}
	r.Put("/routing/service-lists", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&body) != nil || decoder.Decode(&struct{}{}) != io.EOF || body.Enabled == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Требуется значение enabled."})
			return
		}
		update(w, r, body.Enabled, false)
	})
	r.Post("/routing/service-lists/refresh", func(w http.ResponseWriter, r *http.Request) { update(w, r, nil, true) })
}
