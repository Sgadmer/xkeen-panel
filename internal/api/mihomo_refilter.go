package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/cardcontroller"
)

func (h *Handlers) mountRefilter(r chi.Router) {
	write := func(w http.ResponseWriter, status cardcontroller.RefilterStatus, err error) {
		if err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, status)
	}
	r.Get("/routing/blocklist", func(w http.ResponseWriter, r *http.Request) {
		state, err := h.Cards.RefilterStatus()
		write(w, state, err)
	})
	update := func(w http.ResponseWriter, r *http.Request, enabled *bool, force bool) {
		var state cardcontroller.RefilterStatus
		var err error
		if enabled != nil && !*enabled && !force {
			state, err = h.Cards.SetProtectedRouting(r.Context())
		} else {
			state, err = h.Cards.UpdateRefilter(r.Context(), enabled, force)
		}
		if err == nil && h.watchdog != nil {
			go h.watchdog.CheckNow()
		}
		write(w, state, err)
	}
	r.Put("/routing/blocklist", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512))
		dec.DisallowUnknownFields()
		if dec.Decode(&body) != nil || dec.Decode(&struct{}{}) != io.EOF || body.Enabled == nil {
			writeJSON(w, 400, map[string]string{"error": "Требуется значение enabled."})
			return
		}
		update(w, r, body.Enabled, false)
	})
	r.Post("/routing/blocklist/refresh", func(w http.ResponseWriter, r *http.Request) { update(w, r, nil, true) })
}
