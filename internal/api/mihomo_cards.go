package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// MountMihomoCards adds service assignments to the main authenticated API.
func (h *Handlers) MountMihomoCards(r chi.Router, host string) {
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					h.watchdog.LockChanges()
					defer h.watchdog.UnlockChanges()
				}
				next.ServeHTTP(w, r)
			})
		})
		h.Cards.MountExclusions(r, h.config.DataDir)
		h.mountMultiPools(r)
		r.Post("/service-routes/{service}/client", func(w http.ResponseWriter, r *http.Request) {
			access, err := h.Cards.EnableServiceProxy(r.Context(), host, chi.URLParam(r, "service"))
			if err != nil {
				writeJSON(w, 409, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, access)
		})
		r.Get("/service-routes", func(w http.ResponseWriter, r *http.Request) {
			data, err := h.Cards.View(r.Context())
			if err != nil {
				writeJSON(w, 503, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, data)
		})
		r.Put("/service-routes", func(w http.ResponseWriter, r *http.Request) {
			var choice struct {
				ServiceID string  `json:"service_id"`
				TargetID  *string `json:"target_id"`
			}
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
			dec.DisallowUnknownFields()
			if dec.Decode(&choice) != nil || dec.Decode(&struct{}{}) != io.EOF || choice.ServiceID == "" || choice.TargetID == nil {
				writeJSON(w, 400, map[string]string{"error": "Не удалось прочитать выбор сервиса."})
				return
			}
			data, err := h.Cards.Set(r.Context(), choice.ServiceID, *choice.TargetID)
			if err != nil {
				writeJSON(w, 409, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, data)
		})
	})
}
