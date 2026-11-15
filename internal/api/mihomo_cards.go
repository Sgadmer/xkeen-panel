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
		h.mountRefilter(r)
		h.mountServiceLists(r)
		r.Get("/kill-switch/events", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, h.Cards.GuardEvents())
		})
		r.Get("/kill-switch", func(w http.ResponseWriter, r *http.Request) {
			policy, err := h.Cards.KillSwitch()
			if err != nil {
				writeJSON(w, 503, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, policy)
		})
		r.Put("/kill-switch", func(w http.ResponseWriter, r *http.Request) {
			var patch struct {
				Enabled *bool  `json:"enabled"`
				Service string `json:"service_id"`
				Mode    string `json:"mode"`
			}
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
			dec.DisallowUnknownFields()
			if dec.Decode(&patch) != nil || dec.Decode(&struct{}{}) != io.EOF || (patch.Enabled != nil && (patch.Service != "" || patch.Mode != "") || patch.Enabled == nil && (patch.Service == "" || patch.Mode != "on" && patch.Mode != "off" && patch.Mode != "inherit")) {
				writeJSON(w, 400, map[string]string{"error": "Недопустимая настройка Kill switch."})
				return
			}
			policy, err := h.Cards.SetKillSwitch(r.Context(), patch.Enabled, patch.Service, patch.Mode)
			if err != nil {
				writeJSON(w, 409, map[string]string{"error": err.Error()})
				return
			}
			if patch.Enabled != nil {
				h.watchdog.CheckNow()
			}
			writeJSON(w, 200, policy)
		})
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
		r.Post("/service-routes/auto-default", func(w http.ResponseWriter, r *http.Request) {
			data, err := h.Cards.EnableServiceAutoDefault(r.Context())
			if err != nil {
				writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, data)
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
		r.Put("/service-routes/ai-group", func(w http.ResponseWriter, r *http.Request) {
			var choice struct {
				TargetID *string `json:"target_id"`
			}
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
			dec.DisallowUnknownFields()
			if dec.Decode(&choice) != nil || dec.Decode(&struct{}{}) != io.EOF || choice.TargetID == nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Выберите один VPN-сервер или пул для группы AI и аналитики."})
				return
			}
			data, err := h.Cards.SetAIGroup(r.Context(), *choice.TargetID)
			if err != nil {
				writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, data)
		})
	})
}
