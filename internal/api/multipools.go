package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/cardcontroller"
	"xkeen-panel/internal/xkeen"
)

func (h *Handlers) mountMultiPools(router chi.Router) {
	router.Put("/pool/limit", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Limit int `json:"limit"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		dec.DisallowUnknownFields()
		if dec.Decode(&input) != nil || dec.Decode(&struct{}{}) != io.EOF || input.Limit < 1 || input.Limit > xkeen.MaxMultiPoolMembers {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Укажите целое число серверов от 1 до 256."})
			return
		}
		if err := h.Cards.ChangeAutoPoolLimit(r.Context(), input.Limit); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		h.watchdog.CheckNow()
		writeJSON(w, http.StatusOK, map[string]bool{"success": true})
	})
	router.Get("/multipools", func(w http.ResponseWriter, r *http.Request) {
		pools, scopes, err := h.Cards.PoolCatalog()
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"pools": pools, "scopes": scopes})
	})
	router.Post("/pool/scope", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ID string `json:"id"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		dec.DisallowUnknownFields()
		if dec.Decode(&input) != nil || input.ID == "" || dec.Decode(&struct{}{}) != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Укажите пул автовыбора."})
			return
		}
		if err := h.Cards.SetScope(r.Context(), input.ID); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		h.watchdog.CheckNow()
		writeJSON(w, http.StatusOK, map[string]bool{"success": true})
	})
	edit := func(w http.ResponseWriter, r *http.Request) {
		var spec *cardcontroller.PoolSpec
		var sources []string
		if r.Method != http.MethodDelete {
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 96<<10))
			dec.DisallowUnknownFields()
			if dec.Decode(&spec) != nil || spec == nil || dec.Decode(&struct{}{}) != io.EOF || spec.SourceIDs == nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Укажите название и список подписок мультипула."})
				return
			}
			for _, source := range h.subscription.GetSources() {
				sources = append(sources, source.ID)
			}
		}
		pool, err := h.Cards.EditMultiPool(r.Context(), chi.URLParam(r, "id"), spec, sources)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		if spec == nil {
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
		writeJSON(w, http.StatusOK, pool)
	}
	router.Post("/multipools", edit)
	router.Put("/multipools/{id}", edit)
	router.Delete("/multipools/{id}", edit)
}
