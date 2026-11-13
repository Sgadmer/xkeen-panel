package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/cardcontroller"
)

func (h *Handlers) mountMultiPools(router chi.Router) {
	router.Get("/multipools", func(w http.ResponseWriter, r *http.Request) {
		pools, err := h.Cards.MultiPools()
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"pools": pools})
	})
	edit := func(w http.ResponseWriter, r *http.Request) {
		var spec *cardcontroller.PoolSpec
		var sources []string
		if r.Method != http.MethodDelete {
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768))
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
