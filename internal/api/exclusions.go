package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"xkeen-panel/internal/xkeen"

	"github.com/go-chi/chi/v5"
)

func (h *Handlers) HandleGetExclusions(w http.ResponseWriter, r *http.Request) {
	entries, err := xkeen.LoadExclusions(h.config.DataDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (h *Handlers) HandleCreateExclusion(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Value   string `json:"value"`
		Comment string `json:"comment"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "неверный формат запроса"})
		return
	}
	entry, err := xkeen.NormalizeExclusion(req.Value, req.Comment)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	h.changeExclusions(w, r, func(entries xkeen.Exclusions) (xkeen.Exclusions, error) {
		for _, old := range entries.Entries {
			if old.ID == entry.ID {
				return entries, fmt.Errorf("такое исключение уже добавлено")
			}
		}
		if len(entries.Entries) >= xkeen.MaxExclusions {
			return entries, fmt.Errorf("достигнут предел в 500 исключений")
		}
		entries.Entries = append(entries.Entries, entry)
		return entries, nil
	})
}

func (h *Handlers) HandleDeleteExclusion(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h.changeExclusions(w, r, func(entries xkeen.Exclusions) (xkeen.Exclusions, error) {
		for i, old := range entries.Entries {
			if old.ID == id {
				entries.Entries = append(entries.Entries[:i], entries.Entries[i+1:]...)
				return entries, nil
			}
		}
		return entries, fmt.Errorf("исключение не найдено")
	})
}

func (h *Handlers) changeExclusions(w http.ResponseWriter, r *http.Request, change func(xkeen.Exclusions) (xkeen.Exclusions, error)) {
	response, err := h.withSubscriptionTransaction(func(transaction *subscriptionApplySnapshot) (map[string]interface{}, error) {
		rt := h.detector.Runtime()
		if rt.Core != xkeen.CoreXray {
			return nil, fmt.Errorf("исключения поддерживаются при использовании Xray")
		}
		entries, err := xkeen.LoadExclusions(h.config.DataDir)
		if err != nil {
			return nil, err
		}
		entries, err = change(entries)
		if err != nil {
			return nil, err
		}
		if err := xkeen.WriteExclusionsConfig(rt, entries); err != nil {
			return nil, err
		}
		if err := xkeen.SaveExclusions(h.config.DataDir, entries); err != nil {
			return nil, fmt.Errorf("не удалось сохранить исключения")
		}
		if rt.Installed {
			transaction.runtimeTouched = true
			if err := h.restartManaged(rt.Dispatcher); err != nil {
				return nil, err
			}
			if err := h.waitForBalancer(rt); err != nil {
				return nil, err
			}
			if err := h.watchdog.ReapplySelectionLocked(); err != nil {
				return nil, err
			}
		}
		h.detector.InvalidateTopology()
		return map[string]interface{}{"entries": entries.Entries}, nil
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, response)
}
