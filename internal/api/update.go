package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"xkeen-panel/internal/updater"
)

type UpdateHandler struct {
	updater *updater.Updater
}

func NewUpdateHandler(u *updater.Updater) *UpdateHandler {
	return &UpdateHandler{updater: u}
}

func (h *UpdateHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.updater.State())
}

func (h *UpdateHandler) HandleCheck(w http.ResponseWriter, r *http.Request) {
	state, err := h.updater.Check(r.Context())
	if err != nil {
		writeUpdateError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

// Answers as soon as the install starts: the restart into the new version ends this connection anyway.
func (h *UpdateHandler) HandleApply(w http.ResponseWriter, r *http.Request) {
	if err := h.updater.Apply(); err != nil {
		writeUpdateError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusAccepted, h.updater.State())
}

func (h *UpdateHandler) HandleRollback(w http.ResponseWriter, r *http.Request) {
	if err := h.updater.Rollback(); err != nil {
		writeUpdateError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusAccepted, h.updater.State())
}

func (h *UpdateHandler) HandleSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Auto *bool `json:"auto"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Auto == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "неверный формат запроса"})
		return
	}

	if err := h.updater.SetAuto(*req.Auto); err != nil {
		writeUpdateError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, h.updater.State())
}

func writeUpdateError(w http.ResponseWriter, fallbackStatus int, err error) {
	status, message := fallbackStatus, err.Error()
	if errors.Is(err, updater.ErrLocked) {
		status, message = http.StatusForbidden, updater.ErrLocked.Error()
	}
	writeJSON(w, status, map[string]string{"error": message})
}
