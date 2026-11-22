package api

import (
	"encoding/json"
	"errors"
	"io"
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
// Without a body the newest release is installed; {"tag": …} names one from the list.
func (h *UpdateHandler) HandleApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tag string `json:"tag"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "неверный формат запроса"})
		return
	}
	var err error
	if req.Tag == "" {
		err = h.updater.Apply()
	} else {
		err = h.updater.ApplyVersion(req.Tag)
	}
	if err != nil {
		writeUpdateError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusAccepted, h.updater.State())
}

func (h *UpdateHandler) HandleSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Auto    *bool   `json:"auto"`
		Channel *string `json:"channel"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil || req.Auto == nil && req.Channel == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "неверный формат запроса"})
		return
	}

	if req.Auto != nil {
		if err := h.updater.SetAuto(*req.Auto); err != nil {
			writeUpdateError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if req.Channel != nil {
		if err := h.updater.SetChannel(*req.Channel); err != nil {
			writeUpdateError(w, http.StatusBadRequest, err)
			return
		}
		// The list of versions belongs to the channel. A check that fails is
		// reported by the state itself, the choice is saved either way.
		h.updater.Check(r.Context())
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
