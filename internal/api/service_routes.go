package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"xkeen-panel/internal/xkeen"
)

func (h *Handlers) HandleGetServiceRoutes(w http.ResponseWriter, r *http.Request) {
	h.watchdog.LockChanges()
	defer h.watchdog.UnlockChanges()
	view, err := xkeen.ReadServiceRoutes(h.detector.Runtime(), h.subscription.GetServers())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, view)
}

func (h *Handlers) HandlePutServiceRoutes(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServiceID string  `json:"service_id"`
		TargetID  *string `json:"target_id"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(new(interface{})) != io.EOF || req.ServiceID == "" || req.TargetID == nil {
		writeJSON(w, 400, map[string]string{"error": "укажите сервис и выбранную цель"})
		return
	}
	_, err := h.applyServiceRouteChange(req.ServiceID, *req.TargetID)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	h.HandleGetServiceRoutes(w, r)
}

func (h *Handlers) applyServiceRouteChange(service, target string) (map[string]interface{}, error) {
	return h.withSubscriptionTransaction(func(tx *subscriptionApplySnapshot) (map[string]interface{}, error) {
		rt := h.detector.Runtime()
		servers := h.subscription.GetServers()
		changed, err := xkeen.ReconcileServiceRoutes(rt, h.config.OutboundsFile, servers, service, target)
		if err != nil {
			return nil, err
		}
		if changed {
			tx.runtimeTouched = true
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
		if !xkeen.ServiceGuardReady(rt) || !xkeen.IsRunning(rt.Core) {
			return nil, errors.New("работа защищённого маршрута не подтверждена")
		}
		// Prune only after the reload, never while the previous route can
		// still point at an isolated worker that's being replaced.
		if err := xkeen.PruneInactiveServiceProfiles(rt, servers); err != nil {
			h.watchdog.Log("Не удалось убрать неиспользуемый процесс профиля")
		}
		return map[string]interface{}{}, nil
	})
}

func (h *Handlers) InitializeServiceRoutes() error {
	rt := h.detector.Runtime()
	if !xkeen.ServiceRoutesArmed(rt) {
		return nil
	}
	_, err := h.applyServiceRouteChange("", "")
	return err
}
