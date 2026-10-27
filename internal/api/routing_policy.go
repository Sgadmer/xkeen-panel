package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"xkeen-panel/internal/xkeen"
)

func (h *Handlers) routingPolicyView() (map[string]interface{}, error) {
	rt := h.detector.Runtime()
	policy, err := xkeen.LoadRoutingPolicy(rt)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"policy": policy, "services": xkeen.RoutingServices(), "core": rt.Core, "profile_active": xkeen.HasActiveProfile(h.config.OutboundsFile)}, nil
}
func (h *Handlers) HandleGetRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	v, err := h.routingPolicyView()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, v)
}
func (h *Handlers) HandlePutRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		xkeen.RoutingPolicy
		Confirm bool `json:"confirm_replace"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(new(interface{})) != io.EOF {
		writeJSON(w, 400, map[string]string{"error": "неверный формат режима маршрутизации"})
		return
	}
	if !req.Confirm {
		writeJSON(w, 400, map[string]string{"error": "подтвердите изменение правил трафика; прежняя политика останется доступна в режиме сохранения"})
		return
	}
	_, err := h.withSubscriptionTransaction(func(snapshot *subscriptionApplySnapshot) (map[string]interface{}, error) {
		rt := h.detector.Runtime()
		if err := xkeen.SetRoutingPolicy(rt, h.config.OutboundsFile, req.RoutingPolicy); err != nil {
			return nil, err
		}
		h.detector.InvalidateTopology()
		if rt.Installed {
			snapshot.runtimeTouched = true
			if err := h.restartManaged(rt.Dispatcher); err != nil {
				return nil, fmt.Errorf("не удалось применить режим маршрутизации")
			}
			if err := h.waitForBalancer(rt); err != nil {
				return nil, err
			}
			if err := h.watchdog.ReapplySelectionLocked(); err != nil {
				return nil, err
			}
		}
		return map[string]interface{}{}, nil
	})
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	h.HandleGetRoutingPolicy(w, r)
}
