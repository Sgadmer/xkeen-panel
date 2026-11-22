package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"

	"xkeen-panel/internal/keenetic"
	"xkeen-panel/internal/monitor"
	"xkeen-panel/internal/updater"
	"xkeen-panel/internal/xkeen"
)

type SetupHandler struct {
	// Set by the server; nil in a build or a test without the updater.
	Updater      *updater.Updater
	detector     *xkeen.Detector
	subscription *xkeen.SubscriptionManager
	watchdog     *monitor.Watchdog
	devices      *DevicesHandler
}

func NewSetupHandler(det *xkeen.Detector, sub *xkeen.SubscriptionManager, wd *monitor.Watchdog, devices *DevicesHandler) *SetupHandler {
	return &SetupHandler{detector: det, subscription: sub, watchdog: wd, devices: devices}
}

// SetupState is what the first-run wizard still has to do on this router.
type SetupState struct {
	XKeenInstalled        bool   `json:"xkeen_installed"`
	XKeenVersion          string `json:"xkeen_version"`
	Core                  string `json:"core"`
	CoreRunning           bool   `json:"core_running"`
	Autostart             bool   `json:"autostart"`
	Subscription          bool   `json:"subscription"`
	Servers               int    `json:"servers"`
	Configured            bool   `json:"configured"`
	RoutingModeConfigured bool   `json:"routing_mode_configured"`
	PoolNodes             int    `json:"pool_nodes"`
	RouterAPI             bool   `json:"router_api"`
	PolicyFound           bool   `json:"policy_found"`
	DevicesInVPN          int    `json:"devices_in_vpn"`
	NewDevicesVPN         bool   `json:"new_devices_vpn"`
	Watchdog              bool   `json:"watchdog"`
	Complete              bool   `json:"complete"`
	// Defaults the last step still offers. Each is offered on a first setup
	// only: a router that already has its own choice is left as it is.
	OfferProxyPorts bool     `json:"offer_proxy_ports"`
	OfferAutoUpdate bool     `json:"offer_auto_update"`
	ProxyPorts      []string `json:"proxy_ports"`
}

func (h *SetupHandler) state() SetupState {
	h.detector.InvalidateTopology()
	rt := h.detector.Runtime()
	top := h.detector.Topology()
	data := h.subscription.GetData()
	_, routingStateErr := os.Stat(xkeen.RoutingPolicyPath(rt))
	_, routingPolicyErr := xkeen.LoadRoutingPolicy(rt)

	s := SetupState{
		XKeenInstalled: rt.Installed,
		XKeenVersion:   rt.Version,
		Core:           rt.Core,
		CoreRunning:    rt.Installed && xkeen.IsRunning(rt.Core),
		Autostart:      rt.Autostart,
		Subscription:   data.URL != "" || len(data.Servers) > 0,
		Servers:        len(data.Servers),
		// Mihomo keeps its proxies in its own config, which the subscription sync fills
		Configured:            rt.Core == xkeen.CoreMihomo || len(top.ProxyTags) > 0,
		RoutingModeConfigured: rt.Core != xkeen.CoreXray || routingStateErr == nil && routingPolicyErr == nil,
		PoolNodes:             len(top.PoolTags),
		Watchdog:              h.watchdog.IsActive(),
		ProxyPorts:            xkeen.DefaultProxyPorts,
	}
	// XKeen reads its port lists when it starts: the ports are offered only
	// while it has never been started with the owner's own choice.
	s.OfferProxyPorts = s.XKeenInstalled && !s.CoreRunning && xkeen.ProxyPortsUnset(rt)
	s.OfferAutoUpdate = h.Updater != nil && h.Updater.AutoOffered()

	c := h.devices.client()
	if policies, err := c.Policies(); err == nil {
		s.RouterAPI = true
		policy, found := keenetic.XKeenPolicy(policies)
		s.PolicyFound = found
		if found {
			if hosts, err := c.Hosts(); err == nil {
				if cfg, err := c.HotspotConfig(); err == nil {
					for _, d := range keenetic.Devices(hosts, cfg, policy.Name) {
						if d.VPN {
							s.DevicesInVPN++
						}
					}
					s.NewDevicesVPN = cfg.NewDevicesVPN(policy.Name)
				}
			}
		}
	}

	s.Complete = s.XKeenInstalled && s.Subscription && s.Configured &&
		s.PolicyFound && s.CoreRunning && s.Autostart
	return s
}

// HandleState — GET /api/setup/state
func (h *SetupHandler) HandleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.state())
}

// HandlePolicy — POST /api/setup/policy
func (h *SetupHandler) HandlePolicy(w http.ResponseWriter, r *http.Request) {
	if _, err := h.devices.client().CreateXKeenPolicy(); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, h.state())
}

// HandleFinish — POST /api/setup/finish. The installer leaves autostart off until a working config exists
func (h *SetupHandler) HandleFinish(w http.ResponseWriter, r *http.Request) {
	rt := h.detector.Runtime()
	if !rt.Installed {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "XKeen не установлен"})
		return
	}
	// The defaults of a first setup, as the owner left them in the wizard.
	// A missing field changes nothing.
	var req struct {
		ProxyPorts *bool `json:"proxy_ports"`
		AutoUpdate *bool `json:"auto_update"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "неверный формат запроса"})
		return
	}
	if req.ProxyPorts != nil && *req.ProxyPorts && !xkeen.IsRunning(rt.Core) {
		if _, err := xkeen.ApplyDefaultProxyPorts(rt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось записать список портов: " + err.Error()})
			return
		}
	}

	if !rt.Autostart {
		if _, err := xkeen.SetAutostart(rt.Dispatcher, true); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось включить автозапуск XKeen; проверьте локальный журнал роутера"})
			return
		}
	}
	if !xkeen.IsRunning(rt.Core) {
		if _, err := xkeen.Start(rt.Dispatcher); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось запустить XKeen; проверьте локальный журнал роутера"})
			return
		}
	}
	if !h.watchdog.IsActive() {
		h.watchdog.SetActive(true)
	}
	h.watchdog.CheckNow()
	if req.AutoUpdate != nil && h.Updater != nil && h.Updater.AutoOffered() {
		if err := h.Updater.SetAutoDefault(*req.AutoUpdate); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось сохранить настройку обновлений: " + err.Error()})
			return
		}
	}

	writeJSON(w, http.StatusOK, h.state())
}
