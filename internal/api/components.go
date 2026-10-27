package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"time"

	"xkeen-panel/internal/components"
	"xkeen-panel/internal/xkeen"
)

// ComponentsHandler is constructed once per server, next to the other
// authenticated REST handlers. It owns the short-lived previews and job state.
type ComponentsHandler struct{ manager *components.Manager }

func NewComponentsHandler(h *Handlers) *ComponentsHandler {
	manager := components.New(components.Options{
		DataDir: h.config.DataDir, Root: h.detector.Root, Runtime: h.detector.Runtime,
		Lock: h.watchdog.LockChanges, Unlock: h.watchdog.UnlockChanges,
		Running: func() bool { return xkeen.IsRunning(h.detector.Runtime().Core) },
		Restart: func(ctx context.Context) error {
			rt := h.detector.Runtime()
			if e := h.restartManaged(rt.Dispatcher); e != nil {
				return e
			}
			h.detector.InvalidateTopology()
			if e := h.waitForBalancer(rt); e != nil {
				return e
			}
			if e := h.watchdog.ReapplySelectionLocked(); e != nil {
				return e
			}
			// The caller already holds LockChanges. Check the running selection
			// through its forced SOCKS input directly: CheckNow would reacquire
			// that lock, and a direct router request would not test the new core.
			if e := componentsHTTPSCheck(ctx, h.watchdog.ProbeAddress(), h.config.CheckURL); e != nil {
				return e
			}
			if h.geoip != nil {
				_ = h.geoip.Reload(h.config.GeoIPPath, h.config.AvoidCountries())
			}
			return nil
		},
		Firmware: func() string { return componentsFirmware(h.detector.Runtime().XkeenJSON) },
		Log:      h.watchdog.Log,
	})
	handler := &ComponentsHandler{manager: manager}
	if runtime.GOOS == "linux" && h.detector.Root == "" {
		go manager.Start(context.Background())
	}
	return handler
}

func componentsHTTPSCheck(ctx context.Context, probeAddr, target string) error {
	host, port, e := net.SplitHostPort(probeAddr)
	ip := net.ParseIP(host)
	if e != nil || ip == nil || !ip.IsLoopback() || port == "" {
		return fmt.Errorf("проверочный вход текущего VPN недоступен; обновление не подтверждено")
	}
	u, e := url.Parse(target)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		// A historical HTTP check URL must not downgrade this installation
		// acceptance check. This is also the endpoint used by native probes.
		target = "https://www.gstatic.com/generate_204"
	}
	proxy := &url.URL{Scheme: "socks5", Host: probeAddr}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return componentsHTTPSRequest(ctx, client, target)
}

func componentsHTTPSRequest(ctx context.Context, client *http.Client, target string) error {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if e != nil {
		return fmt.Errorf("не удалось подготовить HTTPS-проверку VPN")
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; xkeen-panel health check)")
	resp, e := client.Do(req)
	if e != nil {
		// Neither the configured URL nor underlying proxy errors are exposed.
		return fmt.Errorf("текущий VPN не прошёл HTTPS-проверку после перезапуска")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("текущий VPN не прошёл HTTPS-проверку после перезапуска (HTTP %d)", resp.StatusCode)
	}
	return nil
}

func componentsFirmware(configPath string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:79/rci/show/version", nil)
	if e != nil {
		return ""
	}
	// The RCI token is used only for this loopback call, never returned to the UI.
	if b, e := os.ReadFile(configPath); e == nil {
		var config map[string]interface{}
		if json.Unmarshal(b, &config) == nil {
			if token, ok := config["rci_token"].(string); ok && token != "" {
				req.Header.Set("X-Ndma-Tkn", token)
			}
		}
	}
	client := http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var body struct {
		Release string `json:"release"`
		Title   string `json:"title"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body) != nil {
		return ""
	}
	version := regexp.MustCompile(`[0-9]+\.[0-9]+(?:\.[0-9]+)?`).FindString(body.Release)
	if version == "" {
		version = regexp.MustCompile(`[0-9]+\.[0-9]+(?:\.[0-9]+)?`).FindString(body.Title)
	}
	return version
}

func (h *ComponentsHandler) HandleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.manager.State())
}
func (h *ComponentsHandler) HandleReleases(w http.ResponseWriter, r *http.Request) {
	channel := r.URL.Query().Get("channel")
	if channel == "" {
		channel = "stable"
	}
	releases, e := h.manager.Releases(r.Context(), r.URL.Query().Get("component"), channel)
	if e != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": e.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"releases": releases})
}
func componentRequest(w http.ResponseWriter, r *http.Request, value interface{}) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(value); e != nil {
		return e
	}
	if e := decoder.Decode(new(interface{})); e != io.EOF {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (h *ComponentsHandler) HandlePreview(w http.ResponseWriter, r *http.Request) {
	var req components.PlanRequest
	if componentRequest(w, r, &req) != nil {
		writeJSON(w, 400, map[string]string{"error": "неверный формат операции"})
		return
	}
	plan, e := h.manager.Preview(r.Context(), req)
	if e != nil {
		writeJSON(w, 400, map[string]string{"error": e.Error()})
		return
	}
	writeJSON(w, 200, plan)
}
func (h *ComponentsHandler) HandleApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PlanID string `json:"plan_id"`
	}
	if componentRequest(w, r, &req) != nil {
		writeJSON(w, 400, map[string]string{"error": "неверный формат операции"})
		return
	}
	job, e := h.manager.Apply(req.PlanID)
	if e != nil {
		writeJSON(w, 409, map[string]string{"error": e.Error()})
		return
	}
	writeJSON(w, 202, job)
}
func (h *ComponentsHandler) HandleRollback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BackupID string `json:"backup_id"`
	}
	if componentRequest(w, r, &req) != nil {
		writeJSON(w, 400, map[string]string{"error": "неверный формат отката"})
		return
	}
	job, e := h.manager.Rollback(req.BackupID)
	if e != nil {
		writeJSON(w, 409, map[string]string{"error": e.Error()})
		return
	}
	writeJSON(w, 202, job)
}
func (h *ComponentsHandler) HandleGeodata(w http.ResponseWriter, r *http.Request) {
	var req components.GeoSettings
	if componentRequest(w, r, &req) != nil {
		writeJSON(w, 400, map[string]string{"error": "неверные настройки геобаз"})
		return
	}
	if e := h.manager.SetGeodata(req); e != nil {
		writeJSON(w, 400, map[string]string{"error": e.Error()})
		return
	}
	writeJSON(w, 200, h.manager.State())
}
