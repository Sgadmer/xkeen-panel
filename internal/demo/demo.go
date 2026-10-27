// Package demo serves the actual frontend with synthetic, in-memory responses.
// It never reads router state or executes component operations.
package demo

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"xkeen-panel/internal/components"
)

type object = map[string]interface{}

func Handler(frontend fs.FS) http.Handler {
	status := object{"connected": true, "internet": true, "proxy_checked": true, "xray_running": true, "restarting": false, "current_server": "Нидерланды · основной", "protocol": "vless", "latency_ms": 48, "uptime": "2 д 4 ч", "last_check": time.Now().UTC().Format(time.RFC3339), "watchdog_active": true, "panel_version": "v3.0.0-beta.3", "core": "xray", "mode": "TProxy", "xkeen_version": "2.1 Stable", "generation": 2}
	servers := []object{{"id": 0, "name": "Нидерланды · основной", "address": "nl.example.com", "port": 443, "protocol": "vless", "active": true, "latency_ms": 48, "country": "NL", "probe_kind": "https"}, {"id": 1, "name": "Германия · резервный", "address": "de.example.com", "port": 443, "protocol": "vless", "active": false, "latency_ms": 61, "country": "DE", "probe_kind": "https"}, {"id": 2, "name": "Финляндия", "address": "fi.example.com", "port": 443, "protocol": "vless", "active": false, "latency_ms": 74, "country": "FI", "probe_kind": "https"}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path == "/api/events" {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: status\ndata: %s\n\n", mustJSON(status))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			<-r.Context().Done()
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodPost && r.URL.Path == "/api/components/preview" {
				demoSettingsPreview(w, r)
				return
			}
			if r.Method != "GET" {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(object{"error": "Демонстрационный режим: изменения отключены"})
				return
			}
			var data interface{}
			switch r.URL.Path {
			case "/api/auth/status":
				data = object{"setup_required": false}
			case "/api/status":
				data = status
			case "/api/servers":
				data = object{"servers": servers}
			case "/api/subscription":
				data = object{"configured": true, "host": "subscription.example.com", "source_kind": "subscription", "can_refresh": true, "last_updated": time.Now().Add(-12 * time.Minute).UTC().Format(time.RFC3339), "server_count": 3, "import_report": object{"imported": 3, "skipped_composite": 0, "skipped_unsupported": 0}}
			case "/api/pool":
				data = object{"mode": "pool", "core": "xray", "api_available": true, "pinned_tag": "sub-0", "current_tag": "sub-0", "pool_tags": []string{"sub-0", "sub-1"}, "proxy_tags": []string{"sub-0", "sub-1"}, "pin_manual": true, "nodes": []object{{"tag": "sub-0", "server_id": 0, "name": "Нидерланды · основной", "address": "nl.example.com", "port": 443, "country": "NL", "latency_ms": 48}, {"tag": "sub-1", "server_id": 1, "name": "Германия · резервный", "address": "de.example.com", "port": 443, "country": "DE", "latency_ms": 61}}}
			case "/api/sites":
				data = object{"unavailable": "", "sites": []object{}}
			case "/api/devices":
				data = object{"policy_found": true, "policy": object{"name": "xkeen", "description": "Устройства VPN"}, "new_devices_vpn": false, "devices": []object{{"mac": "02:00:00:00:00:01", "name": "Мой компьютер", "ip": "192.0.2.10", "active": true, "registered": true, "vpn": true}, {"mac": "02:00:00:00:00:02", "name": "iPhone", "ip": "192.0.2.11", "active": true, "registered": true, "vpn": true}, {"mac": "02:00:00:00:00:03", "name": "Телевизор", "ip": "192.0.2.12", "active": false, "registered": true, "vpn": false}}}
			case "/api/exclusions":
				data = object{"entries": []object{{"id": "demo-bank", "type": "domain", "value": "domain:bank.example.com", "comment": "Банк — напрямую"}, {"id": "demo-shop", "type": "domain", "value": "domain:shop.example.com", "comment": "Приложение магазина"}, {"id": "demo-network", "type": "ip", "value": "192.0.2.0/24", "comment": "Пример подсети"}}}
			case "/api/panel/settings":
				data = object{"subscription_refresh_minutes": 60, "avoid_countries": []string{"RU", "BY"}}
			case "/api/account/passkey":
				data = object{"passkeys": []string{}}
			case "/api/update":
				data = object{"locked": false, "repository": "Sgadmer/xkeen-panel", "channel": "preview", "current": "v3.0.0-beta.3", "latest": object{"tag": "v3.0.0-beta.3", "prerelease": true, "url": "https://github.com/Sgadmer/xkeen-panel/releases/tag/v3.0.0-beta.3"}, "supported": true, "available": false, "auto": false, "auto_hour": 4, "last_check": time.Now().UTC().Format(time.RFC3339)}
			case "/api/setup/state":
				data = object{"xkeen_installed": true, "xkeen_version": "2.1 Stable", "core": "xray", "core_running": true, "autostart": true, "subscription": true, "servers": 3, "configured": true, "pool_nodes": 2, "router_api": true, "policy_found": true, "devices_in_vpn": 2, "new_devices_vpn": false, "watchdog": true, "complete": true, "routing_mode_configured": true}
			case "/api/logs":
				stamp := time.Now().Format("2006-01-02 15:04:05")
				data = object{"lines": []string{stamp + " [DEMO] HTTPS через основной сервер: успешно", stamp + " [DEMO] Исключения направляются напрямую", stamp + " [DEMO] Подписка обновлена"}}
			case "/api/access":
				data = object{"url": "http://router.example:3000/", "qr": demoQR()}
			case "/api/components":
				data = object{"supported": true, "architecture": "arm64", "xkeen_version": "2.1 Stable", "xray_version": "26.3.27", "mode": "TProxy", "core": "xray", "router_time": time.Now().Format(time.RFC3339), "geodata": object{"sources": []string{"geosite-v2fly", "geoip-v2fly"}, "auto": false, "day": -1, "hour": 4, "minute": 0}, "sources": components.GeoSources(), "backups": []object{}, "notes": []string{}, "settings": demoSettings()}
			case "/api/components/releases":
				data = object{"releases": []object{{"tag_name": "v26.3.27", "name": "Пример стабильного релиза", "prerelease": false}}}
			case "/api/routing-mode":
				data = object{"policy": object{"mode": "selected", "services": []string{"youtube", "telegram"}, "addresses": []string{}}, "services": []object{{"id": "youtube", "name": "YouTube", "domains": []string{"domain:youtube.com"}}, {"id": "telegram", "name": "Telegram", "domains": []string{"domain:telegram.org"}}, {"id": "discord", "name": "Discord", "domains": []string{"domain:discord.com"}}}, "core": "xray", "profile_active": false}
			default:
				data = object{}
			}
			json.NewEncoder(w).Encode(data)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		body, err := fs.ReadFile(frontend, path)
		if err != nil {
			path = "index.html"
			body, err = fs.ReadFile(frontend, path)
		}
		if err != nil {
			http.Error(w, "build frontend first", 500)
			return
		}
		if path == "index.html" {
			body = []byte(strings.Replace(string(body), "<head>", "<head><script>localStorage.setItem('xkeen_token','synthetic-demo-session')</script>", 1))
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		} else if strings.HasSuffix(path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		} else if strings.HasSuffix(path, ".css") {
			w.Header().Set("Content-Type", "text/css")
		}
		w.Write(body)
	})
}

func mustJSON(value interface{}) string { body, _ := json.Marshal(value); return string(body) }

func demoQR() string {
	code, _ := qr.Encode("http://router.example:3000/", qr.M, qr.Auto)
	code, _ = barcode.Scale(code, 256, 256)
	var buffer bytes.Buffer
	_ = png.Encode(&buffer, code)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buffer.Bytes())
}
