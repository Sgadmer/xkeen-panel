package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/trafficjournal"
	"xkeen-panel/internal/trafficlog"
)

// MountTrafficHistory is called inside the existing authenticated API group.
// Disk operations deliberately do not hold the VPN configuration lock.
func (h *Handlers) MountTrafficHistory(r chi.Router) {
	status := func() trafficjournal.Settings {
		if h.History != nil {
			settings := h.History.Status()
			if settings.Enabled && h.Cards != nil && settings.Error == "" {
				guard := h.Cards.GuardEvents()
				if !guard.Running || !guard.Complete {
					settings.Error = "Поток событий Mihomo пока неполный. История может содержать пропуски."
				}
			}
			return settings
		}
		return trafficjournal.Settings{Status: trafficlog.Status{Error: "Для истории соединений нужен работающий контроллер Mihomo.", RetentionHours: 24}, Storages: []trafficjournal.Volume{}}
	}
	r.Get("/traffic-history/settings", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, status()) })
	r.Put("/traffic-history/settings", func(w http.ResponseWriter, r *http.Request) {
		if h.History == nil {
			writeJSON(w, 409, map[string]string{"error": "История соединений недоступна для текущего ядра."})
			return
		}
		var patch trafficjournal.Patch
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if dec.Decode(&patch) != nil || dec.Decode(&struct{}{}) != io.EOF || patch.Enabled == nil && patch.Path == nil && patch.StorageID == nil && patch.MaxBytes == nil && patch.MaxEvents == nil && patch.MaxDeviceEvents == nil {
			writeJSON(w, 400, map[string]string{"error": "Не удалось прочитать настройки истории."})
			return
		}
		// INFO supplies actual short-lived connection attempts. A disk toggle
		// changes verbosity only; service selections and routing mode survive.
		if err := h.History.ValidatePatch(patch); err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
		if patch.Enabled != nil && *patch.Enabled && h.Cards != nil {
			if err := h.Cards.EnsureTrafficLogging(r.Context()); err != nil {
				writeJSON(w, 409, map[string]string{"error": "Не удалось включить полный поток событий. Прежние настройки сохранены."})
				return
			}
		}
		if _, err := h.History.Apply(r.Context(), patch); err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, status())
	})
	r.Get("/traffic-history", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		limit := 50
		if value := query.Get("limit"); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 100 {
				writeJSON(w, 400, map[string]string{"error": "Недопустимый размер страницы истории."})
				return
			}
			limit = n
		}
		q := trafficlog.Query{Device: query.Get("device"), Service: query.Get("service"), Kind: query.Get("kind"), Search: query.Get("q"), Cursor: query.Get("cursor"), Limit: limit}
		if len(q.Device) > 80 || len(q.Service) > 40 || len(q.Kind) > 24 || len(q.Search) > 256 || len(q.Cursor) > 2048 || strings.ContainsAny(q.Search, "\x00\r\n") {
			writeJSON(w, 400, map[string]string{"error": "Недопустимые фильтры истории."})
			return
		}
		page := trafficlog.Page{Events: []trafficlog.Entry{}}
		devices := []trafficlog.Device{}
		if h.History != nil {
			var err error
			page, devices, err = h.History.Query(r.Context(), q)
			if err != nil {
				writeJSON(w, 409, map[string]string{"error": "История сейчас недоступна. Проверьте накопитель или фильтры."})
				return
			}
		}
		writeJSON(w, 200, struct {
			Events     []trafficlog.Entry      `json:"events"`
			NextCursor string                  `json:"next_cursor,omitempty"`
			HasMore    bool                    `json:"has_more"`
			Status     trafficjournal.Settings `json:"status"`
			Devices    []trafficlog.Device     `json:"devices"`
		}{page.Events, page.NextCursor, page.HasMore, status(), devices})
	})
}

// One bounded firmware request refreshes identities in the background. Each
// log event uses the cached MAC mapping, never a request to the router API.
func (h *DevicesHandler) TrafficIdentities() []trafficjournal.DeviceIdentity {
	hosts, err := h.client().Hosts()
	if err != nil {
		return nil
	}
	result := make([]trafficjournal.DeviceIdentity, 0, len(hosts))
	for _, host := range hosts {
		if !host.Active || host.IP == "" {
			continue
		}
		name := host.Name
		if name == "" {
			name = host.Hostname
		}
		result = append(result, trafficjournal.DeviceIdentity{IP: host.IP, MAC: host.MAC, Name: name})
	}
	return result
}
