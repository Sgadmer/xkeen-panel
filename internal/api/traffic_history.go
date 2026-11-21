package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/trafficjournal"
	"xkeen-panel/internal/trafficlog"
)

// journalQuery reads the filters shared by the journal endpoints.
func journalQuery(query url.Values) (trafficlog.Query, bool) {
	limit := 50
	if value := query.Get("limit"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 100 {
			return trafficlog.Query{}, false
		}
		limit = n
	}
	kind := query.Get("kind")
	q := trafficlog.Query{Device: query.Get("device"), Service: query.Get("service"), Kind: kind, Search: query.Get("q"), Cursor: query.Get("cursor"), Limit: limit}
	if len(q.Device) > 80 || len(q.Service) > 40 || len(q.Kind) > 24 || len(q.Search) > 128 || len(q.Cursor) > 512 || strings.ContainsAny(q.Search, "\x00\r\n") {
		return q, false
	}
	for name, target := range map[string]*time.Time{"since": &q.Since, "before": &q.Before} {
		if value := query.Get(name); value != "" {
			at, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return q, false
			}
			*target = at
		}
	}
	return q, true
}

// MountTrafficHistory is called inside the existing authenticated API group.
// Disk operations deliberately do not hold the VPN configuration lock.
func (h *Handlers) MountTrafficHistory(r chi.Router) {
	dataDir := ""
	if h.config != nil {
		dataDir = h.config.DataDir
	}
	if h.journalPresets == nil {
		h.journalPresets = trafficjournal.NewPresets(dataDir)
	}
	presets := h.journalPresets
	status := func() trafficjournal.Settings {
		if h.History != nil {
			settings := h.History.Status()
			if (settings.Enabled || settings.RecentEnabled) && h.Cards != nil && settings.Error == "" {
				guard := h.Cards.GuardEvents()
				if !guard.Running || !guard.Complete {
					settings.Error = "Поток событий Mihomo пока неполный. Журнал может содержать пропуски."
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
		if dec.Decode(&patch) != nil || dec.Decode(&struct{}{}) != io.EOF || patch.Empty() {
			writeJSON(w, 400, map[string]string{"error": "Не удалось прочитать настройки истории."})
			return
		}
		// INFO supplies actual short-lived connection attempts. A disk toggle
		// changes verbosity only; service selections and routing mode survive.
		if err := h.History.ValidatePatch(patch); err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
		wanted := patch.Enabled != nil && *patch.Enabled || patch.RecentOff != nil && !*patch.RecentOff
		if wanted && h.Cards != nil {
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
		q, ok := journalQuery(r.URL.Query())
		if !ok {
			writeJSON(w, 400, map[string]string{"error": "Недопустимые фильтры истории."})
			return
		}
		page := trafficlog.Page{Events: []trafficlog.Entry{}}
		devices := []trafficlog.Device{}
		if h.History != nil {
			// "recent" is the short journal in memory; the default is the
			// day-long journal on the disk.
			if r.URL.Query().Get("source") == "recent" {
				page, devices = h.History.QueryRecent(q)
			} else {
				var err error
				page, devices, err = h.History.Query(r.Context(), q)
				if err != nil {
					writeJSON(w, 409, map[string]string{"error": "История сейчас недоступна. Проверьте накопитель или фильтры."})
					return
				}
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
	// The short journal grouped by address: what was reached, how often and
	// which way the traffic went.
	r.Get("/traffic-history/sites", func(w http.ResponseWriter, r *http.Request) {
		q, ok := journalQuery(r.URL.Query())
		if !ok {
			writeJSON(w, 400, map[string]string{"error": "Недопустимые фильтры истории."})
			return
		}
		sites := []trafficjournal.Site{}
		if h.History != nil {
			sites = h.History.Sites(q)
		}
		writeJSON(w, 200, map[string]interface{}{"sites": sites, "status": status()})
	})
	r.Get("/journal/presets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{"presets": presets.List()})
	})
	r.Put("/journal/presets", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Presets []trafficjournal.Preset `json:"presets"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
		dec.DisallowUnknownFields()
		if dec.Decode(&body) != nil || dec.Decode(&struct{}{}) != io.EOF || body.Presets == nil {
			writeJSON(w, 400, map[string]string{"error": "Не удалось прочитать шаблоны."})
			return
		}
		saved, err := presets.Replace(body.Presets)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"presets": saved})
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
