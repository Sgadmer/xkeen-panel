package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

// ServersView is how the owner left the Servers screen. It lives on the
// router, so every device and every new sign-in opens the screen the same way.
type ServersView struct {
	Tab            string `json:"tab"`
	CountryOrder   string `json:"country_order"`
	Country        string `json:"country"`
	OnlyResponding bool   `json:"only_responding"`
}

var serversViewMu sync.Mutex
var countryCode = regexp.MustCompile(`^[A-Z]{2}$`)

func defaultServersView() ServersView {
	return ServersView{Tab: "pool", CountryOrder: "name-asc", Country: "all"}
}

// normalize keeps only known values; anything else falls back to the default.
func (v ServersView) normalize() ServersView {
	d := defaultServersView()
	if v.Tab != "pool" && v.Tab != "all" {
		v.Tab = d.Tab
	}
	if v.CountryOrder != "name-asc" && v.CountryOrder != "name-desc" && v.CountryOrder != "latency" {
		v.CountryOrder = d.CountryOrder
	}
	if v.Country != "all" && v.Country != "—" && !countryCode.MatchString(v.Country) {
		v.Country = d.Country
	}
	return v
}

func (h *Handlers) serversViewPath() string {
	return filepath.Join(h.config.DataDir, "ui-servers.json")
}

// HandleServersView — GET/PUT /api/ui/servers
func (h *Handlers) HandleServersView(w http.ResponseWriter, r *http.Request) {
	serversViewMu.Lock()
	defer serversViewMu.Unlock()
	path := h.serversViewPath()
	if r.Method == http.MethodPut {
		var view ServersView
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&view); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "некорректные настройки экрана"})
			return
		}
		view = view.normalize()
		raw, _ := json.Marshal(view)
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, raw, 0600); err != nil || os.Rename(tmp, path) != nil {
			os.Remove(tmp)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось сохранить настройки экрана"})
			return
		}
		writeJSON(w, http.StatusOK, view)
		return
	}
	view := defaultServersView()
	if raw, err := os.ReadFile(path); err == nil {
		var saved ServersView
		if json.Unmarshal(raw, &saved) == nil {
			view = saved.normalize()
		}
	}
	writeJSON(w, http.StatusOK, view)
}
