package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"xkeen-panel/internal/geoip"
	"xkeen-panel/internal/models"
)

// Kept in data/settings.json so config.yaml, comments and all, is never rewritten
type PanelSettings struct {
	AvoidCountries []string `json:"avoid_countries"`
	RefreshMinutes int      `json:"subscription_refresh_minutes"`
	ShowFullPath   *bool    `json:"show_full_path,omitempty"`
}

func panelSettingsPath(dataDir string) string {
	return filepath.Join(dataDir, "settings.json")
}

// LoadPanelSettings applies settings saved from the panel over config.yaml.
func LoadPanelSettings(cfg *models.Config) error {
	data, err := os.ReadFile(panelSettingsPath(cfg.DataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var s PanelSettings
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	cfg.SetRuntime(s.AvoidCountries, s.RefreshMinutes*60)
	cfg.HideServerPath = s.ShowFullPath != nil && !*s.ShowFullPath
	return nil
}

type PanelSettingsHandler struct {
	config          *models.Config
	geoip           *geoip.Matcher
	geoPath         string
	reset           chan<- struct{}
	mu              sync.Mutex
	lockCountries   func()
	unlockCountries func()
	applyCountries  func(context.Context) error
}

func NewPanelSettingsHandler(cfg *models.Config, matcher *geoip.Matcher, geoPath string, reset chan<- struct{}) *PanelSettingsHandler {
	return &PanelSettingsHandler{config: cfg, geoip: matcher, geoPath: geoPath, reset: reset}
}

// The live group and the saved preference share the same mutation lock as
// subscription refresh, country overrides and card assignments.
func (h *PanelSettingsHandler) BindCountryPolicy(lock, unlock func(), apply func(context.Context) error) {
	h.lockCountries, h.unlockCountries, h.applyCountries = lock, unlock, apply
}

func (h *PanelSettingsHandler) stageSettings(next PanelSettings) (string, error) {
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(h.config.DataDir, ".settings-*")
	if err != nil {
		return "", err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func (h *PanelSettingsHandler) loadRuntime(s PanelSettings, updateGeo bool) error {
	if updateGeo && h.geoip != nil && h.geoPath != "" {
		if err := h.geoip.Reload(h.geoPath, s.AvoidCountries); err != nil {
			return err
		}
	}
	h.config.SetRuntime(s.AvoidCountries, s.RefreshMinutes*60)
	return nil
}

func (h *PanelSettingsHandler) current() PanelSettings {
	show := !h.config.HideServerPath
	return PanelSettings{
		AvoidCountries: h.config.AvoidCountries(),
		RefreshMinutes: int(h.config.RefreshInterval() / time.Minute),
		ShowFullPath:   &show,
	}
}

// HandleGet — GET /api/panel/settings
func (h *PanelSettingsHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	writeJSON(w, http.StatusOK, h.current())
}

var countryCodeRe = regexp.MustCompile(`^[A-Z]{2}$`)

// HandlePut — PUT /api/panel/settings
func (h *PanelSettingsHandler) HandlePut(w http.ResponseWriter, r *http.Request) {
	var req PanelSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "неверный формат запроса"})
		return
	}

	seen := map[string]bool{}
	countries := []string{}
	for _, c := range req.AvoidCountries {
		c = strings.ToUpper(strings.TrimSpace(c))
		if !countryCodeRe.MatchString(c) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "код страны должен состоять из двух латинских букв: " + c})
			return
		}
		if !seen[c] {
			seen[c] = true
			countries = append(countries, c)
		}
	}
	if req.RefreshMinutes != 0 && (req.RefreshMinutes < 5 || req.RefreshMinutes > 1440) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "интервал обновления — от 5 минут до суток, или 0 чтобы выключить"})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lockCountries != nil {
		h.lockCountries()
		defer h.unlockCountries()
	}

	next := h.current()
	next.AvoidCountries, next.RefreshMinutes = countries, req.RefreshMinutes
	staged, err := h.stageSettings(next)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось подготовить файл настроек"})
		return
	}
	defer os.Remove(staged)
	previous := h.current()
	changed := !slices.Equal(previous.AvoidCountries, next.AvoidCountries)
	if err := h.loadRuntime(next, changed); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось прочитать GeoIP для выбранных стран"})
		return
	}
	if changed && h.applyCountries != nil {
		err = h.applyCountries(r.Context())
	}
	if err == nil {
		err = os.Rename(staged, panelSettingsPath(h.config.DataDir))
	}
	if err != nil {
		restoreErr := h.loadRuntime(previous, changed)
		if restoreErr == nil && changed && h.applyCountries != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			restoreErr = h.applyCountries(ctx)
			cancel()
		}
		if restoreErr != nil {
			err = errors.Join(err, errors.New("восстановление прежнего фильтра стран не подтверждено"))
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	select {
	case h.reset <- struct{}{}:
	default:
	}

	writeJSON(w, http.StatusOK, h.current())
}

// Save only the display setting. An old tab must never overwrite newer routes or refresh settings.
func (h *PanelSettingsHandler) HandleAppearance(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Show *bool `json:"show_full_path"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Show == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Укажите режим отображения пути"})
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	next := h.current()
	next.ShowFullPath = req.Show
	staged, err := h.stageSettings(next)
	if err == nil {
		defer os.Remove(staged)
		err = os.Rename(staged, panelSettingsPath(h.config.DataDir))
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Не удалось сохранить вид маршрута"})
		return
	}
	h.config.HideServerPath = !*req.Show
	writeJSON(w, http.StatusOK, next)
}
