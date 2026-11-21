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

	"xkeen-panel/internal/models"
)

// Kept in data/settings.json so config.yaml, comments and all, is never rewritten
type PanelSettings struct {
	AvoidCountries []string `json:"avoid_countries"`
	RefreshMinutes int      `json:"subscription_refresh_minutes"`
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
	return nil
}

type PanelSettingsHandler struct {
	config          *models.Config
	reset           chan<- struct{}
	mu              sync.Mutex
	lockCountries   func()
	unlockCountries func()
	applyCountries  func(context.Context) error
}

func NewPanelSettingsHandler(cfg *models.Config, reset chan<- struct{}) *PanelSettingsHandler {
	return &PanelSettingsHandler{config: cfg, reset: reset}
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

func (h *PanelSettingsHandler) loadRuntime(s PanelSettings) {
	h.config.SetRuntime(s.AvoidCountries, s.RefreshMinutes*60)
}

func (h *PanelSettingsHandler) current() PanelSettings {
	return PanelSettings{
		AvoidCountries: h.config.AvoidCountries(),
		RefreshMinutes: int(h.config.RefreshInterval() / time.Minute),
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
	saved, status, err := h.Apply(r.Context(), req)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

// Current returns the settings in force.
func (h *PanelSettingsHandler) Current() PanelSettings {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.current()
}

// normalizePanelSettings checks the values a request or an imported file carries.
func normalizePanelSettings(req PanelSettings) (PanelSettings, error) {
	seen := map[string]bool{}
	countries := []string{}
	for _, c := range req.AvoidCountries {
		c = strings.ToUpper(strings.TrimSpace(c))
		if !countryCodeRe.MatchString(c) {
			return PanelSettings{}, errors.New("код страны должен состоять из двух латинских букв: " + c)
		}
		if !seen[c] {
			seen[c] = true
			countries = append(countries, c)
		}
	}
	if req.RefreshMinutes != 0 && (req.RefreshMinutes < 5 || req.RefreshMinutes > 1440) {
		return PanelSettings{}, errors.New("интервал обновления — от 5 минут до суток, или 0 чтобы выключить")
	}
	return PanelSettings{AvoidCountries: countries, RefreshMinutes: req.RefreshMinutes}, nil
}

// Apply saves the settings and puts the previous ones back when the country
// filter can not be applied. The status is the HTTP answer for a failure.
func (h *PanelSettingsHandler) Apply(ctx context.Context, req PanelSettings) (PanelSettings, int, error) {
	next, err := normalizePanelSettings(req)
	if err != nil {
		return PanelSettings{}, http.StatusBadRequest, err
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lockCountries != nil {
		h.lockCountries()
		defer h.unlockCountries()
	}

	staged, err := h.stageSettings(next)
	if err != nil {
		return PanelSettings{}, http.StatusInternalServerError, errors.New("не удалось подготовить файл настроек")
	}
	defer os.Remove(staged)
	previous := h.current()
	changed := !slices.Equal(previous.AvoidCountries, next.AvoidCountries)
	h.loadRuntime(next)
	if changed && h.applyCountries != nil {
		err = h.applyCountries(ctx)
	}
	if err == nil {
		err = os.Rename(staged, panelSettingsPath(h.config.DataDir))
	}
	if err != nil {
		h.loadRuntime(previous)
		var restoreErr error
		if changed && h.applyCountries != nil {
			restore, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			restoreErr = h.applyCountries(restore)
			cancel()
		}
		if restoreErr != nil {
			err = errors.Join(err, errors.New("восстановление прежнего фильтра стран не подтверждено"))
		}
		return PanelSettings{}, http.StatusInternalServerError, err
	}

	select {
	case h.reset <- struct{}{}:
	default:
	}

	return h.current(), http.StatusOK, nil
}
