package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/cardcontroller"
	"xkeen-panel/internal/trafficjournal"
	"xkeen-panel/internal/version"
)

// The owner's settings as one file: to move them to another router or to put
// them back after a reinstall.
//
// The file holds choices, not secrets: no account, no subscription links, no
// keys, no device identifiers. An import is previewed first and then applied
// section by section through the same checked paths as a change made by hand.
// Whatever lowers protection is a section of its own that is never chosen in
// advance.

const (
	settingsFormat  = "xkeen-panel-settings"
	settingsVersion = 1
)

type settingsFile struct {
	Format         string                   `json:"format"`
	Version        int                      `json:"version"`
	Created        string                   `json:"created,omitempty"`
	Panel          string                   `json:"panel_version,omitempty"`
	Core           string                   `json:"core,omitempty"`
	Settings       *PanelSettings           `json:"panel_settings,omitempty"`
	JournalPresets []trafficjournal.Preset  `json:"journal_presets,omitempty"`
	Cards          *cardcontroller.Portable `json:"cards,omitempty"`
}

// TransferHandler exports and imports the settings.
type TransferHandler struct {
	h        *Handlers
	settings *PanelSettingsHandler
}

func NewTransferHandler(h *Handlers, settings *PanelSettingsHandler) *TransferHandler {
	return &TransferHandler{h: h, settings: settings}
}

func (t *TransferHandler) presets() *trafficjournal.Presets {
	if t.h.journalPresets == nil {
		t.h.journalPresets = trafficjournal.NewPresets(t.h.config.DataDir)
	}
	return t.h.journalPresets
}

func (t *TransferHandler) export() (settingsFile, error) {
	file := settingsFile{Format: settingsFormat, Version: settingsVersion, Created: time.Now().UTC().Format(time.RFC3339), Panel: version.Version}
	if t.h.detector != nil {
		file.Core = t.h.detector.Runtime().Core
	}
	if t.settings != nil {
		current := t.settings.Current()
		file.Settings = &current
	}
	file.JournalPresets = t.presets().List()
	if t.h.Cards != nil {
		cards, err := t.h.Cards.ExportPortable(t.h.config.DataDir)
		if err != nil {
			return settingsFile{}, err
		}
		file.Cards = &cards
	}
	return file, nil
}

func intervalText(minutes int) string {
	if minutes == 0 {
		return "не обновлять"
	}
	return fmt.Sprintf("каждые %d мин", minutes)
}

// ownSections are the parts of the file the panel itself keeps.
func (t *TransferHandler) ownSections(file settingsFile) ([]cardcontroller.ImportSection, PanelSettings, []trafficjournal.Preset) {
	var sections []cardcontroller.ImportSection
	var wanted PanelSettings
	if file.Settings != nil && t.settings != nil {
		section := cardcontroller.ImportSection{ID: "panel_settings", Title: "Подписки и автоматика", Changes: []string{}}
		next, err := normalizePanelSettings(*file.Settings)
		current := t.settings.Current()
		switch {
		case err != nil:
			section.Skipped = append(section.Skipped, err.Error())
		default:
			wanted = next
			if next.RefreshMinutes != current.RefreshMinutes {
				section.Changes = append(section.Changes, "Обновлять подписки: "+intervalText(next.RefreshMinutes))
			}
			if !slices.Equal(next.AvoidCountries, current.AvoidCountries) {
				list := "нет"
				if len(next.AvoidCountries) > 0 {
					list = strings.Join(next.AvoidCountries, ", ")
				}
				section.Changes = append(section.Changes, "Исключенные локации: "+list)
			}
		}
		if len(section.Changes) > 0 || len(section.Skipped) > 0 {
			sections = append(sections, section)
		}
	}
	var added []trafficjournal.Preset
	if len(file.JournalPresets) > 0 {
		have := map[string]bool{}
		for _, preset := range t.presets().List() {
			have[strings.ToLower(preset.Name)] = true
		}
		var names []string
		for _, preset := range file.JournalPresets {
			if name := strings.TrimSpace(preset.Name); name != "" && !have[strings.ToLower(name)] {
				have[strings.ToLower(name)] = true
				preset.ID = ""
				added = append(added, preset)
				names = append(names, name)
			}
		}
		if len(added) > 0 {
			sections = append(sections, cardcontroller.ImportSection{ID: "journal_presets", Title: "Шаблоны журнала",
				Changes: []string{fmt.Sprintf("Добавить шаблоны (%d): %s", len(added), strings.Join(names, ", "))}})
		}
	}
	return sections, wanted, added
}

func checkSettingsFile(file settingsFile) error {
	if file.Format != settingsFormat {
		return errors.New("это не файл настроек панели XKeen")
	}
	if file.Version != settingsVersion {
		return errors.New("файл создан другой версией панели и не может быть прочитан этой")
	}
	return nil
}

func (t *TransferHandler) preview(file settingsFile) ([]cardcontroller.ImportSection, error) {
	if err := checkSettingsFile(file); err != nil {
		return nil, err
	}
	sections, _, _ := t.ownSections(file)
	if file.Cards != nil {
		if t.h.Cards == nil {
			sections = append(sections, cardcontroller.ImportSection{ID: "cards", Title: "Карточки сервисов", Changes: []string{},
				Skipped: []string{"маршруты сервисов, kill switch и исключения из файла относятся к ядру Mihomo; на этом роутере они не применяются"}})
		} else {
			cards, err := t.h.Cards.PreviewImport(t.h.config.DataDir, *file.Cards)
			if err != nil {
				return nil, err
			}
			sections = append(sections, cards...)
		}
	}
	return sections, nil
}

func (t *TransferHandler) apply(ctx context.Context, file settingsFile, chosen []string) ([]cardcontroller.ImportResult, error) {
	if err := checkSettingsFile(file); err != nil {
		return nil, err
	}
	var results []cardcontroller.ImportResult
	sections, wanted, added := t.ownSections(file)
	for _, section := range sections {
		if !slices.Contains(chosen, section.ID) || len(section.Changes) == 0 {
			continue
		}
		result := cardcontroller.ImportResult{ID: section.ID, Title: section.Title, Done: []string{}}
		var err error
		switch section.ID {
		case "panel_settings":
			_, _, err = t.settings.Apply(ctx, wanted)
		case "journal_presets":
			_, err = t.presets().Replace(append(t.presets().List(), added...))
		}
		if err != nil {
			result.Failed = append(result.Failed, err.Error())
		} else {
			result.Done = section.Changes
		}
		results = append(results, result)
	}
	if file.Cards != nil && t.h.Cards != nil {
		cards, err := t.h.Cards.ApplyImport(ctx, t.h.config.DataDir, *file.Cards, chosen)
		results = append(results, cards...)
		if err != nil {
			return results, err
		}
	}
	return results, nil
}

// Mount belongs inside the authenticated API group.
func (t *TransferHandler) Mount(r chi.Router) {
	r.Get("/settings/export", func(w http.ResponseWriter, r *http.Request) {
		file, err := t.export()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, file)
	})
	read := func(w http.ResponseWriter, r *http.Request, into interface{}) bool {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		if decoder.Decode(into) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "файл настроек не читается"})
			return false
		}
		return true
	}
	r.Post("/settings/import/preview", func(w http.ResponseWriter, r *http.Request) {
		var file settingsFile
		if !read(w, r, &file) {
			return
		}
		sections, err := t.preview(file)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if sections == nil {
			sections = []cardcontroller.ImportSection{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"sections": sections, "created": file.Created, "panel_version": file.Panel})
	})
	r.Post("/settings/import/apply", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			File     settingsFile `json:"file"`
			Sections []string     `json:"sections"`
		}
		if !read(w, r, &request) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()
		results, err := t.apply(ctx, request.File, request.Sections)
		if results == nil {
			results = []cardcontroller.ImportResult{}
		}
		body := map[string]interface{}{"results": results}
		if err != nil {
			body["error"] = err.Error()
			writeJSON(w, http.StatusBadRequest, body)
			return
		}
		if t.h.watchdog != nil {
			go t.h.watchdog.CheckNow()
		}
		writeJSON(w, http.StatusOK, body)
	})
}
