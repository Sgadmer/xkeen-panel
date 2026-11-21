package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/cardcontroller"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/trafficjournal"
)

func transferFixture(t *testing.T) (*TransferHandler, *chi.Mux) {
	t.Helper()
	cfg := &models.Config{DataDir: t.TempDir()}
	transfer := NewTransferHandler(&Handlers{config: cfg}, NewPanelSettingsHandler(cfg, make(chan struct{}, 1)))
	router := chi.NewRouter()
	transfer.Mount(router)
	return transfer, router
}

func TestSettingsFileIsPreviewedThenApplied(t *testing.T) {
	transfer, router := transferFixture(t)
	post := func(path string, body interface{}) (int, map[string]json.RawMessage) {
		t.Helper()
		raw, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw)))
		answer := map[string]json.RawMessage{}
		_ = json.Unmarshal(w.Body.Bytes(), &answer)
		return w.Code, answer
	}
	sectionsOf := func(answer map[string]json.RawMessage) []cardcontroller.ImportSection {
		var sections []cardcontroller.ImportSection
		_ = json.Unmarshal(answer["sections"], &sections)
		return sections
	}

	// What is not a settings file of this version is refused outright.
	for name, file := range map[string]interface{}{
		"another format":  map[string]interface{}{"format": "something", "version": 1},
		"another version": map[string]interface{}{"format": settingsFormat, "version": 99},
		"not an object":   []int{1, 2},
	} {
		if code, _ := post("/settings/import/preview", file); code != http.StatusBadRequest {
			t.Errorf("%s: preview answered %d", name, code)
		}
		if code, _ := post("/settings/import/apply", map[string]interface{}{"file": file, "sections": []string{"panel_settings"}}); code != http.StatusBadRequest {
			t.Errorf("%s: apply answered %d", name, code)
		}
	}

	file := settingsFile{Format: settingsFormat, Version: settingsVersion,
		Settings:       &PanelSettings{AvoidCountries: []string{"ru", "BY", "ru"}, RefreshMinutes: 30},
		JournalPresets: []trafficjournal.Preset{{ID: "foreign-id", Name: "Блокировки", Source: "recent", View: "list", Kind: "kill_switch"}},
		// The cards belong to the Mihomo controller, which this router does not have.
		Cards: &cardcontroller.Portable{RoutingMode: "blocklist"},
	}
	code, answer := post("/settings/import/preview", file)
	sections := sectionsOf(answer)
	if code != http.StatusOK || len(sections) != 3 {
		t.Fatalf("preview: %d %+v", code, sections)
	}
	byID := map[string]cardcontroller.ImportSection{}
	for _, section := range sections {
		byID[section.ID] = section
	}
	if got := strings.Join(byID["panel_settings"].Changes, " | "); !strings.Contains(got, "каждые 30 мин") || !strings.Contains(got, "RU, BY") {
		t.Errorf("panel settings: %q", got)
	}
	if len(byID["journal_presets"].Changes) != 1 || len(byID["cards"].Changes) != 0 || len(byID["cards"].Skipped) != 1 {
		t.Errorf("sections: %+v", byID)
	}
	// A preview changes nothing.
	if current := transfer.settings.Current(); current.RefreshMinutes != 0 || len(current.AvoidCountries) != 0 || len(transfer.presets().List()) != 0 {
		t.Fatalf("the preview changed the settings: %+v", current)
	}

	// Only the chosen sections are applied.
	if code, _ = post("/settings/import/apply", map[string]interface{}{"file": file, "sections": []string{"journal_presets"}}); code != http.StatusOK {
		t.Fatalf("apply answered %d", code)
	}
	if presets := transfer.presets().List(); len(presets) != 1 || presets[0].Name != "Блокировки" || presets[0].ID == "foreign-id" {
		t.Fatalf("presets after the import: %+v", presets)
	}
	if transfer.settings.Current().RefreshMinutes != 0 {
		t.Fatal("a section that was not chosen was applied")
	}
	if code, _ = post("/settings/import/apply", map[string]interface{}{"file": file, "sections": []string{"panel_settings", "journal_presets", "cards"}}); code != http.StatusOK {
		t.Fatalf("apply answered %d", code)
	}
	if current := transfer.settings.Current(); current.RefreshMinutes != 30 || strings.Join(current.AvoidCountries, ",") != "RU,BY" {
		t.Fatalf("panel settings after the import: %+v", current)
	}
	if len(transfer.presets().List()) != 1 {
		t.Fatal("the same preset was added twice")
	}
	// Nothing is left to do, and the export describes what was imported.
	if _, answer = post("/settings/import/preview", file); len(sectionsOf(answer)) != 1 {
		t.Fatalf("after the import only the foreign part remains: %+v", sectionsOf(answer))
	}
	exported, err := transfer.export()
	if err != nil || exported.Format != settingsFormat || exported.Version != settingsVersion || exported.Settings.RefreshMinutes != 30 || len(exported.JournalPresets) != 1 || exported.Cards != nil {
		t.Fatalf("export: %+v %v", exported, err)
	}
	raw, _ := json.Marshal(exported)
	for _, secret := range []string{"password", "totp", "jwt", "token", "hwid", "://"} {
		if strings.Contains(strings.ToLower(string(raw)), secret) {
			t.Errorf("the export mentions %q: %s", secret, raw)
		}
	}
	// Values outside the allowed range are told, not applied.
	bad := settingsFile{Format: settingsFormat, Version: settingsVersion, Settings: &PanelSettings{RefreshMinutes: 2}}
	if _, answer = post("/settings/import/preview", bad); len(sectionsOf(answer)) != 1 || len(sectionsOf(answer)[0].Skipped) != 1 || len(sectionsOf(answer)[0].Changes) != 0 {
		t.Fatalf("an invalid interval: %+v", sectionsOf(answer))
	}
	if results, err := transfer.apply(context.Background(), bad, []string{"panel_settings"}); err != nil || len(results) != 0 || transfer.settings.Current().RefreshMinutes != 30 {
		t.Fatalf("an invalid interval was applied: %+v %v", results, err)
	}
}
