package trafficjournal

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"
)

// Preset is a saved set of journal filters: a name and what to show. It is
// kept on the router, so the same presets appear on every device.
type Preset struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Source  string `json:"source"`
	View    string `json:"view"`
	Device  string `json:"device,omitempty"`
	Service string `json:"service,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Search  string `json:"search,omitempty"`
}

const maxPresets = 30

var (
	presetID      = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	presetSources = map[string]bool{"live": true, "recent": true, "history": true}
	presetViews   = map[string]bool{"list": true, "sites": true}
	presetKinds   = map[string]bool{"": true, "connection": true, "kill_switch": true, "quic": true, "error": true}
)

type Presets struct {
	mu    sync.Mutex
	path  string
	items []Preset
}

// NewPresets loads the saved presets. A missing or damaged file is an empty
// list: presets are a convenience and must not stop the journal.
func NewPresets(dataDir string) *Presets {
	p := &Presets{items: []Preset{}}
	if dataDir == "" {
		// No data directory: presets live until the panel restarts.
		return p
	}
	p.path = filepath.Join(dataDir, "journal-presets.json")
	raw, err := os.ReadFile(p.path)
	if err != nil || len(raw) > 64<<10 {
		return p
	}
	var stored []Preset
	if json.Unmarshal(raw, &stored) != nil {
		return p
	}
	if clean, err := normalizePresets(stored); err == nil {
		p.items = clean
	}
	return p
}

func plain(value string, limit int) (string, bool) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > limit {
		return "", false
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return "", false
		}
	}
	return value, true
}

func normalizePresets(items []Preset) ([]Preset, error) {
	if len(items) > maxPresets {
		return nil, errors.New("Шаблонов может быть не больше 30.")
	}
	result := make([]Preset, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		name, ok := plain(item.Name, 40)
		if !ok || name == "" {
			return nil, errors.New("У шаблона должно быть название до 40 символов.")
		}
		device, okDevice := plain(item.Device, 80)
		service, okService := plain(item.Service, 40)
		search, okSearch := plain(item.Search, 128)
		if !okDevice || !okService || !okSearch || !presetSources[item.Source] || !presetViews[item.View] || !presetKinds[item.Kind] {
			return nil, errors.New("В шаблоне недопустимые фильтры.")
		}
		id := item.ID
		if !presetID.MatchString(id) || seen[id] {
			var raw [8]byte
			if _, err := rand.Read(raw[:]); err != nil {
				return nil, errors.New("Не удалось сохранить шаблон.")
			}
			id = hex.EncodeToString(raw[:])
		}
		seen[id] = true
		result = append(result, Preset{ID: id, Name: name, Source: item.Source, View: item.View, Device: device, Service: service, Kind: item.Kind, Search: search})
	}
	return result, nil
}

func (p *Presets) List() []Preset {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Preset{}, p.items...)
}

// Replace stores the whole list: the page sends it back after adding,
// renaming, reordering or removing a preset.
func (p *Presets) Replace(items []Preset) ([]Preset, error) {
	clean, err := normalizePresets(items)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(clean)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.path == "" {
		p.items = clean
		return append([]Preset{}, clean...), nil
	}
	file, err := os.CreateTemp(filepath.Dir(p.path), ".journal-presets-*.json")
	if err != nil {
		return nil, errors.New("Не удалось сохранить шаблоны.")
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, p.path)
	}
	if err != nil {
		return nil, errors.New("Не удалось сохранить шаблоны.")
	}
	p.items = clean
	return append([]Preset{}, clean...), nil
}
