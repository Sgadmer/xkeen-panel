package trafficjournal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"xkeen-panel/internal/trafficlog"
)

type Config struct {
	Enabled         bool   `json:"enabled"`
	StorageID       string `json:"storage_id"`
	Path            string `json:"path"`
	MaxEvents       int    `json:"max_events"`
	MaxDeviceEvents int    `json:"max_device_events"`
	MaxBytes        int64  `json:"max_bytes"`
	// The short journal in memory is on unless switched off. Zero records
	// means the default size for this router.
	RecentOff    bool `json:"recent_off,omitempty"`
	RecentEvents int  `json:"recent_events,omitempty"`
}

type Patch struct {
	Enabled         *bool   `json:"enabled,omitempty"`
	StorageID       *string `json:"storage_id,omitempty"`
	Path            *string `json:"path,omitempty"`
	MaxEvents       *int    `json:"max_events,omitempty"`
	MaxDeviceEvents *int    `json:"max_device_events,omitempty"`
	MaxBytes        *int64  `json:"max_bytes,omitempty"`
	RecentOff       *bool   `json:"recent_off,omitempty"`
	RecentEvents    *int    `json:"recent_events,omitempty"`
}

// Empty reports a patch that names nothing to change.
func (p Patch) Empty() bool {
	return p.Enabled == nil && p.Path == nil && p.StorageID == nil && p.MaxBytes == nil && p.MaxEvents == nil && p.MaxDeviceEvents == nil && p.RecentOff == nil && p.RecentEvents == nil
}

type Settings struct {
	trafficlog.Status
	Enabled              bool     `json:"enabled"`
	Supported            bool     `json:"supported"`
	Path                 string   `json:"path"`
	StorageID            string   `json:"storage_id"`
	StorageLabel         string   `json:"storage_label"`
	Storages             []Volume `json:"storages"`
	MemoryAvailableBytes int64    `json:"memory_available_bytes"`

	// The short journal kept in memory.
	RecentEnabled  bool       `json:"recent_enabled"`
	RecentEvents   int        `json:"recent_events"`
	RecentCount    int        `json:"recent_count"`
	RecentOldestAt *time.Time `json:"recent_oldest_at,omitempty"`
	RecentMinutes  int        `json:"recent_minutes"`
}

type DeviceIdentity struct{ IP, MAC, Name string }

type Manager struct {
	repeatMu       sync.Mutex
	repeats        map[string]repeatWindow
	session        string
	mu             sync.Mutex
	config         Config
	configPath     string
	lastError      string
	ctx            context.Context
	store          atomic.Pointer[trafficlog.Store]
	recent         atomic.Pointer[recentLog]
	volumes        func() []Volume
	memory         func() (int64, int64)
	identities     atomic.Value // immutable map[string]DeviceIdentity
	deviceProvider func() []DeviceIdentity
}

type repeatWindow struct {
	at    time.Time
	count int
}

func New(ctx context.Context, dataDir string) *Manager {
	m := &Manager{ctx: ctx, configPath: filepath.Join(dataDir, "traffic-history-settings.json"), volumes: DiscoverVolumes, memory: memoryBytes}
	m.identities.Store(map[string]DeviceIdentity{})
	var session [8]byte
	_, _ = rand.Read(session[:])
	m.session = fmt.Sprintf("%x", session)
	limits := trafficlog.DefaultLimits()
	if total, _ := m.memory(); total > 0 && total < 192<<20 {
		limits.MaxEvents, limits.MaxDeviceEvents, limits.MaxBytes = 30000, 5000, 32<<20
	}
	m.config = Config{MaxEvents: limits.MaxEvents, MaxDeviceEvents: limits.MaxDeviceEvents, MaxBytes: limits.MaxBytes}
	if raw, err := os.ReadFile(m.configPath); err == nil {
		var stored Config
		if len(raw) > 4096 || json.Unmarshal(raw, &stored) != nil || stored.limits().Validate() != nil {
			m.lastError = "Настройки истории повреждены; запись на диск выключена."
		} else {
			m.config = stored
			if !validRecent(m.config) {
				m.config.RecentEvents = 0
			}
		}
	} else if !os.IsNotExist(err) {
		m.lastError = "Не удалось прочитать настройки истории; запись на диск выключена."
	}
	m.applyRecent(m.config)
	return m
}

func (c Config) limits() trafficlog.Limits {
	return trafficlog.Limits{Retention: 24 * time.Hour, MaxEvents: c.MaxEvents, MaxDeviceEvents: c.MaxDeviceEvents, MaxBytes: c.MaxBytes}
}

// recentCapacity is how many records the short journal keeps. A router with
// little memory gets a smaller default.
func (m *Manager) recentCapacity(c Config) int {
	if c.RecentEvents != 0 {
		return c.RecentEvents
	}
	if total, _ := m.memory(); total > 0 && total < 192<<20 {
		return 1000
	}
	return DefaultRecentEvents
}

func validRecent(c Config) bool {
	return c.RecentEvents == 0 || c.RecentEvents >= minRecentEvents && c.RecentEvents <= maxRecentEvents
}

// applyRecent creates, resizes or drops the short journal to match the config.
// Its records do not survive a change of size.
func (m *Manager) applyRecent(c Config) {
	if c.RecentOff || !validRecent(c) {
		m.recent.Store(nil)
		return
	}
	capacity := m.recentCapacity(c)
	if current := m.recent.Load(); current != nil && len(current.entries) == capacity {
		return
	}
	m.recent.Store(newRecentLog(capacity, m.session))
}

// Active tells the log observer whether anyone keeps the records it parses.
func (m *Manager) Active() bool {
	return m != nil && (m.store.Load() != nil || m.recent.Load() != nil)
}

// ArchiveOpen reports whether the day-long journal on the disk is being written.
func (m *Manager) ArchiveOpen() bool { return m != nil && m.store.Load() != nil }

func (m *Manager) SetDeviceProvider(provider func() []DeviceIdentity) { m.deviceProvider = provider }

func (m *Manager) refreshDevices() {
	if m.deviceProvider == nil {
		return
	}
	values := m.deviceProvider()
	if values == nil {
		return
	}
	index := make(map[string]DeviceIdentity, len(values))
	for _, value := range values {
		ip := net.ParseIP(value.IP)
		mac, err := net.ParseMAC(value.MAC)
		if ip == nil || err != nil || len(mac) != 6 {
			continue
		}
		value.IP, value.MAC = ip.String(), strings.ToLower(mac.String())
		index[value.IP] = value
	}
	m.identities.Store(index)
}

// Record is called by the core log observer. It never opens a file, queries
// SQLite or calls the firmware API. A full writer queue drops metadata only.
func (m *Manager) Record(entry trafficlog.Entry) {
	store, recent := m.store.Load(), m.recent.Load()
	if store == nil && recent == nil {
		return
	}
	if identity, ok := m.identities.Load().(map[string]DeviceIdentity)[entry.Device]; ok {
		entry.DeviceID, entry.DeviceName = "mac:"+identity.MAC, identity.Name
	} else {
		entry.DeviceID = "ip:" + entry.Device
	}
	if entry.Kind != "connection" {
		// A short window folds packet retries without extending an old row's
		// retention time indefinitely. A changed route starts a different row.
		key := entry.DeviceID + "\x00" + entry.Device + "\x00" + entry.Kind + "\x00" + entry.ServiceID + "\x00" + entry.Host + "\x00" + entry.Port + "\x00" + entry.Network + "\x00" + strings.Join(entry.Route, "\x00")
		if entry.Exit != nil {
			key += "\x00" + entry.Exit.Kind + "\x00" + entry.Exit.Name + "\x00" + entry.Exit.Country + "\x00" + entry.Exit.Source
		}
		key += entry.At.Truncate(15 * time.Second).Format(time.RFC3339)
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
		m.repeatMu.Lock()
		if len(m.repeats) >= 256 {
			clear(m.repeats)
		}
		if m.repeats == nil {
			m.repeats = map[string]repeatWindow{}
		}
		window := m.repeats[hash]
		if window.count == 0 {
			window.at = entry.At
		}
		window.count++
		m.repeats[hash] = window
		entry.ID, entry.At, entry.Count = "repeat-"+m.session+"-"+hash[:24], window.at, window.count
		m.repeatMu.Unlock()
	}
	if recent != nil {
		recent.add(entry)
	}
	if store != nil {
		store.Submit(entry)
	}
}

// QueryRecent reads the short journal kept in memory.
func (m *Manager) QueryRecent(query trafficlog.Query) (trafficlog.Page, []trafficlog.Device) {
	recent := m.recent.Load()
	if recent == nil {
		return trafficlog.Page{Events: []trafficlog.Entry{}}, []trafficlog.Device{}
	}
	return recent.query(query), recent.devices()
}

// Sites groups the short journal by address.
func (m *Manager) Sites(query trafficlog.Query) []Site {
	recent := m.recent.Load()
	if recent == nil {
		return []Site{}
	}
	return recent.sites(query)
}

func (m *Manager) Status() Settings {
	m.mu.Lock()
	cfg, lastError := m.config, m.lastError
	m.mu.Unlock()
	_, available := m.memory()
	base := trafficlog.Status{RetentionHours: 24, MaxEvents: cfg.MaxEvents, MaxDeviceEvents: cfg.MaxDeviceEvents, MaxBytes: cfg.MaxBytes}
	if store := m.store.Load(); store != nil {
		base = store.Status()
	}
	if lastError != "" {
		base.Error = lastError
	}
	if !trafficlog.Supported() {
		base.Error = trafficlog.SupportReason()
	}
	volumes := m.volumes()
	status := Settings{Status: base, Enabled: cfg.Enabled, Supported: trafficlog.Supported(), Path: cfg.Path, StorageID: cfg.StorageID, Storages: volumes, MemoryAvailableBytes: available,
		RecentEvents: m.recentCapacity(cfg), RecentMinutes: int(recentKeep / time.Minute)}
	if recent := m.recent.Load(); recent != nil {
		count, capacity, oldest := recent.size()
		status.RecentEnabled, status.RecentCount, status.RecentEvents = true, count, capacity
		if !oldest.IsZero() {
			status.RecentOldestAt = &oldest
		}
	}
	for _, volume := range volumes {
		if volume.ID == cfg.StorageID {
			status.StorageLabel = volume.Label
			if !cfg.Enabled {
				status.StorageAvailable = volume.Available
			}
		}
	}
	return status
}

func (m *Manager) validate(cfg Config, dbPath string) error {
	if cfg.limits().Validate() != nil {
		return errors.New("Недопустимые лимиты истории.")
	}
	for _, volume := range m.volumes() {
		if volume.ID != cfg.StorageID {
			continue
		}
		folder, err := resolveDestination(volume, cfg.Path)
		if err != nil {
			return err
		}
		if filepath.Clean(dbPath) != filepath.Join(folder, "traffic.sqlite") {
			return errors.New("Папка журнала изменилась или ссылается за пределы накопителя.")
		}
		if _, available := m.memory(); available > 0 && available < 24<<20 {
			return errors.New("Недостаточно свободной памяти для дисковой истории; VPN продолжает работать.")
		}
		return nil
	}
	return errors.New("Выбранный внешний накопитель не подключён. Запись не переносится во внутреннюю память.")
}

func (m *Manager) open(cfg Config) (*trafficlog.Store, error) {
	if !trafficlog.Supported() {
		return nil, errors.New(trafficlog.SupportReason())
	}
	path := filepath.Join(cfg.Path, "traffic.sqlite")
	queue := 1024
	if total, _ := m.memory(); total > 0 && total < 192<<20 {
		queue = 256
	}
	return trafficlog.Open(m.ctx, path, trafficlog.Options{Limits: cfg.limits(), QueueSize: queue, FlushInterval: 2 * time.Second, Validate: func(path string) error { return m.validate(cfg, path) }})
}

func (m *Manager) save(cfg Config) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(m.configPath), ".traffic-history-*.json")
	if err != nil {
		return errors.New("Не удалось сохранить настройки истории.")
	}
	path := file.Name()
	defer os.Remove(path)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(path, m.configPath)
	}
	if err != nil {
		return errors.New("Не удалось сохранить настройки истории.")
	}
	return nil
}

func (m *Manager) Apply(ctx context.Context, patch Patch) (Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, next := m.config, m.config
	if patch.Enabled != nil {
		next.Enabled = *patch.Enabled
	}
	if patch.StorageID != nil {
		next.StorageID = *patch.StorageID
	}
	if patch.Path != nil {
		next.Path = *patch.Path
	}
	if patch.MaxEvents != nil {
		next.MaxEvents = *patch.MaxEvents
	}
	if patch.MaxDeviceEvents != nil {
		next.MaxDeviceEvents = *patch.MaxDeviceEvents
	}
	if patch.MaxBytes != nil {
		next.MaxBytes = *patch.MaxBytes
	}
	if patch.RecentOff != nil {
		next.RecentOff = *patch.RecentOff
	}
	if patch.RecentEvents != nil {
		next.RecentEvents = *patch.RecentEvents
	}
	if err := next.limits().Validate(); err != nil {
		return Settings{}, err
	}
	if !validRecent(next) {
		return Settings{}, errRecentSize
	}
	if next.Enabled {
		found := false
		for _, volume := range m.volumes() {
			if volume.ID != next.StorageID {
				continue
			}
			folder, err := resolveDestination(volume, next.Path)
			if err != nil {
				return Settings{}, err
			}
			next.Path, found = folder, true
		}
		if !found {
			return Settings{}, errors.New("Сначала выберите подключённый внешний накопитель.")
		}
		if err := m.validate(next, filepath.Join(next.Path, "traffic.sqlite")); err != nil {
			return Settings{}, err
		}
	}
	// A change of the short journal alone leaves the disk journal running.
	diskOld, diskNext := old, next
	diskOld.RecentOff, diskOld.RecentEvents = false, 0
	diskNext.RecentOff, diskNext.RecentEvents = false, 0
	if diskOld == diskNext && (!next.Enabled || m.store.Load() != nil) {
		if old != next {
			if err := m.save(next); err != nil {
				return Settings{}, err
			}
			m.config = next
			m.applyRecent(next)
		}
		return Settings{}, nil
	}
	previous := m.store.Swap(nil)
	m.repeatMu.Lock()
	clear(m.repeats)
	m.repeats = nil
	m.repeatMu.Unlock()
	if previous != nil {
		_ = previous.Close()
	}
	var candidate *trafficlog.Store
	var err error
	if next.Enabled {
		candidate, err = m.open(next)
	}
	if err == nil {
		err = m.save(next)
	}
	if err != nil {
		if candidate != nil {
			_ = candidate.Close()
		}
		if old.Enabled {
			if restored, reopen := m.open(old); reopen == nil {
				m.store.Store(restored)
			}
		}
		return Settings{}, err
	}
	m.config, m.lastError = next, ""
	m.applyRecent(next)
	if candidate != nil {
		m.refreshDevices()
		m.store.Store(candidate)
	}
	return Settings{}, nil
}

var errRecentSize = errors.New("Размер короткого журнала — от 500 до 20 000 записей.")

// ValidatePatch rejects a bad disk or memory limit before the API requests a
// different core log level. Apply repeats this check before committing.
func (m *Manager) ValidatePatch(patch Patch) error {
	m.mu.Lock()
	cfg := m.config
	m.mu.Unlock()
	if patch.Enabled != nil {
		cfg.Enabled = *patch.Enabled
	}
	if patch.StorageID != nil {
		cfg.StorageID = *patch.StorageID
	}
	if patch.Path != nil {
		cfg.Path = *patch.Path
	}
	if patch.MaxEvents != nil {
		cfg.MaxEvents = *patch.MaxEvents
	}
	if patch.MaxDeviceEvents != nil {
		cfg.MaxDeviceEvents = *patch.MaxDeviceEvents
	}
	if patch.MaxBytes != nil {
		cfg.MaxBytes = *patch.MaxBytes
	}
	if patch.RecentEvents != nil {
		cfg.RecentEvents = *patch.RecentEvents
	}
	if err := cfg.limits().Validate(); err != nil {
		return err
	}
	if !validRecent(cfg) {
		return errRecentSize
	}
	if !cfg.Enabled {
		return nil
	}
	if !trafficlog.Supported() {
		return errors.New(trafficlog.SupportReason())
	}
	for _, volume := range m.volumes() {
		if volume.ID != cfg.StorageID {
			continue
		}
		folder, err := resolveDestination(volume, cfg.Path)
		if err != nil {
			return err
		}
		cfg.Path = folder
		return m.validate(cfg, filepath.Join(folder, "traffic.sqlite"))
	}
	return errors.New("Сначала выберите подключённый внешний накопитель.")
}

func (m *Manager) Query(ctx context.Context, query trafficlog.Query) (trafficlog.Page, []trafficlog.Device, error) {
	store := m.store.Load()
	if store == nil {
		return trafficlog.Page{Events: []trafficlog.Entry{}}, []trafficlog.Device{}, nil
	}
	page, err := store.Query(ctx, query)
	if err != nil {
		return page, nil, err
	}
	devices, err := store.Devices(ctx)
	return page, devices, err
}

// Run retries a saved enabled configuration after the selected disk returns.
// Disabled is the universal default and starts no database or writer queue.
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	defer func() {
		if store := m.store.Swap(nil); store != nil {
			_ = store.Close()
		}
	}()
	for {
		m.mu.Lock()
		if store := m.store.Load(); store != nil && !store.Status().StorageAvailable {
			if m.validate(m.config, filepath.Join(m.config.Path, "traffic.sqlite")) == nil {
				m.store.Store(nil)
				_ = store.Close()
			}
		}
		if m.config.Enabled && m.store.Load() == nil {
			if store, err := m.open(m.config); err == nil {
				m.refreshDevices()
				m.store.Store(store)
				m.lastError = ""
			} else {
				m.lastError = err.Error()
			}
		}
		m.mu.Unlock()
		if m.Active() {
			m.refreshDevices()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
