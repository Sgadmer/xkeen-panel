package xkeen

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"xkeen-panel/internal/models"
)

type SubscriptionManager struct {
	dataDir              string
	data                 *models.SubscriptionData
	mu                   sync.RWMutex
	operationMu          sync.Mutex
	importReport         ImportReport
	pendingImportReport  ImportReport
	rollbackImportReport ImportReport
	rollbackSnapshotKey  string
	// Optional injection for deterministic HTTP/TLS tests; production uses the
	// standard verified-TLS transport. Redirect policy is always enforced.
	httpClient *http.Client
}

func NewSubscriptionManager(dataDir string) *SubscriptionManager {
	return &SubscriptionManager{
		dataDir: dataDir,
		data:    &models.SubscriptionData{},
	}
}

func (sm *SubscriptionManager) filePath() string {
	return filepath.Join(sm.dataDir, "subscription.json")
}

// Load reads the stored subscription.
func (sm *SubscriptionManager) Load() error {
	sm.operationMu.Lock()
	defer sm.operationMu.Unlock()
	sm.mu.Lock()
	defer sm.mu.Unlock()

	data, err := os.ReadFile(sm.filePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var loaded subscriptionStoredData
	if err := json.Unmarshal(data, &loaded); err != nil {
		return fmt.Errorf("не удалось прочитать сохранённую подписку")
	}
	sm.data = &loaded.SubscriptionData
	sm.importReport = cloneSubscriptionImportReport(loaded.ImportReport)
	sm.importReport.Imported = len(sm.data.Servers)
	sm.normalizeCatalogLocked()
	return nil
}

// Save writes the subscription to disk.
func (sm *SubscriptionManager) Save() error {
	sm.operationMu.Lock()
	defer sm.operationMu.Unlock()
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.saveLocked()
}

func (sm *SubscriptionManager) saveLocked() error {
	if err := os.MkdirAll(sm.dataDir, 0700); err != nil {
		return fmt.Errorf("не удалось подготовить хранилище подписки")
	}

	data, err := json.MarshalIndent(subscriptionStoredData{SubscriptionData: *sm.data, ImportReport: sm.importReport}, "", "  ")
	if err != nil {
		return fmt.Errorf("не удалось сохранить подписку")
	}
	if err := writeFileAtomic(sm.filePath(), data, 0600); err != nil {
		return fmt.Errorf("не удалось сохранить подписку")
	}
	return nil
}

// GetData returns a copy of the subscription. Servers is deep-copied: otherwise
// the caller would read the live slice unlocked, racing SetActive and friends.
func (sm *SubscriptionManager) GetData() models.SubscriptionData {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return cloneSubscriptionData(*sm.data)
}

// GetServers returns the server list.
func (sm *SubscriptionManager) GetServers() []models.Server {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return cloneSubscriptionServers(sm.data.Servers)
}

// UpdateLatencies stores measured latencies by stable server identity.
func (sm *SubscriptionManager) UpdateLatencies(checked []models.Server) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	type probeKey struct{ source, identity string }
	results := make(map[probeKey]models.Server, len(checked))
	for _, c := range checked {
		if key := ServerIdentity(c); key != "" {
			results[probeKey{c.SourceID, key}] = c
		}
	}

	now := time.Now()
	previous := sm.data.Servers
	sm.data.Servers = append([]models.Server(nil), previous...)
	for i := range sm.data.Servers {
		s := &sm.data.Servers[i]
		identity := ServerIdentity(*s)
		result, ok := results[probeKey{s.SourceID, identity}]
		if !ok && s.SourceID == "legacy" {
			result, ok = results[probeKey{"", identity}]
		}
		if ok {
			if sm.data.Servers[i].ProbeKind == "https" && result.ProbeKind != "https" {
				continue
			}
			at := result.LastChecked
			if at.IsZero() || result.ProbeKind != "https" {
				at = now
			}
			if s.LastChecked.After(at) {
				continue
			}
			s.Latency, s.ProbeKind, s.CheckError, s.LastChecked = result.Latency, result.ProbeKind, result.CheckError, at
		}
	}

	if err := sm.saveLocked(); err != nil {
		sm.data.Servers = previous
		return err
	}
	return nil
}

// SetCountryOverride sets a server's country by hand — needed in strict mode when
// detection could not resolve it.
func (sm *SubscriptionManager) SetCountryOverride(id int, country string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	index := sm.serverIndexLocked(id)
	if index < 0 {
		return fmt.Errorf("сервер с id %d не найден", id)
	}

	previous := sm.data.Servers[index].CountryOverride
	sm.data.Servers[index].CountryOverride = strings.ToUpper(strings.TrimSpace(country))
	if err := sm.saveLocked(); err != nil {
		sm.data.Servers[index].CountryOverride = previous
		return err
	}
	return nil
}

// SetActive makes the server with the given id active.
func (sm *SubscriptionManager) SetActive(id int) (*models.Server, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	index := sm.serverIndexLocked(id)
	if index < 0 {
		return nil, fmt.Errorf("сервер с id %d не найден", id)
	}

	return sm.setActiveLocked(index)
}

func (sm *SubscriptionManager) serverIndexLocked(id int) int {
	for i, s := range sm.data.Servers {
		if s.ID == id {
			return i
		}
	}
	return -1
}

// SetActiveByRawURI activates a server by its stable RawURI under a single lock.
// Safer than SetActive(id) when a Refresh may have run between snapshot and
// activation: indices move, RawURI does not.
func (sm *SubscriptionManager) SetActiveByRawURI(uri string) (*models.Server, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	idx := -1
	for i := range sm.data.Servers {
		if sm.data.Servers[i].RawURI == uri || ServerIdentity(sm.data.Servers[i]) == uri {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("сервер не найден по RawURI")
	}

	return sm.setActiveLocked(idx)
}

func (sm *SubscriptionManager) setActiveLocked(id int) (*models.Server, error) {
	previous := cloneSubscriptionData(*sm.data)
	sm.data.ActiveID = id
	for i := range sm.data.Servers {
		sm.data.Servers[i].Active = i == id
	}
	if err := sm.saveLocked(); err != nil {
		sm.data = &previous
		return nil, err
	}
	server := cloneSubscriptionServer(sm.data.Servers[id])
	return &server, nil
}

// GetActiveServer returns the active server.
func (sm *SubscriptionManager) GetActiveServer() *models.Server {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if len(sm.data.Servers) == 0 {
		return nil
	}

	id := sm.data.ActiveID
	if id < 0 || id >= len(sm.data.Servers) {
		return nil
	}

	s := cloneSubscriptionServer(sm.data.Servers[id])
	return &s
}

// SelectNext switches to the next server in the list.
func (sm *SubscriptionManager) SelectNext() (*models.Server, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	count := len(sm.data.Servers)

	if count == 0 {
		return nil, fmt.Errorf("нет доступных серверов")
	}

	next := (sm.data.ActiveID + 1) % count
	return sm.setActiveLocked(next)
}

func cloneSubscriptionServer(server models.Server) models.Server {
	server.RawOutbound = append(json.RawMessage(nil), server.RawOutbound...)
	server.RawProfile = append(json.RawMessage(nil), server.RawProfile...)
	return server
}

func cloneSubscriptionServers(servers []models.Server) []models.Server {
	result := make([]models.Server, len(servers))
	for i := range servers {
		result[i] = cloneSubscriptionServer(servers[i])
	}
	return result
}

func cloneSubscriptionData(data models.SubscriptionData) models.SubscriptionData {
	data.Servers = cloneSubscriptionServers(data.Servers)
	data.Sources = append([]models.SubscriptionSource(nil), data.Sources...)
	for i := range data.Sources {
		data.Sources[i].Report = cloneSubscriptionImportReport(data.Sources[i].Report)
	}
	return data
}

// The envelope adds sanitized import diagnostics without changing the model or
// breaking the legacy top-level subscription.json fields.
type subscriptionStoredData struct {
	models.SubscriptionData
	ImportReport ImportReport `json:"import_report"`
}

func cloneSubscriptionImportReport(report ImportReport) ImportReport {
	report.Warnings = append([]string(nil), report.Warnings...)
	return report
}

func subscriptionSnapshotKey(data models.SubscriptionData) string {
	encoded, _ := json.Marshal(data)
	return subscriptionURLHash(string(encoded))
}

func (sm *SubscriptionManager) GetImportReport() ImportReport {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return cloneSubscriptionImportReport(sm.importReport)
}

// RestoreData is used when the caller's post-import verification or live apply
// rejects a subscription. The registered installation identity and negotiated
// client profile are deliberately not rolled back.
func (sm *SubscriptionManager) RestoreData(previous models.SubscriptionData) error {
	sm.operationMu.Lock()
	defer sm.operationMu.Unlock()
	sm.mu.Lock()
	defer sm.mu.Unlock()
	current := cloneSubscriptionData(*sm.data)
	currentReport := cloneSubscriptionImportReport(sm.importReport)
	restored := cloneSubscriptionData(previous)
	sm.data = &restored
	sm.importReport = ImportReport{Imported: len(previous.Servers)}
	if subscriptionSnapshotKey(previous) == sm.rollbackSnapshotKey {
		sm.importReport = cloneSubscriptionImportReport(sm.rollbackImportReport)
	}
	sm.normalizeCatalogLocked()
	if err := sm.saveLocked(); err != nil {
		sm.data = &current
		sm.importReport = currentReport
		return err
	}
	return nil
}
