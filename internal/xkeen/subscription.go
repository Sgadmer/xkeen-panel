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

// UpdateURL sets a new subscription URL, then downloads and parses it.
func (sm *SubscriptionManager) UpdateURL(url string) ([]models.Server, error) {
	sm.operationMu.Lock()
	defer sm.operationMu.Unlock()
	servers, err := sm.downloadAndParse(url)
	if err != nil {
		return nil, err
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()
	previous := cloneSubscriptionData(*sm.data)
	previousReport := cloneSubscriptionImportReport(sm.importReport)
	sm.data.URL = url
	sm.data.SourceKind = "subscription"
	sm.applyRefreshLocked(servers)
	sm.importReport = cloneSubscriptionImportReport(sm.pendingImportReport)
	if err := sm.saveLocked(); err != nil {
		sm.data = &previous
		sm.importReport = previousReport
		return nil, err
	}
	sm.rollbackSnapshotKey = subscriptionSnapshotKey(previous)
	sm.rollbackImportReport = previousReport
	return cloneSubscriptionServers(sm.data.Servers), nil
}

// Refresh reloads the servers from the current URL.
func (sm *SubscriptionManager) Refresh() ([]models.Server, error) {
	sm.operationMu.Lock()
	defer sm.operationMu.Unlock()
	sm.mu.RLock()
	url := sm.data.URL
	sm.mu.RUnlock()

	if url == "" {
		return nil, fmt.Errorf("серверы добавлены вручную; для изменения импортируйте новую ссылку или файл")
	}

	servers, err := sm.downloadAndParse(url)
	if err != nil {
		return nil, err
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()
	previous := cloneSubscriptionData(*sm.data)
	previousReport := cloneSubscriptionImportReport(sm.importReport)
	sm.applyRefreshLocked(servers)
	sm.importReport = cloneSubscriptionImportReport(sm.pendingImportReport)
	if err := sm.saveLocked(); err != nil {
		sm.data = &previous
		sm.importReport = previousReport
		return nil, err
	}
	sm.rollbackSnapshotKey = subscriptionSnapshotKey(previous)
	sm.rollbackImportReport = previousReport
	return cloneSubscriptionServers(sm.data.Servers), nil
}

// CanRefresh distinguishes a remote subscription from local server credentials.
// The latter must never be treated as a URL or fetched by the hourly task.
func (sm *SubscriptionManager) CanRefresh() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.data.URL != "" && (sm.data.SourceKind == "" || sm.data.SourceKind == "subscription")
}

// ImportContent stores parsed server credentials locally, never the file name
// or a synthetic URL. The caller verifies HTTPS and rolls the whole operation
// back if these endpoints cannot be applied to the installed core.
func (sm *SubscriptionManager) ImportContent(content, kind string) ([]models.Server, error) {
	sm.operationMu.Lock()
	defer sm.operationMu.Unlock()
	if kind != "server" && kind != "file" {
		return nil, fmt.Errorf("выберите ссылку сервера или локальный файл")
	}
	if len(content) == 0 || len(content) > 4<<20 {
		return nil, fmt.Errorf("пустой или слишком большой источник серверов (предел 4 МиБ)")
	}
	servers, report, err := ParseSubscriptionDetailed(content)
	if err != nil {
		return nil, fmt.Errorf("источник не содержит поддерживаемых серверов; проверьте формат ссылки или файла")
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	previous := cloneSubscriptionData(*sm.data)
	previousReport := cloneSubscriptionImportReport(sm.importReport)
	sm.data.URL = ""
	sm.data.SourceKind = kind
	sm.applyRefreshLocked(servers)
	sm.importReport = cloneSubscriptionImportReport(report)
	if err := sm.saveLocked(); err != nil {
		sm.data = &previous
		sm.importReport = previousReport
		return nil, err
	}
	sm.rollbackSnapshotKey = subscriptionSnapshotKey(previous)
	sm.rollbackImportReport = previousReport
	return cloneSubscriptionServers(sm.data.Servers), nil
}

// applyRefreshLocked keeps the active server and country overrides matched by
// stable server identity, including native JSON endpoints. Call with sm.mu held.
func (sm *SubscriptionManager) applyRefreshLocked(servers []models.Server) {
	var activeIdentity string
	if sm.data.ActiveID >= 0 && sm.data.ActiveID < len(sm.data.Servers) {
		activeIdentity = ServerIdentity(sm.data.Servers[sm.data.ActiveID])
	}

	carryOverrides(sm.data.Servers, servers)

	sm.data.LastUpdated = time.Now()
	sm.data.Servers = cloneSubscriptionServers(servers)

	newActive := 0
	if activeIdentity != "" {
		for i := range servers {
			if ServerIdentity(servers[i]) == activeIdentity {
				newActive = i
				break
			}
		}
	}
	sm.data.ActiveID = newActive
	for i := range sm.data.Servers {
		sm.data.Servers[i].ID = i
		sm.data.Servers[i].Active = i == newActive
	}
}

// carryOverrides moves manual CountryOverride values by stable server identity.
func carryOverrides(old, fresh []models.Server) {
	if len(old) == 0 {
		return
	}
	overrides := make(map[string]string, len(old))
	for i := range old {
		if key := ServerIdentity(old[i]); old[i].CountryOverride != "" && key != "" {
			overrides[key] = old[i].CountryOverride
		}
	}
	for i := range fresh {
		if ov, ok := overrides[ServerIdentity(fresh[i])]; ok {
			fresh[i].CountryOverride = ov
		}
	}
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
func (sm *SubscriptionManager) UpdateLatencies(checked []models.Server) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	byURI := make(map[string]models.Server, len(checked))
	for _, c := range checked {
		if key := ServerIdentity(c); key != "" {
			byURI[key] = c
		}
	}

	now := time.Now()
	for i := range sm.data.Servers {
		if result, ok := byURI[ServerIdentity(sm.data.Servers[i])]; ok {
			if sm.data.Servers[i].ProbeKind == "https" && result.ProbeKind != "https" {
				continue
			}
			sm.data.Servers[i].Latency = result.Latency
			sm.data.Servers[i].ProbeKind = result.ProbeKind
			sm.data.Servers[i].CheckError = result.CheckError
			sm.data.Servers[i].LastChecked = now
		}
	}

	_ = sm.saveLocked()
}

// SetCountryOverride sets a server's country by hand — needed in strict mode when
// detection could not resolve it.
func (sm *SubscriptionManager) SetCountryOverride(id int, country string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if id < 0 || id >= len(sm.data.Servers) {
		return fmt.Errorf("сервер с id %d не найден", id)
	}

	previous := sm.data.Servers[id].CountryOverride
	sm.data.Servers[id].CountryOverride = strings.ToUpper(strings.TrimSpace(country))
	if err := sm.saveLocked(); err != nil {
		sm.data.Servers[id].CountryOverride = previous
		return err
	}
	return nil
}

// SetActive makes the server with the given id active.
func (sm *SubscriptionManager) SetActive(id int) (*models.Server, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if id < 0 || id >= len(sm.data.Servers) {
		return nil, fmt.Errorf("сервер с id %d не найден", id)
	}

	return sm.setActiveLocked(id)
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
	sm.mu.RLock()
	count := len(sm.data.Servers)
	current := sm.data.ActiveID
	sm.mu.RUnlock()

	if count == 0 {
		return nil, fmt.Errorf("нет доступных серверов")
	}

	next := (current + 1) % count
	return sm.SetActive(next)
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
	if err := sm.saveLocked(); err != nil {
		sm.data = &current
		sm.importReport = currentReport
		return err
	}
	return nil
}
