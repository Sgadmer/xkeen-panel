package xkeen

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"xkeen-panel/internal/models"
)

// SourceSummary contains only information that can be sent to a browser.
type SourceSummary struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Kind               string    `json:"kind"`
	Host               string    `json:"host,omitempty"`
	ServerCount        int       `json:"server_count"`
	LastUpdated        time.Time `json:"last_updated"`
	CanRefresh         bool      `json:"can_refresh"`
	NativeProvider     bool      `json:"native_provider,omitempty"`
	ImportedProfiles   int       `json:"imported_profiles,omitempty"`
	SkippedComposite   int       `json:"skipped_composite,omitempty"`
	SkippedUnsupported int       `json:"skipped_unsupported,omitempty"`
}

type SourceInput struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	URL     string `json:"url,omitempty"`
	Content string `json:"content,omitempty"`
}

var ErrSourceNotFound = errors.New("источник не найден")

func sourceHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func defaultSourceName(kind, rawURL string) string {
	if host := sourceHost(rawURL); host != "" {
		return host
	}
	if kind == "server" {
		return "Ссылка на сервер"
	}
	return "Импортированные серверы"
}

func (sm *SubscriptionManager) normalizeCatalogLocked() {
	d := sm.data
	if d.CatalogVersion != 0 {
		// A restored catalog may still carry an older copy of a renamed source on its servers.
		names := make(map[string]string, len(d.Sources))
		for _, source := range d.Sources {
			if source.ID != "" && source.Name != "" {
				names[source.ID] = source.Name
			}
		}
		for i := range d.Servers {
			if name, ok := names[d.Servers[i].SourceID]; ok {
				d.Servers[i].SourceName = name
			}
		}
		return
	}
	if len(d.Servers) == 0 && d.URL == "" {
		return
	}
	kind := d.SourceKind
	if kind == "" {
		if d.URL == "" {
			kind = "file"
		} else {
			kind = "subscription"
		}
	}
	source := models.SubscriptionSource{ID: "legacy", Kind: kind, Name: defaultSourceName(kind, d.URL), URL: d.URL, LastUpdated: d.LastUpdated, Report: cloneSubscriptionImportReport(sm.importReport)}
	d.CatalogVersion = 1
	d.Sources = []models.SubscriptionSource{source}
	for i := range d.Servers {
		s := &d.Servers[i]
		s.SourceID, s.SourceName = source.ID, source.Name
		if s.ID >= d.NextServerID {
			d.NextServerID = s.ID + 1
		}
	}
}

func (sm *SubscriptionManager) GetSources() []SourceSummary {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return SourceSummaries(*sm.data)
}

func SourceSummaries(data models.SubscriptionData) []SourceSummary {
	counts := make(map[string]int, len(data.Sources))
	for _, server := range data.Servers {
		counts[server.SourceID]++
	}
	sources := make([]SourceSummary, 0, len(data.Sources))
	for _, s := range data.Sources {
		sources = append(sources, SourceSummary{
			ID: s.ID, Name: s.Name, Kind: s.Kind, Host: sourceHost(s.URL),
			ServerCount: counts[s.ID], LastUpdated: s.LastUpdated, CanRefresh: s.Kind == "subscription" && s.URL != "",
			ImportedProfiles: s.Report.ImportedProfiles, SkippedComposite: s.Report.SkippedComposite, SkippedUnsupported: s.Report.SkippedUnsupported,
		})
	}
	return sources
}

func (sm *SubscriptionManager) CanRefresh() bool {
	for _, s := range sm.GetSources() {
		if s.CanRefresh {
			return true
		}
	}
	return false
}

// updateFirst keeps the pre-catalogue API usable. Other sources always survive
// replacing the first one. Source operations serialize the fetch as well as the
// write, so a late response cannot resurrect a removed subscription.
func (sm *SubscriptionManager) updateFirst(input SourceInput) ([]models.Server, error) {
	sm.operationMu.Lock()
	defer sm.operationMu.Unlock()
	sm.mu.RLock()
	source := models.SubscriptionSource{ID: "legacy"}
	if len(sm.data.Sources) > 0 {
		source = sm.data.Sources[0]
	}
	sm.mu.RUnlock()
	source.Kind, source.URL = input.Kind, strings.TrimSpace(input.URL)
	if source.Name == "" {
		source.Name = defaultSourceName(source.Kind, source.URL)
	}
	return sm.importSource(context.Background(), source, input.Content)
}

func (sm *SubscriptionManager) UpdateURL(rawURL string) ([]models.Server, error) {
	return sm.updateFirst(SourceInput{Kind: "subscription", URL: rawURL})
}

func (sm *SubscriptionManager) ImportContent(content, kind string) ([]models.Server, error) {
	return sm.updateFirst(SourceInput{Kind: kind, Content: content})
}

func (sm *SubscriptionManager) Refresh() ([]models.Server, error) {
	var failures []error
	refreshed := false
	for _, s := range sm.GetSources() {
		if s.CanRefresh {
			refreshed = true
			if _, err := sm.RefreshSource(context.Background(), s.ID); err != nil {
				failures = append(failures, err)
			}
		}
	}
	if refreshed {
		return sm.GetServers(), errors.Join(failures...)
	}
	return nil, errors.New("серверы добавлены вручную; для изменения импортируйте новую ссылку или файл")
}

func validSourceName(name string) bool {
	return name != "" && utf8.RuneCountInString(name) <= 80 && !strings.Contains(name, "://") && strings.IndexFunc(name, unicode.IsControl) < 0
}

func (sm *SubscriptionManager) AddSource(ctx context.Context, input SourceInput) ([]models.Server, error) {
	sm.operationMu.Lock()
	defer sm.operationMu.Unlock()
	name := strings.TrimSpace(input.Name)
	if !validSourceName(name) {
		return nil, errors.New("введите название источника до 80 символов без ссылок")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, errors.New("не удалось создать идентификатор источника")
	}
	source := models.SubscriptionSource{ID: hex.EncodeToString(id[:]), Name: name, Kind: input.Kind, URL: strings.TrimSpace(input.URL)}
	return sm.importSource(ctx, source, input.Content)
}

func (sm *SubscriptionManager) RefreshSource(ctx context.Context, id string) ([]models.Server, error) {
	sm.operationMu.Lock()
	defer sm.operationMu.Unlock()
	sm.mu.RLock()
	index := sm.sourceIndexLocked(id)
	if index == -1 {
		sm.mu.RUnlock()
		return nil, ErrSourceNotFound
	}
	source := sm.data.Sources[index]
	sm.mu.RUnlock()
	if source.Kind != "subscription" || source.URL == "" {
		return nil, errors.New("обновить по сети можно только подписку по ссылке")
	}
	return sm.importSource(ctx, source, "")
}

func (sm *SubscriptionManager) importSource(ctx context.Context, source models.SubscriptionSource, content string) ([]models.Server, error) {
	sm.mu.RLock()
	for _, s := range sm.data.Sources {
		if s.ID == source.ID {
			continue
		}
		if source.URL != "" && s.URL == source.URL {
			sm.mu.RUnlock()
			return nil, errors.New("эта ссылка подписки уже добавлена")
		}
		if strings.EqualFold(source.Name, s.Name) {
			sm.mu.RUnlock()
			return nil, errors.New("такое название уже используется")
		}
	}
	sm.mu.RUnlock()
	var fresh []models.Server
	var err error
	switch source.Kind {
	case "subscription":
		if content != "" {
			return nil, errors.New("для подписки по ссылке укажите только URL")
		}
		fresh, err = sm.downloadAndParseContext(ctx, source.URL)
		if err != nil {
			return nil, err
		}
		source.Report = cloneSubscriptionImportReport(sm.pendingImportReport)
	case "file", "server":
		if source.URL != "" || len(content) == 0 || len(content) > 4<<20 {
			return nil, errors.New("нужно содержимое файла или ссылка сервера размером до 4 МиБ")
		}
		fresh, source.Report, err = ParseSubscriptionDetailed(content)
		if err != nil {
			return nil, errors.New("источник не содержит поддерживаемых серверов; проверьте формат ссылки или файла")
		}
	default:
		return nil, errors.New("неизвестный тип источника")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	source.LastUpdated = time.Now()
	previous := cloneSubscriptionData(*sm.data)
	index := sm.sourceIndexLocked(source.ID)
	if index < 0 {
		sm.data.Sources = append(sm.data.Sources, source)
	} else {
		sm.data.Sources[index] = source
	}
	fresh = sm.replaceSourceServersLocked(source, fresh)
	if err = sm.saveCatalogLocked(previous); err != nil {
		return nil, err
	}
	return cloneSubscriptionServers(fresh), nil
}

func (sm *SubscriptionManager) sourceIndexLocked(id string) int {
	for i, s := range sm.data.Sources {
		if s.ID == id {
			return i
		}
	}
	return -1
}

func (sm *SubscriptionManager) RenameSource(id, name string) error {
	name = strings.TrimSpace(name)
	if !validSourceName(name) {
		return errors.New("введите название источника до 80 символов без ссылок")
	}
	sm.operationMu.Lock()
	defer sm.operationMu.Unlock()
	sm.mu.Lock()
	defer sm.mu.Unlock()
	index := sm.sourceIndexLocked(id)
	if index < 0 {
		return ErrSourceNotFound
	}
	for _, s := range sm.data.Sources {
		if s.ID != id && strings.EqualFold(s.Name, name) {
			return errors.New("такое название уже используется")
		}
	}
	previous := cloneSubscriptionData(*sm.data)
	sm.data.Sources[index].Name = name
	for i := range sm.data.Servers {
		if sm.data.Servers[i].SourceID == id {
			sm.data.Servers[i].SourceName = name
		}
	}
	return sm.saveCatalogLocked(previous)
}

func (sm *SubscriptionManager) DeleteSource(id string) error {
	sm.operationMu.Lock()
	defer sm.operationMu.Unlock()
	sm.mu.Lock()
	defer sm.mu.Unlock()
	index := sm.sourceIndexLocked(id)
	if index < 0 {
		return ErrSourceNotFound
	}
	previous := cloneSubscriptionData(*sm.data)
	source := sm.data.Sources[index]
	sm.data.Sources = append(sm.data.Sources[:index], sm.data.Sources[index+1:]...)
	sm.replaceSourceServersLocked(source, nil)
	return sm.saveCatalogLocked(previous)
}

func (sm *SubscriptionManager) saveCatalogLocked(previous models.SubscriptionData) error {
	previousReport := sm.importReport
	d := sm.data
	d.CatalogVersion = 1
	d.URL, d.SourceKind = "", ""
	if len(d.Sources) > 0 {
		d.URL, d.SourceKind = d.Sources[0].URL, d.Sources[0].Kind
	}
	d.LastUpdated = time.Now()
	sm.importReport = ImportReport{Imported: len(d.Servers)}
	for _, s := range d.Sources {
		r := s.Report
		sm.importReport.ImportedProfiles += r.ImportedProfiles
		sm.importReport.SkippedComposite += r.SkippedComposite
		sm.importReport.SkippedUnsupported += r.SkippedUnsupported
		sm.importReport.Warnings = append(sm.importReport.Warnings, r.Warnings...)
	}
	if err := sm.saveLocked(); err != nil {
		sm.data, sm.importReport = &previous, previousReport
		return err
	}
	sm.rollbackSnapshotKey, sm.rollbackImportReport = subscriptionSnapshotKey(previous), previousReport
	return nil
}

func sourceServerKey(s models.Server) string {
	if key := ServiceTargetID(s); key != "" {
		return key
	}
	return ServerIdentity(s)
}

// Numeric IDs belong to an occurrence inside a source. Card assignments use
// ServiceTargetID, so the same endpoint can survive removal of either owner.
func (sm *SubscriptionManager) replaceSourceServersLocked(source models.SubscriptionSource, fresh []models.Server) []models.Server {
	d := sm.data
	activeID := -1
	if d.ActiveID >= 0 && d.ActiveID < len(d.Servers) {
		activeID = d.Servers[d.ActiveID].ID
	}
	bySource := make(map[string][]models.Server, len(d.Sources))
	old := make(map[string][]models.Server)
	for _, s := range d.Servers {
		if s.SourceID == source.ID {
			key := sourceServerKey(s)
			old[key] = append(old[key], s)
		} else {
			bySource[s.SourceID] = append(bySource[s.SourceID], s)
		}
	}
	fresh = cloneSubscriptionServers(fresh)
	for i := range fresh {
		s := &fresh[i]
		s.SourceID, s.SourceName = source.ID, source.Name
		key := sourceServerKey(*s)
		if matches := old[key]; key != "" && len(matches) != 0 {
			prev := matches[0]
			s.ID, s.CountryOverride = prev.ID, prev.CountryOverride
			s.Latency, s.LastChecked, s.ProbeKind, s.CheckError = prev.Latency, prev.LastChecked, prev.ProbeKind, prev.CheckError
			s.ExitCountry, s.ExitCheckedAt = prev.ExitCountry, prev.ExitCheckedAt
			s.EntryCountry = prev.EntryCountry
			old[key] = matches[1:]
		} else {
			s.ID = d.NextServerID
			d.NextServerID++
		}
	}
	bySource[source.ID] = fresh
	d.Servers = make([]models.Server, 0)
	for _, src := range d.Sources {
		d.Servers = append(d.Servers, bySource[src.ID]...)
	}
	d.ActiveID = 0 // legacy field is the active position, including after reorder
	for i, s := range d.Servers {
		if s.ID == activeID {
			d.ActiveID = i
			break
		}
	}
	for i := range d.Servers {
		d.Servers[i].Active = i == d.ActiveID
	}
	for i := range fresh {
		fresh[i].Active = len(d.Servers) != 0 && fresh[i].ID == d.Servers[d.ActiveID].ID
	}
	return fresh
}
