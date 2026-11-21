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
	// This older single-source call may swap in a different provider. Only a
	// repeated download of the same link continues the previous servers.
	sameLink := input.Content == "" && source.Kind == input.Kind && source.URL != "" && source.URL == strings.TrimSpace(input.URL)
	source.Kind, source.URL = input.Kind, strings.TrimSpace(input.URL)
	if source.Name == "" {
		source.Name = defaultSourceName(source.Kind, source.URL)
	}
	return sm.importSource(context.Background(), source, input.Content, sameLink)
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
	return sm.importSource(ctx, source, input.Content, false)
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
	return sm.importSource(ctx, source, "", true)
}

// continued says that the import continues the same subscription, so a server
// whose parameters changed under an unchanged name is still the same server.
func (sm *SubscriptionManager) importSource(ctx context.Context, source models.SubscriptionSource, content string, continued bool) ([]models.Server, error) {
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
	fresh, moves := sm.replaceSourceServersLocked(source, fresh, continued)
	sm.pendingMoves = nil
	if err = sm.saveCatalogLocked(previous); err != nil {
		return nil, err
	}
	sm.pendingMoves = moves
	return cloneSubscriptionServers(fresh), nil
}

// TargetMove says that one named entry of a source stayed in the catalogue
// while its connection parameters, and therefore its target identity, changed.
type TargetMove struct {
	SourceID string
	From, To string
}

// FollowableTargets resolves identity changes for selections that store no
// source. A change is usable only when the catalogue holds its result and no
// other subscription reissued the same parameters differently. The caller
// still follows it only for a selection whose own target left the catalogue:
// another subscription may keep offering exactly the chosen server.
func FollowableTargets(moves []TargetMove, present map[string]bool) map[string]string {
	replacement := map[string]string{}
	ambiguous := map[string]bool{}
	for _, move := range moves {
		if move.From == "" || move.From == move.To || !present[move.To] {
			continue
		}
		if to, seen := replacement[move.From]; seen && to != move.To {
			ambiguous[move.From] = true
			continue
		}
		replacement[move.From] = move.To
	}
	for from := range ambiguous {
		delete(replacement, from)
	}
	return replacement
}

// ChangedFields names the connection settings that the latest import found
// changed under unchanged server names. It lists setting names only, never
// values, so the journal can show what a provider keeps reissuing.
func (sm *SubscriptionManager) ChangedFields() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return append([]string(nil), sm.changedFields...)
}

// TakeTargetMoves hands over the identity changes of the latest import once.
// The caller applies them to saved selections in the same transaction.
func (sm *SubscriptionManager) TakeTargetMoves() []TargetMove {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	moves := sm.pendingMoves
	sm.pendingMoves = nil
	return moves
}

// ReplaceSourceURL points an existing subscription at a new link, for example
// after the provider moved to another domain. Servers keep their IDs, country
// corrections and selections through the same matching as an ordinary refresh.
func (sm *SubscriptionManager) ReplaceSourceURL(ctx context.Context, id, rawURL string) ([]models.Server, error) {
	sm.operationMu.Lock()
	defer sm.operationMu.Unlock()
	rawURL = strings.TrimSpace(rawURL)
	sm.mu.RLock()
	index := sm.sourceIndexLocked(id)
	if index == -1 {
		sm.mu.RUnlock()
		return nil, ErrSourceNotFound
	}
	source := sm.data.Sources[index]
	sm.mu.RUnlock()
	if source.Kind != "subscription" {
		return nil, errors.New("заменить ссылку можно только у подписки по ссылке")
	}
	if rawURL == "" || rawURL == source.URL {
		return nil, errors.New("укажите новую ссылку подписки")
	}
	source.URL = rawURL
	return sm.importSource(ctx, source, "", true)
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
	sm.replaceSourceServersLocked(source, nil, false)
	sm.pendingMoves = nil
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
func (sm *SubscriptionManager) replaceSourceServersLocked(source models.SubscriptionSource, fresh []models.Server, continued bool) ([]models.Server, []TargetMove) {
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
	inherit := func(s *models.Server, prev models.Server) {
		s.ID, s.CountryOverride = prev.ID, prev.CountryOverride
		s.Latency, s.LastChecked, s.ProbeKind, s.CheckError = prev.Latency, prev.LastChecked, prev.ProbeKind, prev.CheckError
	}
	var changed []int
	for i := range fresh {
		s := &fresh[i]
		s.SourceID, s.SourceName = source.ID, source.Name
		key := sourceServerKey(*s)
		if matches := old[key]; key != "" && len(matches) != 0 {
			inherit(s, matches[0])
			old[key] = matches[1:]
		} else {
			changed = append(changed, i)
		}
	}
	// A provider may reissue the parameters of every server on each download
	// while keeping its name. To the owner this is still the same server, so
	// it keeps its ID and country correction. A latency measured through the
	// previous parameters says nothing about the new ones and is not carried
	// over. Only a name that is unique among the leftovers on both sides
	// identifies such an entry.
	type label struct {
		profile bool
		name    string
	}
	labelOf := func(s models.Server) label {
		return label{len(s.RawProfile) > 0, strings.TrimSpace(s.Name)}
	}
	previous := map[label][]models.Server{}
	for _, rest := range old {
		for _, s := range rest {
			previous[labelOf(s)] = append(previous[labelOf(s)], s)
		}
	}
	renamed := map[label]int{}
	for _, i := range changed {
		renamed[labelOf(fresh[i])]++
	}
	var moves []TargetMove
	fields := map[string]bool{}
	for _, i := range changed {
		s := &fresh[i]
		name := labelOf(*s)
		if matches := previous[name]; continued && name.name != "" && len(matches) == 1 && renamed[name] == 1 {
			s.ID, s.CountryOverride = matches[0].ID, matches[0].CountryOverride
			for _, field := range changedOutboundFields(matches[0], *s) {
				fields[field] = true
			}
			from, to := ServiceTargetID(matches[0]), ServiceTargetID(*s)
			if from != "" && to != "" && from != to {
				moves = append(moves, TargetMove{SourceID: source.ID, From: from, To: to})
			}
			continue
		}
		s.ID = d.NextServerID
		d.NextServerID++
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
	sm.changedFields = sortedFieldNames(fields)
	return fresh, moves
}
