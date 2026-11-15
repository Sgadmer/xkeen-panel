package cardcontroller

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"xkeen-panel/internal/geoip"
	"xkeen-panel/internal/xkeen"
)

const serviceListsKey = "x-xkeen-panel-service-lists"
const serviceListsVersion = 1
const serviceListInterval = 24 * time.Hour
const serviceListMaxBytes = 2 << 20

// The same maintained domain datasets used by Xkeen-UI's Mihomo templates.
// Text is validated and installed as one immutable snapshot instead of letting
// independent HTTP providers replace an active subset during an outage.
var serviceListTags = map[string]string{
	"claude": "anthropic", "openai": "openai", "analytics": "category-telemetry", "youtube": "youtube", "telegram": "telegram",
	"discord": "discord", "spotify": "spotify", "github": "github", "steam": "steam",
	"playstation": "playstation", "xbox": "xbox", "instagram": "instagram", "whatsapp": "whatsapp",
	"facebook": "facebook", "netflix": "netflix", "twitch": "twitch", "disney": "disney",
	"primevideo": "primevideo", "amazon": "amazon", "twitter": "twitter", "hulu": "hulu",
	"hbo": "hbo", "line": "line", "google": "google", "ai": "category-ai-!cn",
}

// Shared dependencies have one explicit destination policy. A router cannot
// discover which phone app owns a request to a shared purchases/auth host.
var openAISharedDomains = []string{
	"api.revenuecat.com", "api.rc-backup.com", "cdn.workos.com", "forwarder.workos.com",
	"frontend-apps-multi-region.workos.com", "setup.workos.com", "images.workoscdn.com",
	"workos.imgix.net", "chatgpt.livekit.cloud", "host.livekit.cloud", "turn.livekit.cloud",
	"o33249.ingest.sentry.io", "o33249.ingest.us.sentry.io",
}

type ServiceListsStatus struct {
	Enabled            bool   `json:"enabled"`
	Ready              bool   `json:"ready"`
	Updating           bool   `json:"updating"`
	Source             string `json:"source"`
	Sources            int    `json:"sources"`
	Domains            int    `json:"domains"`
	UpdatedAt          string `json:"updated_at,omitempty"`
	CheckedAt          string `json:"checked_at,omitempty"`
	NextCheckAt        string `json:"next_check_at,omitempty"`
	Error              string `json:"error,omitempty"`
	SharedDependencies string `json:"shared_dependencies"`
}

type serviceListFile struct {
	Hash  string `json:"hash"`
	Count int    `json:"count"`
}

type serviceListsCache struct {
	Version    int                        `json:"version"`
	Enabled    bool                       `json:"enabled"`
	UpdatedAt  string                     `json:"updated_at"`
	CheckedAt  string                     `json:"checked_at"`
	DrainToken string                     `json:"drain_token,omitempty"`
	Files      map[string]serviceListFile `json:"files"`
}

func serviceProviderName(id string) string { return "XKP-service-" + id }

func serviceGuardName(id string) string { return cardPrefix + "guard-" + id }

// Specific AI cards remain first, and the general AI category precedes broad
// Google domains. This changes classifier precedence only, not the user's UI
// order or any saved service/server selection.
func serviceListOrder(services []xkeen.ServiceRouteView) []xkeen.ServiceRouteView {
	ordered := make([]xkeen.ServiceRouteView, 0, len(services))
	var ai *xkeen.ServiceRouteView
	for i := range services {
		if services[i].ID == "ai" {
			ai = &services[i]
			break
		}
	}
	if ai == nil {
		return services
	}
	inserted := false
	for _, service := range services {
		if service.ID == "ai" {
			continue
		}
		ordered = append(ordered, service)
		if service.ID == "openai" {
			ordered = append(ordered, *ai)
			inserted = true
		}
	}
	if !inserted {
		ordered = append(ordered, *ai)
	}
	return ordered
}

func discordVoicePredicate(condition string) string {
	return "AND,((" + condition + "),(NETWORK,udp),(DST-PORT,19200-19400/50000-51000))"
}

// The old migration imported shared CDN prefixes as unconditional Discord
// classifiers. Retain their intended voice use, restricted by transport and
// ports, both in the card and the owner's trailing rules. The correction is
// idempotent and remains safe when automatic dataset updates are disabled.
func scopeDiscordRule(rule string) string {
	parts, end := targetPart(rule)
	if end < 1 || parts[end] != groupNames["discord"] {
		return rule
	}
	switch parts[0] {
	case "IP-CIDR", "IP-CIDR6", "GEOIP":
		return discordVoicePredicate(ruleCondition(parts, end)) + "," + parts[end]
	}
	return rule
}

func serviceListsEnabled(doc map[string]interface{}) bool {
	info, err := readServiceLists(doc)
	return err == nil && info.Enabled
}

func readServiceLists(doc map[string]interface{}) (serviceListsCache, error) {
	info := serviceListsCache{Files: map[string]serviceListFile{}}
	raw, exists := doc[serviceListsKey]
	if !exists {
		return info, nil
	}
	metadata := object(raw)
	_, hasEnabled := metadata["enabled"].(bool)
	data, err := json.Marshal(raw)
	if !hasEnabled || err != nil || json.Unmarshal(data, &info) != nil || info.Version != serviceListsVersion || len(info.Files) > len(serviceListTags) {
		return info, errors.New("повреждены настройки обновляемых списков сервисов")
	}
	// A panel upgrade must keep the last complete 24-service snapshot usable
	// while the newly introduced telemetry dataset is still being downloaded.
	// Every original dataset remains mandatory; an incomplete critical cache
	// is never accepted as a legacy snapshot.
	for id := range serviceListTags {
		if _, found := info.Files[id]; !found && id != "analytics" {
			return info, errors.New("повреждены настройки обновляемых списков сервисов")
		}
	}
	for id, file := range info.Files {
		if serviceListTags[id] == "" || !validHash(file.Hash) || file.Count <= 0 || file.Count > 100000 {
			return info, errors.New("повреждена сохранённая база сервиса")
		}
	}
	for _, stamp := range []string{info.CheckedAt, info.UpdatedAt} {
		if _, err := time.Parse(time.RFC3339, stamp); err != nil {
			return info, errors.New("повреждена дата обновления списков сервисов")
		}
	}
	if info.DrainToken != "" {
		if _, err := time.Parse(time.RFC3339Nano, info.DrainToken); err != nil {
			return info, errors.New("повреждено состояние переподключения сервисов")
		}
	}
	return info, nil
}

func (info serviceListsCache) status(problem string) ServiceListsStatus {
	n := 0
	for _, file := range info.Files {
		n += file.Count
	}
	status := ServiceListsStatus{
		Enabled: true, Ready: info.Enabled && len(info.Files) == len(serviceListTags), Source: "MetaCubeX / v2fly", Sources: len(info.Files), Domains: n,
		UpdatedAt: info.UpdatedAt, CheckedAt: info.CheckedAt, Error: problem,
		SharedDependencies: "Общие адреса аналитики, диагностики и проверки безопасности используют карточку «Аналитика и диагностика». Адреса оплаты RevenueCat, входа WorkOS и голосовой связи LiveKit идут через сервер ChatGPT. Одними адресами могут пользоваться разные приложения.",
	}
	if checked, err := time.Parse(time.RFC3339, info.CheckedAt); err == nil {
		status.NextCheckAt = checked.Add(serviceListInterval).Format(time.RFC3339)
	}
	return status
}

func (c *Controller) ServiceListsStatus() (ServiceListsStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return ServiceListsStatus{}, err
	}
	info, err := readServiceLists(p.doc)
	status := c.serviceListStatus(info, c.serviceListsError)
	return status, err
}

func (c *Controller) serviceListStatus(info serviceListsCache, problem string) ServiceListsStatus {
	status := info.status(problem)
	status.Updating = c.serviceListsUpdating
	checked, _ := time.Parse(time.RFC3339, info.CheckedAt)
	now := time.Now().UTC()
	if !status.Ready || now.Sub(checked) >= serviceListInterval {
		next := c.serviceListsAttempt.Add(5 * time.Minute)
		if c.serviceListsAttempt.IsZero() || next.Before(now) {
			next = now
		}
		status.NextCheckAt = next.Format(time.RFC3339)
	}
	return status
}

// EnsureServiceLists keeps the classifier datasets active independently of the
// routing mode and browser. A legacy disabled cache is reactivated without a
// download; an overdue cache is refreshed on the following maintenance tick.
func (c *Controller) EnsureServiceLists(ctx context.Context) (ServiceListsStatus, error) {
	return c.UpdateServiceLists(ctx, nil, false)
}

// A failed download, an unexpected source format or a rejected reload keeps
// every old file and the previous live policy. nil enables automatic daily
// maintenance; only an explicit refresh bypasses its interval and retry delay.
// enabled=true is retained for older clients; disabling is no longer allowed.
func (c *Controller) UpdateServiceLists(ctx context.Context, enabled *bool, force bool) (ServiceListsStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return ServiceListsStatus{}, err
	}
	old, err := readServiceLists(p.doc)
	if err != nil {
		return ServiceListsStatus{}, err
	}
	if enabled != nil && !*enabled {
		return c.serviceListStatus(old, c.serviceListsError), errors.New("списки сервисов обновляются автоматически; отключение недоступно")
	}
	if c.serviceListsUpdating {
		status := c.serviceListStatus(old, c.serviceListsError)
		status.Updating = true
		return status, errors.New("списки сервисов уже обновляются")
	}
	if err := c.finishServiceListsDrain(ctx, p, old); err != nil {
		c.serviceListsError = err.Error()
		return c.serviceListStatus(old, c.serviceListsError), err
	}
	next := old
	next.Enabled = true
	now := time.Now().UTC()
	checked, _ := time.Parse(time.RFC3339, old.CheckedAt)
	hasCache := len(old.Files) == len(serviceListTags)
	download := force || !hasCache || old.Enabled && now.Sub(checked) >= serviceListInterval
	if !download && old.Enabled {
		return c.serviceListStatus(old, c.serviceListsError), nil
	}
	if download && !force && !c.serviceListsAttempt.IsZero() && now.Sub(c.serviceListsAttempt) < 5*time.Minute {
		return c.serviceListStatus(old, c.serviceListsError), nil
	}
	fail := func(err error) (ServiceListsStatus, error) {
		c.serviceListsError = err.Error()
		return c.serviceListStatus(old, c.serviceListsError), err
	}
	dir := filepath.Dir(c.path)
	if download {
		c.serviceListsAttempt = now
		// Downloading public datasets does not own the routing transaction.
		// Status/diagnostics and unrelated edits remain usable during an outage.
		c.serviceListsUpdating = true
		c.mu.Unlock()
		files, downloadErr := c.downloadServiceLists(ctx)
		c.mu.Lock()
		c.serviceListsUpdating = false
		fresh, err := c.read()
		if err != nil {
			return fail(err)
		}
		current, err := readServiceLists(fresh.doc)
		if err != nil {
			return fail(err)
		}
		if !reflect.DeepEqual(current, old) {
			return c.serviceListStatus(current, c.serviceListsError), errors.New("списки сервисов изменены параллельно; повторите обновление")
		}
		if downloadErr != nil {
			return fail(downloadErr)
		}
		next.Version, next.Files, next.CheckedAt = serviceListsVersion, map[string]serviceListFile{}, now.Format(time.RFC3339)
		changed := len(old.Files) != len(files)
		for id, file := range files {
			hash, err := saveRuleFile(dir, serviceProviderName(id), file)
			if err != nil {
				c.cleanServiceListCandidates(next, old)
				return fail(fmt.Errorf("не удалось сохранить список %s", groupNames[id]))
			}
			next.Files[id] = serviceListFile{Hash: hash, Count: file.Count}
			changed = changed || old.Files[id] != next.Files[id]
		}
		if changed {
			next.UpdatedAt = now.Format(time.RFC3339)
			next.DrainToken = now.Format(time.RFC3339Nano)
		}
	}
	if next.Enabled != old.Enabled {
		next.DrainToken = now.Format(time.RFC3339Nano)
	}
	_, err = c.apply(ctx, "", "", func(candidate *profile) error {
		if err := configureDomainPolicy(candidate.doc, next.Enabled); err != nil {
			return err
		}
		if _, exists := candidate.doc[serviceListsKey]; !exists {
			providers := object(candidate.doc["rule-providers"])
			for id := range serviceListTags {
				if _, conflict := providers[serviceProviderName(id)]; conflict {
					return errors.New("имя набора правил сервиса уже занято")
				}
			}
		}
		data, _ := json.Marshal(next)
		var value map[string]interface{}
		_ = json.Unmarshal(data, &value)
		candidate.doc[serviceListsKey] = value
		return nil
	})
	if err != nil {
		c.cleanServiceListCandidates(next, old)
		return fail(err)
	}
	current, err := c.read()
	if err != nil {
		return c.serviceListStatus(next, err.Error()), err
	}
	if err := c.finishServiceListsDrain(ctx, current, next); err != nil {
		c.serviceListsError = err.Error()
		return c.serviceListStatus(next, c.serviceListsError), err
	}
	for id, file := range old.Files {
		if file.Hash != next.Files[id].Hash {
			_ = os.Remove(filepath.Join(dir, refilterPath(serviceProviderName(id), file.Hash)))
		}
	}
	c.serviceListsError = ""
	return c.serviceListStatus(next, ""), nil
}

func (c *Controller) cleanServiceListCandidates(next, old serviceListsCache) {
	p, err := c.read()
	if err != nil {
		return
	}
	current, err := readServiceLists(p.doc)
	if err != nil {
		return
	}
	for id, file := range next.Files {
		if validHash(file.Hash) && file.Hash != old.Files[id].Hash && file.Hash != current.Files[id].Hash {
			_ = os.Remove(filepath.Join(filepath.Dir(c.path), refilterPath(serviceProviderName(id), file.Hash)))
		}
	}
}

func (c *Controller) downloadServiceLists(ctx context.Context) (map[string]geoip.RuleFile, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	jobs := make(chan string, len(serviceListTags))
	for id := range serviceListTags {
		jobs <- id
	}
	close(jobs)
	type result struct {
		id   string
		file geoip.RuleFile
		err  error
	}
	results := make(chan result, len(serviceListTags))
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for id := range jobs {
				file, err := c.downloadServiceList(ctx, id)
				results <- result{id, file, err}
			}
		}()
	}
	workers.Wait()
	close(results)
	files := map[string]geoip.RuleFile{}
	var problem error
	for r := range results {
		if r.err != nil && problem == nil {
			problem = r.err
		}
		files[r.id] = r.file
	}
	return files, problem
}

func (c *Controller) downloadServiceList(ctx context.Context, id string) (geoip.RuleFile, error) {
	url := "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/" + serviceListTags[id] + ".list"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return geoip.RuleFile{}, err
	}
	req.Header.Set("User-Agent", "XKeen-Panel-service-rules/1")
	resp, err := c.http.Do(req)
	if err != nil {
		return geoip.RuleFile{}, fmt.Errorf("не удалось скачать список %s; сохранена прежняя база", groupNames[id])
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return geoip.RuleFile{}, fmt.Errorf("источник списка %s ответил HTTP %d; сохранена прежняя база", groupNames[id], resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, serviceListMaxBytes+1))
	if err != nil {
		return geoip.RuleFile{}, fmt.Errorf("не удалось дочитать список %s", groupNames[id])
	}
	file, err := normalizeServiceList(data)
	if err != nil {
		return geoip.RuleFile{}, fmt.Errorf("список %s имеет неожиданный формат; сохранена прежняя база", groupNames[id])
	}
	return file, nil
}

func normalizeServiceList(data []byte) (geoip.RuleFile, error) {
	if len(data) == 0 || len(data) > serviceListMaxBytes || !utf8.Valid(data) {
		return geoip.RuleFile{}, errors.New("недопустимый размер или кодировка")
	}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host := strings.TrimPrefix(line, "+.")
		_, numeric := netip.ParseAddr(host)
		if !validServiceDomain(host) || numeric == nil || !strings.HasPrefix(line, "+.") && !strings.Contains(host, ".") {
			return geoip.RuleFile{}, errors.New("неподдерживаемое доменное правило")
		}
		seen[line] = true
	}
	if scanner.Err() != nil || len(seen) == 0 || len(seen) > 100000 {
		return geoip.RuleFile{}, errors.New("пустой или повреждённый набор")
	}
	lines := make([]string, 0, len(seen))
	for line := range seen {
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return geoip.RuleFile{Data: []byte(strings.Join(lines, "\n") + "\n"), Count: len(lines), Behavior: "domain"}, nil
}

func validServiceDomain(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, ",:/*\\ \t\r\n") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if ch < 'a' || ch > 'z' {
				if ch < '0' || ch > '9' {
					if ch != '-' && ch != '_' {
						return false
					}
				}
			}
		}
	}
	return true
}

func serviceListProviders(doc map[string]interface{}, info serviceListsCache) error {
	providers := object(doc["rule-providers"])
	if raw, exists := doc["rule-providers"]; exists && raw != nil && providers == nil {
		return errors.New("неподдерживаемый формат rule-providers")
	}
	if providers == nil && info.Enabled {
		providers = map[string]interface{}{}
		doc["rule-providers"] = providers
	}
	for id, file := range info.Files {
		name := serviceProviderName(id)
		if info.Enabled {
			providers[name] = map[string]interface{}{"type": "file", "behavior": "domain", "format": "text", "path": refilterPath(name, file.Hash)}
		} else {
			delete(providers, name)
		}
	}
	return nil
}

func (a coreAPI) serviceListsReady(ctx context.Context, doc map[string]interface{}) bool {
	info, err := readServiceLists(doc)
	if err != nil {
		return false
	}
	if !info.Enabled {
		return true
	}
	var response struct {
		Providers map[string]struct {
			RuleCount int
			Behavior  string
		}
	}
	if a.request(ctx, http.MethodGet, "/providers/rules", nil, &response) != nil {
		return false
	}
	for id, file := range info.Files {
		provider := response.Providers[serviceProviderName(id)]
		if provider.RuleCount != file.Count || !strings.EqualFold(provider.Behavior, "domain") {
			return false
		}
	}
	return true
}

func serviceListDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
