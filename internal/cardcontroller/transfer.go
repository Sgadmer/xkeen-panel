package cardcontroller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

// Portable is the part of the card controller's state that makes sense on
// another router or after a reinstall: the owner's choices, written with
// names instead of the identifiers of this installation.
//
// It carries no secret. A server is named by its subscription and its own
// name, never by its address or keys; the importing router finds it again in
// its own subscriptions or leaves that route as it is.
type Portable struct {
	KillSwitch     *PortableKillSwitch      `json:"kill_switch,omitempty"`
	RoutingMode    string                   `json:"routing_mode,omitempty"` // protected | blocklist
	DNS            *DNSSettings             `json:"dns,omitempty"`
	CustomServices []PortableService        `json:"custom_services,omitempty"`
	Exclusions     []PortableExclusion      `json:"exclusions,omitempty"`
	Routes         map[string]PortableRoute `json:"routes,omitempty"`
}

// Cards are keyed by the identifier of a built-in card or by "custom:" and
// the name of the owner's card.
type PortableKillSwitch struct {
	Enabled bool              `json:"enabled"`
	Cards   map[string]string `json:"cards,omitempty"`
}

type PortableService struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

type PortableExclusion struct {
	Value    string `json:"value"`
	Comment  string `json:"comment,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
}

type PortableRoute struct {
	Kind    string `json:"kind"` // direct | auto | country | server | pool | source
	Country string `json:"country,omitempty"`
	Source  string `json:"source,omitempty"` // the subscription a server belongs to
	Name    string `json:"name,omitempty"`   // of the server or of the multipool
}

// ImportSection is one group of changes the owner accepts or leaves out.
type ImportSection struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Changes []string `json:"changes"`
	Skipped []string `json:"skipped,omitempty"`
	// The changes lower protection. They are applied only when chosen on purpose.
	Weakens bool `json:"weakens,omitempty"`
}

const customKeyPrefix = "custom:"

func portableKey(id string) string {
	for _, custom := range xkeen.CustomServices() {
		if custom.ID == id {
			return customKeyPrefix + custom.Name
		}
	}
	return id
}

// cardOfKey finds the card a portable key names on this router.
func cardOfKey(key string) (id, name string, found bool) {
	if wanted, custom := strings.CutPrefix(key, customKeyPrefix); custom {
		for _, service := range xkeen.CustomServices() {
			if strings.EqualFold(service.Name, wanted) {
				return service.ID, service.Name, true
			}
		}
		return "", wanted, false
	}
	if display := groupNames[key]; display != "" {
		for _, service := range xkeen.ServiceNames() {
			if service.ID == key {
				return key, service.Name, true
			}
		}
	}
	return "", key, false
}

func (c *Controller) routingMode(p profile) string {
	info, err := readRefilter(p.doc)
	if err != nil {
		return ""
	}
	if mode := c.routingModeStatus(p, info.status("")).Mode; mode == "protected" || mode == "blocklist" {
		return mode
	}
	return ""
}

func (c *Controller) portableRoute(p profile, target string, servers []models.Server) (PortableRoute, bool) {
	switch {
	case target == directTarget:
		return PortableRoute{Kind: "direct"}, true
	case target == allPoolID:
		return PortableRoute{Kind: "auto"}, true
	case countryPoolCodes[target] != "":
		return PortableRoute{Kind: "country", Country: countryPoolCodes[target]}, true
	}
	for _, pool := range p.pools {
		if pool.ID == target {
			return PortableRoute{Kind: "pool", Name: pool.Name}, true
		}
	}
	if p.sourcePool(target) != "" {
		return PortableRoute{Kind: "source", Name: p.pool(target).Name}, true
	}
	for _, server := range servers {
		if xkeen.ServiceTargetID(server) == target {
			return PortableRoute{Kind: "server", Source: server.SourceName, Name: server.Name}, true
		}
	}
	return PortableRoute{}, false
}

// ExportPortable collects the owner's choices. dataDir holds the exclusions.
func (c *Controller) ExportPortable(dataDir string) (Portable, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return Portable{}, err
	}
	policy, err := readKillSwitch(p.doc)
	if err != nil {
		return Portable{}, err
	}
	result := Portable{KillSwitch: &PortableKillSwitch{Enabled: policy.Enabled, Cards: map[string]string{}}, RoutingMode: c.routingMode(p), Routes: map[string]PortableRoute{}}
	for id, mode := range policy.Services {
		result.KillSwitch.Cards[portableKey(id)] = mode
	}
	if dns := readDNS(p.doc); !dns.Foreign {
		settings := dns.DNSSettings
		result.DNS = &settings
	}
	for _, service := range xkeen.CustomServices() {
		result.CustomServices = append(result.CustomServices, PortableService{Name: service.Name, Addresses: service.Addresses()})
	}
	entries, err := currentExclusions(p, dataDir)
	if err != nil {
		return Portable{}, err
	}
	for _, entry := range entries.Entries {
		result.Exclusions = append(result.Exclusions, PortableExclusion{Value: entry.Value, Comment: entry.Comment, Disabled: entry.Disabled})
	}
	servers := c.catalog()
	for id, target := range p.assigned {
		if id == defaultID || !knownCard(id) {
			continue
		}
		if route, ok := c.portableRoute(p, target, servers); ok {
			result.Routes[portableKey(id)] = route
		}
	}
	return result, nil
}

// One step of an import: what the owner reads and how it is carried out.
type importStep struct {
	section string
	text    string
	run     func(context.Context) error
}

var importSections = []struct {
	id, title string
	weakens   bool
}{
	{"custom_services", "Свои сервисы", false},
	{"exclusions", "Исключения", false},
	{"routing_mode", "Защищённый режим", false},
	{"kill_switch", "Kill switch", false},
	{"dns", "DNS ядра", false},
	{"routes", "Маршруты карточек", false},
	{"weak_kill_switch", "Выключение kill switch", true},
	{"weak_routing_mode", "Режим «только по списку блокировок»", true},
	{"weak_routes", "Маршрут «Напрямую»", true},
}

func routeText(route PortableRoute) string {
	switch route.Kind {
	case "direct":
		return "напрямую"
	case "auto":
		return "автовыбор"
	case "country":
		return "пул страны " + strings.ToUpper(route.Country)
	case "pool":
		return "мультипул «" + route.Name + "»"
	case "source":
		return "пул подписки «" + route.Name + "»"
	}
	if route.Source != "" {
		return "сервер «" + route.Name + "» (" + route.Source + ")"
	}
	return "сервер «" + route.Name + "»"
}

// resolveRoute finds the target of a portable route on this router.
func resolveRoute(p profile, route PortableRoute, servers []models.Server) (string, error) {
	switch route.Kind {
	case "direct":
		return directTarget, nil
	case "auto":
		return allPoolID, nil
	case "country":
		id := scopeHash("country:" + strings.ToUpper(route.Country))
		if countryPoolCodes[id] == "" {
			return "", errors.New("неизвестная страна")
		}
		return id, nil
	case "pool":
		for _, pool := range p.pools {
			if strings.EqualFold(pool.Name, route.Name) {
				return pool.ID, nil
			}
		}
		return "", fmt.Errorf("мультипула «%s» здесь нет", route.Name)
	case "source":
		for _, pool := range p.sourcePools {
			if strings.EqualFold(pool.Name, route.Name) {
				return pool.ID, nil
			}
		}
		return "", fmt.Errorf("подписки «%s» здесь нет", route.Name)
	case "server":
		found := ""
		for _, server := range servers {
			if server.Name != route.Name || route.Source != "" && server.SourceName != route.Source {
				continue
			}
			id := xkeen.ServiceTargetID(server)
			if id == "" || found != "" && found != id {
				return "", fmt.Errorf("сервер «%s» здесь определяется неоднозначно", route.Name)
			}
			found = id
		}
		if found == "" {
			return "", fmt.Errorf("сервера «%s» в подписках этого роутера нет", route.Name)
		}
		return found, nil
	}
	return "", errors.New("неизвестный вид маршрута")
}

// planImport compares the file with this router. The caller holds c.mu.
func (c *Controller) planImport(p profile, dataDir string, file Portable) ([]importStep, map[string][]string, error) {
	var steps []importStep
	skipped := map[string][]string{}
	skip := func(section, text string) { skipped[section] = append(skipped[section], text) }
	policy, err := readKillSwitch(p.doc)
	if err != nil {
		return nil, nil, err
	}

	// The owner's cards come first: the settings below may refer to them.
	existing := map[string]xkeen.CustomService{}
	for _, service := range xkeen.CustomServices() {
		existing[strings.ToLower(service.Name)] = service
	}
	planned := map[string]bool{} // names of cards this import will create
	for _, wanted := range file.CustomServices {
		name, addresses := wanted.Name, wanted.Addresses
		if current, found := existing[strings.ToLower(strings.Join(strings.Fields(name), " "))]; found {
			normal, err := xkeen.NormalizeCustomService(current.ID, name, addresses)
			if err != nil {
				skip("custom_services", fmt.Sprintf("«%s»: %v", name, err))
				continue
			}
			if slices.Equal(normal.Domains, current.Domains) && slices.Equal(normal.Networks, current.Networks) {
				continue
			}
			if err = c.customConflict(p, normal); err != nil {
				skip("custom_services", fmt.Sprintf("«%s»: %v", name, err))
				continue
			}
			id := current.ID
			steps = append(steps, importStep{"custom_services", fmt.Sprintf("Изменить адреса сервиса «%s»", normal.Name), func(ctx context.Context) error {
				return c.updateCustomService(ctx, dataDir, id, name, addresses)
			}})
			continue
		}
		normal, err := xkeen.NormalizeCustomService("custom-00000000", name, addresses)
		if err == nil {
			err = uniqueCardName(normal)
		}
		if err == nil {
			err = c.customConflict(p, normal)
		}
		if err != nil {
			skip("custom_services", fmt.Sprintf("«%s»: %v", name, err))
			continue
		}
		planned[strings.ToLower(normal.Name)] = true
		steps = append(steps, importStep{"custom_services", fmt.Sprintf("Добавить сервис «%s» (%d адр.)", normal.Name, len(normal.Domains)+len(normal.Networks)), func(ctx context.Context) error {
			_, err := c.createCustomService(ctx, dataDir, name, addresses)
			return err
		}})
	}

	// Exclusions are only added: nothing the owner has here is removed.
	current, err := currentExclusions(p, dataDir)
	if err != nil {
		return nil, nil, err
	}
	have := map[string]bool{}
	for _, entry := range current.Entries {
		have[exclusionRule(entry)] = true
	}
	guard := c.newExclusionGuard(p)
	var additions []xkeen.Exclusion
	for _, wanted := range file.Exclusions {
		entry, err := xkeen.NormalizeExclusion(wanted.Value, wanted.Comment)
		if err != nil {
			skip("exclusions", fmt.Sprintf("%s: %v", shortText(wanted.Value), err))
			continue
		}
		entry.Disabled = wanted.Disabled
		if have[exclusionRule(entry)] {
			continue
		}
		if !entry.Disabled {
			if _, _, refusal := guard.conflict(entry); refusal != nil {
				skip("exclusions", fmt.Sprintf("%s: %v", shortText(wanted.Value), refusal))
				continue
			}
		}
		have[exclusionRule(entry)] = true
		additions = append(additions, entry)
	}
	if len(current.Entries)+len(additions) > xkeen.MaxExclusions {
		skip("exclusions", fmt.Sprintf("исключений стало бы больше %d", xkeen.MaxExclusions))
		additions = nil
	}
	if len(additions) > 0 {
		shown := make([]string, 0, len(additions))
		for _, entry := range additions {
			shown = append(shown, strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(entry.Value, "domain:"), "pattern:"), "full:"))
		}
		steps = append(steps, importStep{"exclusions", fmt.Sprintf("Добавить исключения (%d): %s", len(additions), shortList(shown)), func(ctx context.Context) error {
			_, err := c.updateExclusions(ctx, dataDir, func(live profile, list *xkeen.Exclusions) error {
				known := map[string]bool{}
				for _, entry := range list.Entries {
					known[exclusionRule(entry)] = true
				}
				liveGuard := c.newExclusionGuard(live)
				for _, entry := range additions {
					if known[exclusionRule(entry)] {
						continue
					}
					if !entry.Disabled {
						if _, _, refusal := liveGuard.conflict(entry); refusal != nil {
							continue
						}
					}
					list.Entries = append(list.Entries, entry)
				}
				if len(list.Entries) > xkeen.MaxExclusions {
					return fmt.Errorf("достигнут предел в %d исключений", xkeen.MaxExclusions)
				}
				return nil
			})
			return err
		}})
	}

	mode := c.routingMode(p)
	switch file.RoutingMode {
	case "protected":
		if mode != "protected" {
			steps = append(steps, importStep{"routing_mode", "Включить защищённый режим: неопознанный трафик пойдёт через VPN", func(ctx context.Context) error {
				_, err := c.SetProtectedRouting(ctx)
				return err
			}})
		}
	case "blocklist":
		if mode != "blocklist" {
			steps = append(steps, importStep{"weak_routing_mode", "Перейти на режим «только по списку блокировок»: неопознанный трафик пойдёт напрямую", func(ctx context.Context) error {
				enabled := true
				_, err := c.UpdateRefilter(ctx, &enabled, false)
				return err
			}})
		}
	}

	if file.KillSwitch != nil {
		wanted := KillSwitch{Enabled: file.KillSwitch.Enabled, Services: map[string]string{}}
		if wanted.Enabled != policy.Enabled {
			enabled := wanted.Enabled
			if enabled {
				steps = append(steps, importStep{"kill_switch", "Включить общий kill switch", func(ctx context.Context) error {
					_, err := c.SetKillSwitch(ctx, &enabled, "", "")
					return err
				}})
			} else {
				steps = append(steps, importStep{"weak_kill_switch", "Выключить общий kill switch", func(ctx context.Context) error {
					_, err := c.SetKillSwitch(ctx, &enabled, "", "")
					return err
				}})
			}
		}
		keys := make([]string, 0, len(file.KillSwitch.Cards))
		for key := range file.KillSwitch.Cards {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			mode := file.KillSwitch.Cards[key]
			if mode != "on" && mode != "off" && mode != "inherit" {
				skip("kill_switch", fmt.Sprintf("%s: неизвестный режим", shortText(key)))
				continue
			}
			id, name, found := cardOfKey(key)
			created := strings.HasPrefix(key, customKeyPrefix) && planned[strings.ToLower(strings.TrimPrefix(key, customKeyPrefix))]
			if !found && !created {
				skip("kill_switch", fmt.Sprintf("карточки «%s» здесь нет", shortText(name)))
				continue
			}
			currentMode := "on"
			if found && policy.Services[id] != "" {
				currentMode = policy.Services[id]
			}
			if found && currentMode == mode {
				continue
			}
			// Whether the card is still protected is judged with the general
			// switch as this very file leaves it.
			protected := mode == "on" || mode == "inherit" && wanted.Enabled
			section := "kill_switch"
			if !protected {
				section = "weak_kill_switch"
			}
			label := map[string]string{"on": "всегда включён", "off": "всегда выключен", "inherit": "как в настройках"}[mode]
			key, mode := key, mode
			steps = append(steps, importStep{section, fmt.Sprintf("Kill switch · %s: %s", name, label), func(ctx context.Context) error {
				id, _, found := cardOfKey(key)
				if !found {
					return errors.New("карточка не найдена")
				}
				_, err := c.SetKillSwitch(ctx, nil, id, mode)
				return err
			}})
		}
	}

	if file.DNS != nil {
		if view := readDNS(p.doc); view.Foreign {
			skip("dns", "в профиле Mihomo свои настройки DNS; панель их не меняет")
		} else if wanted, _, err := normalizeDNS(*file.DNS); err != nil {
			skip("dns", err.Error())
		} else if previous, _, _ := normalizeDNS(view.DNSSettings); !sameDNS(previous, wanted) {
			text := "Вернуть DNS ядра роутеру"
			if wanted.Mode == dnsModeSecure {
				text = "Перевести ядро на зашифрованный DNS (" + wanted.Preset + "); при сбое панель вернёт прежний"
			}
			steps = append(steps, importStep{"dns", text, func(ctx context.Context) error {
				_, err := c.SetDNS(ctx, wanted)
				return err
			}})
		}
	}

	servers := c.catalog()
	keys := make([]string, 0, len(file.Routes))
	for key := range file.Routes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		route := file.Routes[key]
		id, name, found := cardOfKey(key)
		created := strings.HasPrefix(key, customKeyPrefix) && planned[strings.ToLower(strings.TrimPrefix(key, customKeyPrefix))]
		if !found && !created {
			skip("routes", fmt.Sprintf("карточки «%s» здесь нет", shortText(name)))
			continue
		}
		target, err := resolveRoute(p, route, servers)
		if err == nil && !validAssignment(id, target) && found {
			err = errors.New("этой карточке нужен VPN")
		}
		if err != nil {
			skip("routes", fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if found && p.assigned[id] == target {
			continue
		}
		section := "routes"
		if target == directTarget {
			section = "weak_routes"
		}
		key, route := key, route
		steps = append(steps, importStep{section, fmt.Sprintf("%s → %s", name, routeText(route)), func(ctx context.Context) error {
			id, _, found := cardOfKey(key)
			if !found {
				return errors.New("карточка не найдена")
			}
			// Resolve again: the catalogue may have changed since the preview.
			c.mu.Lock()
			live, err := c.read()
			c.mu.Unlock()
			if err != nil {
				return err
			}
			target, err := resolveRoute(live, route, c.catalog())
			if err != nil {
				return err
			}
			_, err = c.Set(ctx, id, target)
			return err
		}})
	}
	return steps, skipped, nil
}

func sameDNS(a, b DNSSettings) bool {
	return a.Mode == b.Mode && a.Preset == b.Preset && slices.Equal(a.Servers, b.Servers)
}

func shortText(text string) string {
	runes := []rune(text)
	if len(runes) > 60 {
		return string(runes[:60]) + "…"
	}
	return text
}

func shortList(items []string) string {
	if len(items) > 6 {
		return strings.Join(items[:6], ", ") + fmt.Sprintf(" и ещё %d", len(items)-6)
	}
	return strings.Join(items, ", ")
}

func (c *Controller) importPlan(dataDir string, file Portable) ([]importStep, map[string][]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return nil, nil, err
	}
	return c.planImport(p, dataDir, file)
}

// PreviewImport tells what the file would change here, without changing it.
func (c *Controller) PreviewImport(dataDir string, file Portable) ([]ImportSection, error) {
	steps, skipped, err := c.importPlan(dataDir, file)
	if err != nil {
		return nil, err
	}
	var sections []ImportSection
	for _, section := range importSections {
		item := ImportSection{ID: section.id, Title: section.title, Weakens: section.weakens, Changes: []string{}}
		for _, step := range steps {
			if step.section == section.id {
				item.Changes = append(item.Changes, step.text)
			}
		}
		item.Skipped = skipped[section.id]
		if len(item.Changes) > 0 || len(item.Skipped) > 0 {
			sections = append(sections, item)
		}
	}
	return sections, nil
}

// ImportResult reports one section after it was applied.
type ImportResult struct {
	ID     string   `json:"id"`
	Title  string   `json:"title"`
	Done   []string `json:"done"`
	Failed []string `json:"failed,omitempty"`
}

// ApplyImport carries out the chosen sections. Every change goes through the
// same checked path as the same change made by hand, so a refused step leaves
// the router as it was and the rest continues.
func (c *Controller) ApplyImport(ctx context.Context, dataDir string, file Portable, chosen []string) ([]ImportResult, error) {
	var results []ImportResult
	for _, section := range importSections {
		if !slices.Contains(chosen, section.id) {
			continue
		}
		// Planned again before each section: earlier ones change what is left to do.
		steps, _, err := c.importPlan(dataDir, file)
		if err != nil {
			return results, err
		}
		result := ImportResult{ID: section.id, Title: section.title, Done: []string{}}
		for _, step := range steps {
			if step.section != section.id {
				continue
			}
			if err := step.run(ctx); err != nil {
				result.Failed = append(result.Failed, step.text+": "+err.Error())
			} else {
				result.Done = append(result.Done, step.text)
			}
		}
		if len(result.Done) > 0 || len(result.Failed) > 0 {
			results = append(results, result)
		}
	}
	return results, nil
}
