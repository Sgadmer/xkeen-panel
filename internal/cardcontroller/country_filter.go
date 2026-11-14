package cardcontroller

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

// SetCountryPolicy is wired before the HTTP server and worker goroutines start.
func (c *Controller) SetCountryPolicy(countries func() []string, allowed func(models.Server) bool) {
	c.avoidCountries, c.autoAllowed = countries, allowed
}

type autoCountryGroups struct {
	types   map[string]string
	allowed map[string]map[string]bool
}

func (g autoCountryGroups) ready(live, before map[string]selector) bool {
	for name, kind := range g.types {
		group, ok := live[name]
		if !ok || !strings.EqualFold(strings.ReplaceAll(kind, "-", ""), group.Type) || len(group.All) == 0 {
			return false
		}
		present := make(map[string]bool, len(group.All))
		for _, member := range group.All {
			present[member] = true
			if member != "REJECT" && !g.allowed[name][member] {
				return false
			}
		}
		for _, previous := range before[name].All {
			if g.allowed[name][previous] && !present[previous] {
				return false
			}
		}
		if kind != "load-balance" && !present[group.Now] {
			return false
		}
	}
	return true
}

const countryFilterKey = "x-xkeen-panel-country-policy"

// An existing profile can use country exclusions before its first service
// assignment. Avoid creating card routes merely to filter an automatic group.
func (c *Controller) reconcileCountryGroups(ctx context.Context, p profile) error {
	if c.avoidCountries == nil {
		return nil
	}
	groups, err := c.renderCountryFilter(&p, c.catalog())
	if err != nil {
		return err
	}
	var original map[string]interface{}
	if err := yaml.Unmarshal(p.raw, &original); err != nil {
		return err
	}
	live, err := p.api.selectors(ctx)
	if err != nil {
		return err
	}
	if reflect.DeepEqual(p.doc, original) && groups.ready(live, nil) {
		return nil
	}
	body, err := yaml.Marshal(p.doc)
	if err != nil {
		return err
	}
	return c.install(ctx, p, body, p.doc, live, nil, groups)
}

// Store our exact addition beside the group so the owner's filter, ordering and
// empty fallback can be restored even when the panel restarts between edits.
func removeCountryFilter(group map[string]interface{}) error {
	raw, found := group[countryFilterKey]
	if !found {
		return nil
	}
	state := object(raw)
	previous, ok := state["filter"].(string)
	if !ok || previous == "" {
		return errors.New("повреждены параметры фильтра стран Mihomo")
	}
	parts := strings.Split(str(group["exclude-filter"]), "`")
	index := slices.Index(parts, previous)
	if index < 0 {
		return errors.New("правило фильтра стран в группе Mihomo изменено вне панели")
	}
	parts = slices.Delete(parts, index, index+1)
	if len(parts) == 0 {
		delete(group, "exclude-filter")
	} else {
		group["exclude-filter"] = strings.Join(parts, "`")
	}
	if str(group["empty-fallback"]) == "REJECT" {
		if fallback, existed := state["empty-fallback"]; existed {
			group["empty-fallback"] = fallback
		} else {
			delete(group, "empty-fallback")
		}
	}
	delete(group, countryFilterKey)
	return nil
}

// exclude-filter is applied to both provider nodes and explicitly listed
// proxies. Keep the provider's own include/exclude filters intact. An unseen
// node from an independently updated provider is ineligible until classified.
func (c *Controller) renderCountryFilter(p *profile, servers []models.Server) (autoCountryGroups, error) {
	var result autoCountryGroups
	if c.avoidCountries == nil {
		return result, nil
	}
	enabled := len(c.avoidCountries()) > 0
	type providerNode struct{ source, name string }
	unavailable := map[providerNode]bool{}
	if enabled {
		eligible := xkeen.AutoCountryEligibility(servers, func(s models.Server) bool {
			return len(s.RawProfile) == 0 && c.autoAllowed(s)
		})
		for i, s := range servers {
			if !eligible[i] {
				unavailable[providerNode{s.SourceID, s.Name}] = true
			}
		}
	}
	result.allowed = make(map[string]map[string]bool)
	result.types = make(map[string]string)
	for _, raw := range list(p.doc["proxy-groups"]) {
		group := object(raw)
		if err := removeCountryFilter(group); err != nil {
			return result, err
		}
		if !enabled || strings.HasPrefix(str(group["name"]), cardPrefix) {
			continue
		}
		switch str(group["type"]) {
		case "url-test", "fallback", "load-balance":
		default:
			continue
		}
		name := str(group["name"])
		allowed := map[string]bool{}
		for _, s := range c.nativeServers(*p, name, servers) {
			if s.Name == "" {
				continue
			}
			if previous, seen := allowed[s.Name]; seen && !previous {
				continue
			}
			allowed[s.Name] = !unavailable[providerNode{s.SourceID, s.Name}]
		}
		var names []string
		for node, ok := range allowed {
			if ok {
				names = append(names, strings.ReplaceAll(regexp.QuoteMeta(node), "`", `\x60`))
			}
		}
		sort.Strings(names)
		filter := `\A(?!(?:` + strings.Join(names, "|") + `)\z)`
		result.allowed[name] = allowed
		state := map[string]interface{}{"filter": filter}
		if original, exists := group["empty-fallback"]; exists {
			state["empty-fallback"] = original
		}
		exclude := filter
		if raw, exists := group["exclude-filter"]; exists {
			original, ok := raw.(string)
			if !ok {
				return result, errors.New("формат exclude-filter Mihomo не поддерживается")
			}
			exclude = original + "`" + filter
		}
		group["exclude-filter"], group["empty-fallback"], group[countryFilterKey] = exclude, "REJECT", state
		result.types[name] = str(group["type"])
	}
	return result, nil
}
