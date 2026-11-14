package cardcontroller

import (
	"errors"
	"slices"
	"strings"

	"xkeen-panel/internal/xkeen"
)

const strictDomains = cardPrefix + "strict-domains"
const relaxedDomains = cardPrefix + "relaxed-domains"
const domainGuardOwner = "x-xkeen-panel-service-guard"

// An unassigned card inherits the destination from the owner's matching rule.
// Classify its failure policy independently, at that rule's original position.
type serviceGuard struct {
	strict, relaxed bool
	native          map[string]bool
}

func prepareServiceGuard(doc map[string]interface{}, services []xkeen.ServiceRouteView, policy KillSwitch, assigned map[string]string, enabled bool) (serviceGuard, error) {
	g := serviceGuard{native: map[string]bool{}}
	providers := object(doc["rule-providers"])
	for _, name := range []string{strictDomains, relaxedDomains} {
		if def, exists := providers[name]; exists {
			if object(def)[domainGuardOwner] != true {
				return g, errors.New("занято имя набора правил Kill switch")
			}
			delete(providers, name)
		}
	}
	if !enabled {
		return g, nil
	}
	var suffixes []string
	modes := map[string]bool{}
	for _, service := range services {
		protected := policy.Protects(service.ID)
		if service.ID == "claude" || assigned[service.ID] != "" {
			continue // Explicit routes and Claude have dedicated, higher-priority rules.
		}
		g.native[groupNames[service.ID]] = protected
		for _, domain := range service.Domains {
			suffix, ok := strings.CutPrefix(domain, "domain:")
			if _, exists := modes[suffix]; ok && !exists {
				modes[suffix] = protected
				suffixes = append(suffixes, suffix)
			}
		}
	}
	slices.Sort(suffixes)
	// More-specific card domains can have the opposite policy, e.g.
	// youtubei.googleapis.com within googleapis.com. Give the child precedence.
	exceptions := map[string][]string{}
	for _, child := range suffixes {
		for parent := child; strings.Contains(parent, "."); {
			_, parent, _ = strings.Cut(parent, ".")
			if mode, found := modes[parent]; found && mode != modes[child] {
				exceptions[parent] = append(exceptions[parent], child)
			}
		}
	}
	payload := map[bool][]string{}
	for _, suffix := range suffixes {
		predicate := "DOMAIN-SUFFIX," + suffix
		for _, child := range exceptions[suffix] {
			predicate = "AND,((" + predicate + "),(NOT,((DOMAIN-SUFFIX," + child + "))))"
		}
		mode := modes[suffix]
		payload[mode] = append(payload[mode], predicate)
	}
	for _, item := range []struct {
		name string
		mode bool
	}{{strictDomains, true}, {relaxedDomains, false}} {
		if len(payload[item.mode]) == 0 {
			continue
		}
		if providers == nil {
			if doc["rule-providers"] != nil {
				return g, errors.New("неподдерживаемый формат rule-providers")
			}
			providers = map[string]interface{}{}
			doc["rule-providers"] = providers
		}
		providers[item.name] = map[string]interface{}{"type": "inline", "behavior": "classical", "payload": payload[item.mode], domainGuardOwner: true}
	}
	g.strict, g.relaxed = len(payload[true]) > 0, len(payload[false]) > 0
	return g, nil
}

func (g serviceGuard) predicate(fields []string, end int) string {
	condition := ""
	if g.native[fields[end]] && fields[0] != "MATCH" {
		// The owner already classified this service (e.g. by GeoSite, IP or
		// port); only a known, more specific relaxed card may override it.
		if g.relaxed {
			condition = "NOT,((RULE-SET," + relaxedDomains + "))"
		} else {
			return ruleCondition(fields, end)
		}
	} else if g.strict {
		condition = "RULE-SET," + strictDomains
	} else {
		return ""
	}
	if fields[0] == "MATCH" {
		return condition
	}
	return "AND,((" + ruleCondition(fields, end) + "),(" + condition + "))"
}
