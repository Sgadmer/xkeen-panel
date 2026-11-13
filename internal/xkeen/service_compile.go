package xkeen

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

func serviceOutbound(state serviceRoutesState, service string) string {
	id := state.Assignments[service]
	if state.Outbounds[id] == nil {
		return serviceBlock
	}
	return servicePrefix + id
}

// Xray replaces routing wholesale in its multi-file loader. Edit the effective
// routing document and append a separate "tail" outbound fragment so its first
// handler never becomes Xray's default outbound.
func compileServiceRoutes(rt Runtime, writes map[string]map[string]interface{}, state serviceRoutesState) error {
	paths := map[string]bool{}
	for _, path := range ConfigFiles(rt) {
		paths[path] = true
	}
	for path := range writes {
		paths[path] = true
	}
	fragment := ServiceFragmentPath(rt)
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		if path != fragment {
			ordered = append(ordered, path)
		}
	}
	sort.Strings(ordered)

	ids := make([]string, 0, len(state.Outbounds))
	for id := range state.Outbounds {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	nodes := []interface{}{map[string]interface{}{"tag": serviceBlock, "protocol": "blackhole", "settings": map[string]interface{}{}}}
	for _, id := range ids {
		nodes = append(nodes, state.Outbounds[id])
	}
	newFragment := map[string]interface{}{"outbounds": nodes}
	var oldFragment map[string]interface{}
	if _, err := os.Stat(fragment); err == nil {
		if ReadJSONC(fragment, &oldFragment) != nil || len(oldFragment) != 1 {
			return fmt.Errorf("конфликт файла исходящих сервисов")
		}
		for _, raw := range asSlice(oldFragment["outbounds"]) {
			if !strings.HasPrefix(outboundTag(mapOf(raw)), servicePrefix) {
				return fmt.Errorf("файл исходящих сервисов занят")
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if !sameJSON(oldFragment, newFragment) {
		writes[fragment] = newFragment
	}

	var clients []string
	var routePath string
	var routeDoc map[string]interface{}
	hasDedicated := false
	for _, path := range ordered {
		doc := writes[path]
		if doc == nil {
			if err := ReadJSONC(path, &doc); err != nil {
				return err
			}
		}
		if _, ok := doc["routing"].(map[string]interface{}); ok {
			routePath, routeDoc = path, doc
		}
		for _, raw := range asSlice(doc["outbounds"]) {
			if strings.HasPrefix(outboundTag(mapOf(raw)), servicePrefix) {
				return fmt.Errorf("конфликт зарезервированных тегов исходящих сервисов")
			}
		}
		for _, raw := range asSlice(doc["inbounds"]) {
			ib := mapOf(raw)
			tag, _ := ib["tag"].(string)
			proto, _ := ib["protocol"].(string)
			if tag == ClaudeClientInbound {
				hasDedicated = true
				continue
			}
			if !policyClientInput(tag, proto) {
				continue
			}
			clients = profileAppendUnique(clients, tag)
			sniff := mapOf(ib["sniffing"])
			if sniff == nil {
				sniff = map[string]interface{}{}
			}
			kinds := stringList(sniff["destOverride"])
			changed := sniff["enabled"] != true || sniff["metadataOnly"] == true || sniff["domainsExcluded"] != nil || sniff["ipsExcluded"] != nil
			for _, kind := range []string{"http", "tls", "quic"} {
				if !containsPolicyString(kinds, kind) {
					kinds = append(kinds, kind)
					changed = true
				}
			}
			if changed {
				sniff["enabled"], sniff["destOverride"] = true, kinds
				delete(sniff, "metadataOnly")
				delete(sniff, "domainsExcluded")
				delete(sniff, "ipsExcluded")
				ib["sniffing"] = sniff
				writes[path] = doc
			}
		}
	}
	if routePath == "" || len(clients) == 0 && !hasDedicated {
		return fmt.Errorf("не найдены маршрутизация и клиентские входы Xray")
	}
	sort.Strings(clients)
	routing := mapOf(routeDoc["routing"])
	previous := asSlice(routing["rules"])
	rules := make([]interface{}, 0, len(previous)+len(state.Assignments)+1)
	if hasDedicated {
		rules = append(rules, map[string]interface{}{"type": "field", "ruleTag": servicePrefix + "dedicated", "inboundTag": []string{ClaudeClientInbound}, "outboundTag": serviceOutbound(state, "claude")})
	}
	if len(clients) != 0 {
		geo := serviceGeosites(rt)
		for i, service := range serviceCatalog {
			if service.id != "claude" && state.Assignments[service.id] == "" {
				continue
			}
			out := serviceOutbound(state, service.id)
			rules = append(rules, map[string]interface{}{"type": "field", "ruleTag": servicePrefix + service.id, "inboundTag": clients, "domain": serviceDomains(i, geo), "outboundTag": out})
			if ips := serviceNetworks[service.id]; len(ips) != 0 {
				rules = append(rules, map[string]interface{}{"type": "field", "ruleTag": servicePrefix + service.id + "-ips", "inboundTag": clients, "ip": ips, "outboundTag": out})
			}
		}
	}
	for _, raw := range previous {
		tag, _ := mapOf(raw)["ruleTag"].(string)
		if !strings.HasPrefix(tag, servicePrefix) {
			rules = append(rules, raw)
		}
	}
	if !sameJSON(map[string]interface{}{"rules": previous}, map[string]interface{}{"rules": rules}) {
		routing["rules"] = rules
		writes[routePath] = routeDoc
	}
	return nil
}

func applyServiceRoutes(rt Runtime, writes map[string]map[string]interface{}) error {
	if !ServiceRoutesArmed(rt) {
		return nil
	}
	state, err := loadServiceRoutes(rt)
	if err != nil {
		return err
	}
	return compileServiceRoutes(rt, writes, state)
}
