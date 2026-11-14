package cardcontroller

import (
	"errors"
	"reflect"
	"strings"
)

const nativeGuardKey = "x-xkeen-panel-native-guard"

func namesOf(value interface{}) []string {
	if names, ok := value.([]string); ok {
		return names
	}
	var names []string
	for _, item := range list(value) {
		names = append(names, str(item))
	}
	return names
}

// A manual selector may intentionally be set to DIRECT. But an automatic
// group must never select such a member on its own when the VPN fails.
// Keep original fields so disabling the protection restores provider behavior.
func protectNativeGroups(groups, nodes []interface{}, policy KillSwitch) error {
	protect := policy.Enabled
	for _, mode := range policy.Services {
		protect = protect || mode == "on"
	}
	index := map[string]map[string]interface{}{}
	direct := map[string]bool{"DIRECT": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true}
	for _, raw := range nodes {
		node := object(raw)
		switch strings.ToLower(str(node["type"])) {
		case "direct", "pass", "compatible", "rematch", "dns":
			direct[str(node["name"])] = true
		}
	}
	for _, raw := range groups {
		group := object(raw)
		if err := removeCountryFilter(group); err != nil {
			return err
		}
		if raw, ok := group[nativeGuardKey]; ok {
			fields := object(raw)
			original, applied := object(fields["original"]), object(fields["applied"])
			if original == nil || applied == nil {
				return errors.New("повреждены исходные параметры группы Kill switch")
			}
			for _, key := range []string{"proxies", "empty-fallback", "exclude-type"} {
				// Preserve a later edit by the owner. Re-evaluate the changed
				// value against the current protection policy below.
				if !reflect.DeepEqual(group[key], applied[key]) {
					continue
				}
				if value, found := original[key]; found {
					group[key] = value
				} else {
					delete(group, key)
				}
			}
			delete(group, nativeGuardKey)
		}
		index[str(group["name"])] = group
	}
	if !protect {
		return nil
	}
	// Exclude nested manual selectors with a possible direct path from auto
	// rotation. A user can still explicitly select them outside auto groups.
	var mayDirect func(string, map[string]bool) bool
	classified := make(map[string]bool)
	mayDirect = func(name string, visiting map[string]bool) bool {
		if direct[name] || visiting[name] {
			return true
		}
		if result, exists := classified[name]; exists {
			return result
		}
		g := index[name]
		if g == nil {
			return false
		}
		switch str(g["type"]) {
		case "url-test", "fallback", "load-balance":
			return false // their membership is hardened below, incl. empty pools
		case "select":
		default:
			return true
		}
		visiting[name] = true
		defer delete(visiting, name)
		if len(namesOf(g["use"])) != 0 || g["include-all"] == true || g["include-all-providers"] == true || g["include-all-proxies"] == true {
			return true
		}
		for _, child := range namesOf(g["proxies"]) {
			if mayDirect(child, visiting) {
				classified[name] = true
				return true
			}
		}
		classified[name] = false
		return false
	}
	for _, raw := range groups {
		g := object(raw)
		auto := false
		switch str(g["type"]) {
		case "fallback", "url-test", "load-balance":
			auto = true
		case "select":
		default:
			continue
		}
		original := map[string]interface{}{}
		for _, key := range []string{"proxies", "empty-fallback", "exclude-type"} {
			if value, ok := g[key]; ok {
				original[key] = value
			}
		}
		g["empty-fallback"] = "REJECT"
		if auto {
			old := str(g["exclude-type"])
			g["exclude-type"] = strings.TrimPrefix(old+"|Direct|Pass|Compatible|Dns|Rematch", "|")
			// Mihomo may apply exclude-type only to members expanded from
			// providers. Inspect explicitly listed and nested members too.
			var safe []string
			for _, child := range namesOf(g["proxies"]) {
				if !mayDirect(child, map[string]bool{}) {
					safe = append(safe, child)
				}
			}
			if len(safe) > 0 || len(namesOf(g["use"])) != 0 || g["include-all"] == true || g["include-all-providers"] == true || g["include-all-proxies"] == true {
				g["proxies"] = safe
			} else {
				g["proxies"] = []string{"REJECT"}
			}
		}
		applied := map[string]interface{}{}
		for _, key := range []string{"proxies", "empty-fallback", "exclude-type"} {
			if value, ok := g[key]; ok {
				applied[key] = value
			}
		}
		g[nativeGuardKey] = map[string]interface{}{"original": original, "applied": applied}
	}
	return nil
}
