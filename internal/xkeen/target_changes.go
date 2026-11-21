package xkeen

import (
	"reflect"
	"sort"
	"strings"

	"xkeen-panel/internal/models"
)

const maxChangedFields = 12

// changedOutboundFields compares the outbounds built from two versions of one
// named server and returns the names of the settings that differ, such as
// "streamSettings.realitySettings.shortId". Values are credentials and never
// leave this function. Positions in lists are omitted for the same reason a
// journal line should stay short.
func changedOutboundFields(previous, next models.Server) []string {
	if len(previous.RawProfile) > 0 || len(next.RawProfile) > 0 {
		return []string{"profile"}
	}
	before, err := BuildServerOutbound(previous, "endpoint", nil)
	if err != nil {
		return nil
	}
	after, err := BuildServerOutbound(next, "endpoint", nil)
	if err != nil {
		return nil
	}
	found := map[string]bool{}
	diffOutboundValue("", before, after, found)
	return sortedFieldNames(found)
}

func diffOutboundValue(path string, before, after interface{}, found map[string]bool) {
	if reflect.DeepEqual(before, after) {
		return
	}
	switch a := before.(type) {
	case map[string]interface{}:
		b, ok := after.(map[string]interface{})
		if !ok {
			break
		}
		for key := range b {
			if _, present := a[key]; !present {
				diffOutboundValue(joinField(path, key), nil, b[key], found)
			}
		}
		for key, value := range a {
			diffOutboundValue(joinField(path, key), value, b[key], found)
		}
		return
	case []interface{}:
		b, ok := after.([]interface{})
		if !ok || len(a) != len(b) {
			break
		}
		for i := range a {
			diffOutboundValue(path, a[i], b[i], found)
		}
		return
	}
	if path == "" {
		path = "outbound"
	}
	found[path] = true
}

func joinField(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func sortedFieldNames(found map[string]bool) []string {
	names := make([]string, 0, len(found))
	for name := range found {
		// A setting name comes from the panel's own outbound builder. Reject
		// anything that could be data rather than a key.
		if name != "" && len(name) <= 96 && !strings.ContainsAny(name, " :/@=") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) > maxChangedFields {
		names = append(names[:maxChangedFields], "…")
	}
	return names
}
