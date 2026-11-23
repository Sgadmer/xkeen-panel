package xkeen

import (
	"encoding/json"
	"sort"
	"strings"

	"xkeen-panel/internal/models"
)

// maxSkippedModes bounds what one import remembers about refused modes.
const maxSkippedModes = 30

// featureValues are the settings whose value names a kind of thing rather
// than an address or a secret, so a refused mode can be described by them.
var featureValues = map[string]bool{
	"protocol": true, "network": true, "security": true, "type": true,
	"domainStrategy": true, "domainMatcher": true, "queryStrategy": true,
	"flow": true, "mode": true, "packetEncoding": true, "fingerprint": true,
}

// noteSkippedMode remembers a refused mode with the features its document
// uses. Only key paths and the kinds listed in featureValues are kept.
func noteSkippedMode(report *ImportReport, name, reason string, raw []byte) {
	if len(report.Skipped) >= maxSkippedModes {
		return
	}
	var document interface{}
	_ = json.Unmarshal(raw, &document)
	seen := map[string]bool{}
	var walk func(value interface{}, path string)
	walk = func(value interface{}, path string) {
		if len(seen) >= 120 {
			return
		}
		switch v := value.(type) {
		case map[string]interface{}:
			for key, child := range v {
				next := key
				if path != "" {
					next = path + "." + key
				}
				// Tags, names and maps keyed by domains are the provider's own
				// words: only that they are there is kept.
				lower := strings.ToLower(key)
				if key == "remarks" || key == "meta" || strings.HasSuffix(lower, "tag") || lower == "hosts" || lower == "headers" {
					seen[next] = true
					continue
				}
				if s, ok := child.(string); ok && featureValues[key] {
					seen[next+"="+s] = true
					continue
				}
				walk(child, next)
			}
		case []interface{}:
			for _, child := range v {
				walk(child, path+"[]")
			}
		default:
			if path != "" {
				seen[path] = true
			}
		}
	}
	walk(document, "")
	features := make([]string, 0, len(seen))
	for feature := range seen {
		features = append(features, feature)
	}
	sort.Strings(features)
	report.Skipped = append(report.Skipped, models.SkippedMode{Name: strings.TrimSpace(name), Reason: reason, Features: features})
}

// noteSkippedGroup is noteSkippedMode for a group read from YAML.
func noteSkippedGroup(report *ImportReport, name, reason string, group map[string]interface{}) {
	raw, _ := json.Marshal(group)
	noteSkippedMode(report, name, reason, raw)
}

// skippedReason is a fixed code for why a mode was refused.
func skippedReason(err error, fallback string) string {
	if phase := ProfileRenderPhase(err); phase != "" {
		if detail := ProfileRefusal(err); detail != "" {
			return "profile/" + phase + "/" + detail
		}
		return "profile/" + phase
	}
	return fallback
}
