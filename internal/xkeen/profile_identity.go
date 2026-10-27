package xkeen

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"xkeen-panel/internal/models"
)

const profileInboundPrefix = "xkp-profile-"
const profileIdentityPrefix = "xray-profile://"

var profileHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ProfileIdentity retains complete policy semantics while ignoring display and
// client-local logging metadata. The hash never exposes provider credentials.
func ProfileIdentity(server models.Server) string {
	profile, err := decodeServerOutbound(server.RawProfile)
	if err != nil {
		return ""
	}
	for _, key := range []string{"remarks", "name", "ps", "remark", "log"} {
		delete(profile, key)
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(raw)
	return profileIdentityPrefix + hex.EncodeToString(hash[:])
}

func BuildProfileEntry(server models.Server, tag string, template map[string]interface{}) (map[string]interface{}, error) {
	identity := ProfileIdentity(server)
	hash := strings.TrimPrefix(identity, profileIdentityPrefix)
	if !profileHashPattern.MatchString(hash) {
		return nil, fmt.Errorf("некорректный составной профиль")
	}
	entry := map[string]interface{}{"tag": tag, "protocol": "loopback", "settings": map[string]interface{}{"inboundTag": profileInboundPrefix + hash}}
	if options := mapOf(mapOf(template["streamSettings"])["sockopt"]); options != nil {
		if mark, ok := options["mark"]; ok {
			entry["streamSettings"] = map[string]interface{}{"sockopt": map[string]interface{}{"mark": mark}}
		}
	}
	return entry, nil
}

func ProfileEndpointIdentity(outbound map[string]interface{}) string {
	if outbound["protocol"] != "loopback" {
		return ""
	}
	inbound, _ := mapOf(outbound["settings"])["inboundTag"].(string)
	hash := strings.TrimPrefix(inbound, profileInboundPrefix)
	if !strings.HasPrefix(inbound, profileInboundPrefix) || !profileHashPattern.MatchString(hash) {
		return ""
	}
	return profileIdentityPrefix + hash
}

func IsProfileInternalTag(tag string) bool {
	if !strings.HasPrefix(tag, "xkp-") || len(tag) < 69 {
		return false
	}
	return profileHashPattern.MatchString(tag[4:68]) && tag[68] == '-'
}

func serverFromRawProfile(raw json.RawMessage) (models.Server, error) {
	profile, err := decodeServerOutbound(raw)
	if err != nil {
		return models.Server{}, err
	}
	count := 0
	for _, item := range asSlice(profile["outbounds"]) {
		outbound := mapOf(item)
		if outbound != nil && !isServiceOutbound(outbound) {
			count++
		}
	}
	if count == 0 || count > 256 {
		return models.Server{}, fmt.Errorf("неподдерживаемый размер профиля")
	}
	display := objectDisplayNameMust(profile)
	if display == "" {
		display = "Профиль провайдера"
	}
	server := models.Server{Name: display, Protocol: "xray-profile", RawProfile: append(json.RawMessage(nil), raw...), ProfileNodes: count, Latency: -1}
	server.RawURI = ProfileIdentity(server)
	if server.RawURI == "" {
		return models.Server{}, fmt.Errorf("некорректный профиль")
	}
	// Validate all dependencies before the profile can enter the catalogue.
	if _, err := BuildProfileBundle(server, ManualTag, nil); err != nil {
		return models.Server{}, err
	}
	return server, nil
}

func objectDisplayNameMust(profile map[string]interface{}) string {
	for _, key := range []string{"remarks", "name", "ps", "remark", "tag"} {
		if value, ok := profile[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
