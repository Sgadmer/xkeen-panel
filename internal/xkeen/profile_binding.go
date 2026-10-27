package xkeen

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ProfileRuleBinding routes actual client inputs directly through provider
// rules. Xray v26.3.27's loopback clears session.Content and disables routing
// DNS resolution, so the virtual entry must be used only as control identity.
// Put OwnedRules before the owner's routing; put ClientRules at the existing
// main-proxy policy boundary, after the owner's direct exceptions. A separate
// binding for a forced panel-probe input belongs before its existing rule.
type ProfileRuleBinding struct {
	OwnedRules     []interface{}
	ClientRules    []interface{}
	GuardOutbounds []interface{}
}

// BindProfileRules splits mixed entry/DNS rules without changing provider
// predicate fields or their order within each input class. The terminal default
// is retained. A guarded virtual entry cannot recurse through the outer pool.
func BindProfileRules(bundle ProfileBundle, actualClientTags []string) (ProfileRuleBinding, error) {
	var empty ProfileRuleBinding
	if bundle.InboundTag == "" || bundle.Namespace == "" || len(actualClientTags) == 0 || len(actualClientTags) > 128 {
		return empty, profileError()
	}
	var inputs []string
	for _, tag := range actualClientTags {
		if strings.TrimSpace(tag) == "" || tag == bundle.InboundTag || strings.HasPrefix(tag, bundle.Namespace) {
			return empty, profileError()
		}
		inputs = profileAppendUnique(inputs, tag)
	}
	guardTag := bundle.Namespace + "virtual-block"
	identityInputs := append([]string(nil), inputs...)
	sort.Strings(identityInputs)
	identityBytes, _ := json.Marshal(identityInputs)
	identity := sha256.Sum256(identityBytes)
	bindingID := hex.EncodeToString(identity[:])
	result := ProfileRuleBinding{
		GuardOutbounds: []interface{}{map[string]interface{}{"tag": guardTag, "protocol": "blackhole", "settings": map[string]interface{}{}}},
		OwnedRules:     []interface{}{map[string]interface{}{"type": "field", "ruleTag": bundle.Namespace + "virtual-guard", "inboundTag": []interface{}{bundle.InboundTag}, "outboundTag": guardTag}},
	}
	for index, item := range bundle.Rules {
		rule := mapOf(item)
		if rule == nil {
			return empty, profileError()
		}
		tags, err := profileStrings(rule["inboundTag"])
		if err != nil || len(tags) == 0 {
			return empty, profileError()
		}
		hasEntry := false
		var owned []string
		for _, tag := range tags {
			if tag == bundle.InboundTag {
				hasEntry = true
				continue
			}
			if !strings.HasPrefix(tag, bundle.Namespace) {
				return empty, fmt.Errorf("правило профиля содержит внешний вход")
			}
			owned = profileAppendUnique(owned, tag)
		}
		for _, binding := range []struct {
			tags   []string
			client bool
		}{{inputs, true}, {owned, false}} {
			if binding.client && !hasEntry || len(binding.tags) == 0 {
				continue
			}
			clone, err := cloneProfileRule(rule)
			if err != nil {
				return empty, err
			}
			clone["inboundTag"] = profileInterfaces(binding.tags)
			if binding.client {
				clone["ruleTag"] = fmt.Sprintf("%sbound-%s-%d-client", bundle.Namespace, bindingID, index+1)
			} else {
				clone["ruleTag"] = fmt.Sprintf("%sbound-%d-owned", bundle.Namespace, index+1)
			}
			if binding.client {
				result.ClientRules = append(result.ClientRules, clone)
			} else {
				result.OwnedRules = append(result.OwnedRules, clone)
			}
		}
	}
	if len(result.ClientRules) == 0 {
		return empty, profileError()
	}
	return result, nil
}

func cloneProfileRule(rule map[string]interface{}) (map[string]interface{}, error) {
	raw, err := json.Marshal(rule)
	if err != nil {
		return nil, profileError()
	}
	clone, err := decodeServerOutbound(raw)
	if err != nil {
		return nil, profileError()
	}
	return clone, nil
}
