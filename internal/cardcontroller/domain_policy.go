package cardcontroller

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

const domainPolicyKey = "x-xkeen-panel-domain-policy"
const quicGuardGroup = cardPrefix + "guard-quic"

// This policy preserves names available in HTTP/TLS/QUIC handshakes. It does
// not claim ownership of the router's DNS listener or identify client apps.
type domainPolicySnapshot struct {
	Enabled         bool
	SnifferPresent  bool
	Sniffer         map[string]interface{}
	LogLevelPresent bool
	LogLevel        string
}

func readDomainPolicy(doc map[string]interface{}) (domainPolicySnapshot, error) {
	var state domainPolicySnapshot
	raw, present := doc[domainPolicyKey]
	if !present {
		return state, nil
	}
	value, ok := raw.(map[string]interface{})
	if !ok {
		return state, errors.New("повреждена настройка сохранения доменов")
	}
	for key := range value {
		switch key {
		case "version", "enabled", "sniffer_present", "sniffer", "log_level_present", "log_level":
		default:
			return state, errors.New("неподдерживаемая настройка сохранения доменов")
		}
	}
	versionOK := false
	switch version := value["version"].(type) {
	case int:
		versionOK = version == 1
	case float64: // A synthetic JSON profile can be decoded before YAML staging.
		versionOK = version == 1
	}
	enabled, enabledOK := value["enabled"].(bool)
	snifferPresent, snifferOK := value["sniffer_present"].(bool)
	logPresent, logOK := value["log_level_present"].(bool)
	if !versionOK || !enabledOK || !enabled || !snifferOK || !logOK {
		return state, errors.New("повреждены исходные настройки сохранения доменов")
	}
	state.Enabled, state.SnifferPresent, state.LogLevelPresent = enabled, snifferPresent, logPresent
	if snifferPresent {
		original, ok := value["sniffer"].(map[string]interface{})
		if !ok || validateSniffer(original) != nil {
			return domainPolicySnapshot{}, errors.New("повреждена исходная настройка распознавания доменов")
		}
		copy, err := copyDomainValue(original, 0)
		if err != nil {
			return domainPolicySnapshot{}, err
		}
		state.Sniffer = copy.(map[string]interface{})
	} else if _, found := value["sniffer"]; found {
		return domainPolicySnapshot{}, errors.New("противоречивые исходные настройки доменов")
	}
	if logPresent {
		level, ok := value["log_level"].(string)
		if !ok || !validDomainLogLevel(level) {
			return domainPolicySnapshot{}, errors.New("повреждён исходный уровень журнала Mihomo")
		}
		state.LogLevel = level
	} else if _, found := value["log_level"]; found {
		return domainPolicySnapshot{}, errors.New("противоречивый исходный уровень журнала Mihomo")
	}
	return state, nil
}

// configureDomainPolicy is part of the caller's normal validated transaction.
// Keep the first pre-policy snapshot so repeated refreshes remain reversible.
func configureDomainPolicy(doc map[string]interface{}, enabled bool) error {
	if doc == nil {
		return errors.New("конфигурация Mihomo отсутствует")
	}
	state, err := readDomainPolicy(doc)
	if err != nil {
		return err
	}
	if !enabled {
		if !state.Enabled {
			return nil
		}
		if state.SnifferPresent {
			doc["sniffer"] = state.Sniffer
		} else {
			delete(doc, "sniffer")
		}
		if state.LogLevelPresent {
			doc["log-level"] = state.LogLevel
		} else {
			delete(doc, "log-level")
		}
		delete(doc, domainPolicyKey)
		return nil
	}

	sniffer := map[string]interface{}{}
	if raw, present := doc["sniffer"]; present {
		current, ok := raw.(map[string]interface{})
		if !ok || validateSniffer(current) != nil {
			return errors.New("неподдерживаемые настройки распознавания доменов Mihomo")
		}
		copy, err := copyDomainValue(current, 0)
		if err != nil {
			return err
		}
		sniffer = copy.(map[string]interface{})
		if !state.Enabled {
			state.SnifferPresent = true
			state.Sniffer = current
		}
	}
	if raw, present := doc["log-level"]; present {
		level, ok := raw.(string)
		if !ok || !validDomainLogLevel(level) {
			return errors.New("неподдерживаемый уровень журнала Mihomo")
		}
		if !state.Enabled {
			state.LogLevelPresent, state.LogLevel = true, level
		}
	}

	metadata := map[string]interface{}{
		"version": 1, "enabled": true,
		"sniffer_present": state.SnifferPresent, "log_level_present": state.LogLevelPresent,
	}
	if state.SnifferPresent {
		copy, err := copyDomainValue(state.Sniffer, 0)
		if err != nil {
			return err
		}
		metadata["sniffer"] = copy
	}
	if state.LogLevelPresent {
		metadata["log_level"] = state.LogLevel
	}
	for _, key := range []string{"skip-domain", "skip-src-address", "skip-dst-address"} {
		// A previous broad exception must not make a protected service opaque.
		// Its exact value is retained in the snapshot for a later disable.
		delete(sniffer, key)
	}
	sniffer["enable"] = true
	sniffer["force-dns-mapping"] = true
	sniffer["parse-pure-ip"] = true
	sniffer["override-destination"] = false
	sniffer["sniff"] = map[string]interface{}{
		"HTTP": map[string]interface{}{"ports": []interface{}{80, 8080}, "override-destination": false},
		"TLS":  map[string]interface{}{"ports": []interface{}{443, 8443}, "override-destination": false},
		"QUIC": map[string]interface{}{"ports": []interface{}{443, 8443}, "override-destination": false},
	}
	doc[domainPolicyKey], doc["sniffer"], doc["log-level"] = metadata, sniffer, "info"
	return nil
}

func domainPolicyRules(doc map[string]interface{}) []string {
	state, err := readDomainPolicy(doc)
	if err != nil || !state.Enabled {
		return nil
	}
	return []string{
		"AND,((NETWORK,udp),(DST-PORT,443))," + quicGuardGroup,
		"AND,((NETWORK,udp),(DST-PORT,8443))," + quicGuardGroup,
	}
}

func validDomainLogLevel(level string) bool {
	switch level {
	case "silent", "error", "warning", "info", "debug":
		return true
	}
	return false
}

func validateSniffer(value map[string]interface{}) error {
	if value == nil {
		return errors.New("пустая настройка распознавания доменов")
	}
	if _, err := copyDomainValue(value, 0); err != nil {
		return err
	}
	for _, key := range []string{"enable", "force-dns-mapping", "parse-pure-ip", "override-destination"} {
		if raw, found := value[key]; found {
			if _, ok := raw.(bool); !ok {
				return errors.New("неверный переключатель распознавания доменов")
			}
		}
	}
	for _, key := range []string{"force-domain", "skip-domain", "skip-src-address", "skip-dst-address"} {
		if raw, found := value[key]; found {
			switch values := raw.(type) {
			case []string:
			case []interface{}:
				for _, item := range values {
					if _, ok := item.(string); !ok {
						return errors.New("неверные исключения распознавания доменов")
					}
				}
			default:
				return errors.New("неверные исключения распознавания доменов")
			}
		}
	}
	if raw, present := value["sniff"]; present {
		protocols, ok := raw.(map[string]interface{})
		if !ok {
			return errors.New("неверный список протоколов распознавания доменов")
		}
		for _, raw := range protocols {
			options, ok := raw.(map[string]interface{})
			if !ok {
				return errors.New("неверные настройки протокола распознавания доменов")
			}
			if raw, present := options["override-destination"]; present {
				if _, ok := raw.(bool); !ok {
					return errors.New("неверный переключатель назначения домена")
				}
			}
			if raw, present := options["ports"]; present {
				var values []interface{}
				switch ports := raw.(type) {
				case []interface{}:
					values = ports
				case []string:
					for _, p := range ports {
						values = append(values, p)
					}
				case []int:
					for _, p := range ports {
						values = append(values, p)
					}
				default:
					return errors.New("неверные порты распознавания доменов")
				}
				for _, port := range values {
					if !validSniffPort(port) {
						return errors.New("неверный диапазон портов распознавания доменов")
					}
				}
			}
		}
	}
	return nil
}

func validSniffPort(raw interface{}) bool {
	if value, ok := raw.(int); ok {
		return value > 0 && value <= 65535
	}
	if value, ok := raw.(float64); ok {
		return value > 0 && value <= 65535 && value == math.Trunc(value)
	}
	value, ok := raw.(string)
	if !ok {
		return false
	}
	start, end, interval := strings.Cut(value, "-")
	from, err := strconv.Atoi(start)
	if err != nil || from < 1 || from > 65535 {
		return false
	}
	if !interval {
		return true
	}
	to, err := strconv.Atoi(end)
	return err == nil && to >= from && to <= 65535
}

// Copy only YAML-compatible values, retaining integer and slice types in the
// in-memory snapshot. Reject cycles and objects that cannot be restored safely.
func copyDomainValue(value interface{}, depth int) (interface{}, error) {
	if depth > 32 {
		return nil, errors.New("слишком сложная настройка распознавания доменов")
	}
	switch value := value.(type) {
	case nil, bool, string, int, int64, uint64:
		return value, nil
	case float64:
		if !math.IsNaN(value) && !math.IsInf(value, 0) {
			return value, nil
		}
	case []string:
		if value == nil {
			return []string(nil), nil
		}
		return append(make([]string, 0, len(value)), value...), nil
	case []int:
		if value == nil {
			return []int(nil), nil
		}
		return append(make([]int, 0, len(value)), value...), nil
	case []interface{}:
		if value == nil {
			return []interface{}(nil), nil
		}
		result := make([]interface{}, len(value))
		for i, item := range value {
			copied, err := copyDomainValue(item, depth+1)
			if err != nil {
				return nil, err
			}
			result[i] = copied
		}
		return result, nil
	case map[string]interface{}:
		if value == nil {
			return map[string]interface{}(nil), nil
		}
		result := make(map[string]interface{}, len(value))
		for key, item := range value {
			copied, err := copyDomainValue(item, depth+1)
			if err != nil {
				return nil, err
			}
			result[key] = copied
		}
		return result, nil
	}
	return nil, errors.New("неподдерживаемый формат распознавания доменов")
}
