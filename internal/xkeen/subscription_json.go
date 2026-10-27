package xkeen

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"xkeen-panel/internal/models"
)

// ImportReport describes skipped profiles without including credentials or URLs.
type ImportReport struct {
	Imported           int      `json:"imported"`
	ImportedProfiles   int      `json:"imported_profiles,omitempty"`
	SkippedComposite   int      `json:"skipped_composite"`
	SkippedUnsupported int      `json:"skipped_unsupported"`
	Warnings           []string `json:"warnings,omitempty"`
}

const maxSubscriptionBody = 16 << 20

// ParseSubscriptionDetailed accepts URI subscriptions and full Xray JSON
// profiles, optionally base64 wrapped. Client inbounds/DNS/routing are never
// copied to the router. A composite profile is skipped rather than flattened.
func ParseSubscriptionDetailed(content string) ([]models.Server, ImportReport, error) {
	report := ImportReport{}
	if len(content) > maxSubscriptionBody {
		return nil, report, fmt.Errorf("подписка слишком большая")
	}
	body := trimSubscriptionBody(content)
	for depth := 0; depth < 3 && body != ""; depth++ {
		if strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") || strings.Contains(body, "://") || looksLikeClashYAML(body) {
			break
		}
		compact := strings.Join(strings.Fields(body), "")
		var decoded []byte
		var err error
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			decoded, err = encoding.DecodeString(compact)
			if err == nil {
				break
			}
		}
		if err != nil {
			break
		}
		body = trimSubscriptionBody(string(decoded))
	}
	var servers []models.Server
	var err error
	var foreign bool
	servers, foreign, err = parseForeignSubscription(body, &report)
	if foreign {
		// Foreign endpoint converters never apply client DNS/routes/groups.
	} else if strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") {
		if !json.Valid([]byte(body)) {
			return nil, report, fmt.Errorf("подписка содержит некорректный Xray JSON")
		}
		servers, err = parseJSONSubscription(json.RawMessage(body), &report)
	} else {
		servers, err = parseURISubscription(body)
	}
	if err != nil {
		return nil, report, err
	}
	report.Imported = len(servers)
	if report.SkippedComposite > 0 {
		report.Warnings = append(report.Warnings, "Некоторые составные профили используют неподдерживаемые функции; доступные серверы и профили сохранены.")
	}
	if report.SkippedUnsupported > 0 {
		report.Warnings = append(report.Warnings, "Часть записей не является поддерживаемым самостоятельным Xray-сервером.")
	}
	if len(servers) == 0 {
		return nil, report, fmt.Errorf("в подписке нет поддерживаемых независимых серверов")
	}
	for i := range servers {
		servers[i].ID = i
		servers[i].Latency = -1
		servers[i].Country = detectCountry(servers[i].Name)
	}
	return servers, report, nil
}

func trimSubscriptionBody(body string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(body), "\ufeff"))
}

func parseJSONSubscription(root json.RawMessage, report *ImportReport) ([]models.Server, error) {
	var servers []models.Server
	seen := make(map[string]bool)
	var visit func(json.RawMessage, int)
	add := func(raw json.RawMessage, hint string) {
		outbound, err := decodeServerOutbound(raw)
		if err != nil || hasOutboundDependency(outbound) {
			if hasOutboundDependency(outbound) {
				report.SkippedComposite++
			} else {
				report.SkippedUnsupported++
			}
			return
		}
		server, err := serverFromRawOutbound(raw, hint)
		if err != nil {
			report.SkippedUnsupported++
			return
		}
		key := ServerIdentity(server)
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		servers = append(servers, server)
	}
	visit = func(raw json.RawMessage, depth int) {
		if depth > 16 || len(servers) >= 4096 {
			report.SkippedUnsupported++
			return
		}
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			return
		}
		if raw[0] == '[' {
			var list []json.RawMessage
			if json.Unmarshal(raw, &list) != nil {
				report.SkippedUnsupported++
				return
			}
			for _, entry := range list {
				visit(entry, depth+1)
			}
			return
		}
		var object map[string]json.RawMessage
		if raw[0] != '{' || json.Unmarshal(raw, &object) != nil {
			report.SkippedUnsupported++
			return
		}
		if outbounds, ok := object["outbounds"]; ok {
			var entries []json.RawMessage
			if json.Unmarshal(outbounds, &entries) != nil {
				report.SkippedUnsupported++
				return
			}
			var proxies []json.RawMessage
			for _, entry := range entries {
				var endpoint map[string]json.RawMessage
				if json.Unmarshal(entry, &endpoint) != nil {
					report.SkippedUnsupported++
					continue
				}
				proto := rawString(endpoint["protocol"])
				if proto != "" && !serviceProtocols[strings.ToLower(proto)] {
					proxies = append(proxies, entry)
				}
			}
			if len(proxies) > 1 || profileHasBalancer(object) {
				server, err := serverFromRawProfile(raw)
				if err != nil {
					report.SkippedComposite++
					return
				}
				key := ServerIdentity(server)
				if key != "" && !seen[key] {
					seen[key] = true
					servers = append(servers, server)
					report.ImportedProfiles++
					if bundle, bundleErr := BuildProfileBundle(server, ManualTag, nil); bundleErr == nil {
						for _, note := range bundle.Adaptations {
							found := false
							for _, old := range report.Warnings {
								found = found || old == note
							}
							if !found {
								report.Warnings = append(report.Warnings, note)
							}
						}
					}
				}
				return
			}
			if len(proxies) == 1 {
				add(proxies[0], objectDisplayName(object))
			} else {
				report.SkippedUnsupported++
			}
			return
		}
		if _, ok := object["protocol"]; ok {
			add(raw, objectDisplayName(object))
			return
		}
		found := false
		for _, key := range []string{"configs", "nodes", "profiles", "servers", "subscriptions", "data", "items", "entries"} {
			if child, ok := object[key]; ok {
				found = true
				visit(child, depth+1)
			}
		}
		if !found {
			report.SkippedUnsupported++
		}
	}
	visit(root, 0)
	return servers, nil
}

func profileHasBalancer(object map[string]json.RawMessage) bool {
	var routing struct {
		Balancers []json.RawMessage `json:"balancers"`
		Rules     []struct {
			BalancerTag string `json:"balancerTag"`
		} `json:"rules"`
	}
	if json.Unmarshal(object["routing"], &routing) == nil {
		if len(routing.Balancers) > 0 {
			return true
		}
		for _, rule := range routing.Rules {
			if rule.BalancerTag != "" {
				return true
			}
		}
	}
	return false
}

func rawString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return strings.TrimSpace(value)
}

func objectDisplayName(object map[string]json.RawMessage) string {
	for _, key := range []string{"remarks", "name", "ps", "remark", "tag"} {
		if value := rawString(object[key]); value != "" {
			return value
		}
	}
	return ""
}

func serverFromRawOutbound(raw json.RawMessage, hint string) (models.Server, error) {
	ob, err := decodeServerOutbound(raw)
	if err != nil {
		return models.Server{}, err
	}
	address, port, proto, err := outboundMetadata(ob)
	if err != nil {
		return models.Server{}, err
	}
	name := strings.TrimSpace(hint)
	if name == "" {
		name, _ = ob["tag"].(string)
	}
	if strings.TrimSpace(name) == "" {
		name = address
	}
	server := models.Server{Name: name, Address: address, Port: port, Protocol: proto, Latency: -1,
		RawOutbound: append(json.RawMessage(nil), raw...)}
	server.RawURI = ServerIdentity(server)
	return server, nil
}

func decodeServerOutbound(raw json.RawMessage) (map[string]interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var object map[string]interface{}
	if decoder.Decode(&object) != nil || object == nil {
		return nil, fmt.Errorf("некорректный Xray outbound")
	}
	var extra interface{}
	if decoder.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("некорректный Xray outbound")
	}
	return object, nil
}
