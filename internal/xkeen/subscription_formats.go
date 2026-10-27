package xkeen

// Foreign formats are translated field by field. Keeping an unknown field in
// Xray JSON would be worse than dropping it: Xray ignores many unknown keys.
// Unconsumed endpoint/security/transport fields therefore reject that endpoint.
import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"xkeen-panel/internal/models"
)

var errFormatUnsupported = errors.New("unsupported subscription endpoint parameters")
var errFormatComposite = errors.New("dependent subscription endpoint")
var clashYAMLKey = regexp.MustCompile(`(?m)^[ \t]*(?:proxies|proxy-groups|proxy-providers)\s*:`)

const foreignPolicyWarning = "Импортированы самостоятельные серверы. Группы, маршрутизация, DNS и локальные политики исходного приложения не переносятся; используются настройки роутера."

func looksLikeClashYAML(body string) bool { return clashYAMLKey.MatchString(body) }

func addFormatWarning(report *ImportReport, warning string) {
	for _, current := range report.Warnings {
		if current == warning {
			return
		}
	}
	report.Warnings = append(report.Warnings, warning)
}

// parseForeignSubscription returns handled=false for native Xray JSON/URI.
// Client policy blocks are deliberately never installed on the router.
func parseForeignSubscription(body string, report *ImportReport) ([]models.Server, bool, error) {
	var root interface{}
	jsonBody := trimSubscriptionBody(string(StripJSONComments([]byte(body))))
	if strings.HasPrefix(jsonBody, "{") || strings.HasPrefix(jsonBody, "[") {
		decoder := json.NewDecoder(strings.NewReader(jsonBody))
		decoder.UseNumber()
		if decoder.Decode(&root) != nil {
			return nil, false, nil
		}
		var extra interface{}
		if decoder.Decode(&extra) != io.EOF {
			return nil, false, nil
		}
	} else if looksLikeClashYAML(body) {
		decoder := yaml.NewDecoder(strings.NewReader(body))
		var document yaml.Node
		if decoder.Decode(&document) != nil || !boundedSubscriptionYAML(&document) || document.Decode(&root) != nil {
			return nil, true, fmt.Errorf("некорректная YAML-подписка")
		}
		var extra interface{}
		if decoder.Decode(&extra) != io.EOF {
			return nil, true, fmt.Errorf("подписка содержит несколько YAML-документов")
		}
		// Round-trip also rejects non-string mapping keys rather than guessing.
		raw, err := json.Marshal(root)
		if err != nil {
			return nil, true, fmt.Errorf("некорректная структура YAML-подписки")
		}
		decoderJSON := json.NewDecoder(bytes.NewReader(raw))
		decoderJSON.UseNumber()
		if decoderJSON.Decode(&root) != nil {
			return nil, true, fmt.Errorf("некорректная структура YAML-подписки")
		}
	} else {
		return nil, false, nil
	}

	var entries []interface{}
	var convert func(map[string]interface{}) (map[string]interface{}, string, error)
	switch object := root.(type) {
	case map[string]interface{}:
		if proxies, ok := object["proxies"]; ok {
			var valid bool
			entries, valid = proxies.([]interface{})
			if !valid {
				return nil, true, fmt.Errorf("список серверов YAML/Clash некорректен")
			}
			convert = convertClashEndpoint
			if groups, ok := object["proxy-groups"].([]interface{}); ok {
				report.SkippedComposite += len(groups)
			}
			if providers, ok := object["proxy-providers"].(map[string]interface{}); ok {
				report.SkippedUnsupported += len(providers)
			}
		} else if list, ok := object["outbounds"].([]interface{}); ok && containsSingBoxType(list) {
			entries, convert = list, convertSingBoxEndpoint
		} else if _, ok := object["type"].(string); ok && object["protocol"] == nil {
			entries, convert = []interface{}{object}, convertSingBoxEndpoint
		} else if looksLikeClashYAML(body) {
			report.SkippedUnsupported++
			addFormatWarning(report, foreignPolicyWarning)
			return nil, true, nil
		} else {
			return nil, false, nil
		}
	case []interface{}:
		if !containsSingBoxType(object) {
			return nil, false, nil
		}
		entries, convert = object, convertSingBoxEndpoint
	default:
		return nil, false, nil
	}
	addFormatWarning(report, foreignPolicyWarning)
	capacity := len(entries)
	if capacity > 4096 {
		capacity = 4096
	}
	servers := make([]models.Server, 0, capacity)
	seen := map[string]bool{}
	for index, entry := range entries {
		if index >= 4096 {
			report.SkippedUnsupported += len(entries) - index
			break
		}
		object, ok := entry.(map[string]interface{})
		if !ok {
			report.SkippedUnsupported++
			continue
		}
		outbound, name, err := convert(object)
		if errors.Is(err, errFormatComposite) {
			report.SkippedComposite++
			continue
		}
		if err != nil {
			report.SkippedUnsupported++
			continue
		}
		if outbound == nil {
			continue
		} // direct/block/DNS infrastructure
		raw, err := json.Marshal(outbound)
		if err != nil {
			report.SkippedUnsupported++
			continue
		}
		server, err := serverFromRawOutbound(raw, name)
		if err != nil {
			report.SkippedUnsupported++
			continue
		}
		identity := ServerIdentity(server)
		if identity == "" || seen[identity] {
			continue
		}
		seen[identity] = true
		servers = append(servers, server)
	}
	return servers, true, nil
}

// Count alias expansion before decoding to maps: a short subscription must not
// allocate an unbounded graph on a router. Ordinary YAML anchors/merge keys are
// supported, cyclic aliases and excessive nesting/expansion are rejected.
func boundedSubscriptionYAML(root *yaml.Node) bool {
	budget := 200000
	visiting := map[*yaml.Node]bool{}
	var visit func(*yaml.Node, int) bool
	visit = func(node *yaml.Node, depth int) bool {
		budget--
		if node == nil || depth > 64 || budget < 0 || visiting[node] {
			return false
		}
		visiting[node] = true
		defer delete(visiting, node)
		if node.Alias != nil && !visit(node.Alias, depth+1) {
			return false
		}
		for _, child := range node.Content {
			if !visit(child, depth+1) {
				return false
			}
		}
		return true
	}
	return visit(root, 0)
}

func containsSingBoxType(entries []interface{}) bool {
	for _, entry := range entries {
		if object, ok := entry.(map[string]interface{}); ok && object["protocol"] == nil {
			if _, ok := object["type"].(string); ok {
				return true
			}
		}
	}
	return false
}

type formatFields struct {
	values   map[string]interface{}
	children []*formatFields
	bad      bool
}

func newFormatFields(values map[string]interface{}) *formatFields {
	copy := make(map[string]interface{}, len(values))
	for k, v := range values {
		copy[k] = v
	}
	return &formatFields{values: copy}
}
func (f *formatFields) take(key string) interface{} {
	value := f.values[key]
	delete(f.values, key)
	return value
}
func (f *formatFields) text(key string) string {
	value := f.take(key)
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return string(v)
	default:
		f.bad = true
		return ""
	}
}
func (f *formatFields) boolean(key string) bool {
	value := f.take(key)
	if value == nil {
		return false
	}
	result, ok := value.(bool)
	if !ok {
		f.bad = true
	}
	return result
}
func (f *formatFields) integer(key string) int {
	value := f.take(key)
	if value == nil {
		return 0
	}
	text := ""
	switch v := value.(type) {
	case string:
		text = v
	case json.Number:
		text = string(v)
	default:
		f.bad = true
		return 0
	}
	result, err := strconv.ParseInt(text, 10, 32)
	if err != nil {
		f.bad = true
	}
	return int(result)
}
func (f *formatFields) list(key string) []string {
	value := f.take(key)
	if value == nil {
		return nil
	}
	if text, ok := value.(string); ok {
		return []string{text}
	}
	entries, ok := value.([]interface{})
	if !ok {
		f.bad = true
		return nil
	}
	var result []string
	for _, entry := range entries {
		text, ok := entry.(string)
		if !ok {
			f.bad = true
			continue
		}
		result = append(result, text)
	}
	return result
}
func (f *formatFields) child(key string) *formatFields {
	value := f.take(key)
	object, ok := value.(map[string]interface{})
	if value != nil && !ok {
		f.bad = true
	}
	child := newFormatFields(object)
	f.children = append(f.children, child)
	return child
}
func (f *formatFields) zero(key string) {
	value := f.take(key)
	switch v := value.(type) {
	case nil:
		return
	case bool:
		if !v {
			return
		}
	case string:
		if v == "" {
			return
		}
	case json.Number:
		if v == "0" {
			return
		}
	case []interface{}:
		if len(v) == 0 {
			return
		}
	case map[string]interface{}:
		if len(v) == 0 {
			return
		}
	}
	f.bad = true
}
func (f *formatFields) valid() bool {
	if f.bad || len(f.values) > 0 {
		return false
	}
	for _, child := range f.children {
		if !child.valid() {
			return false
		}
	}
	return true
}

func formatHeaders(f *formatFields, key string) map[string]interface{} {
	value := f.take(key)
	if value == nil {
		return nil
	}
	object, ok := value.(map[string]interface{})
	if !ok {
		f.bad = true
		return nil
	}
	result := map[string]interface{}{}
	for name, value := range object {
		text, ok := value.(string)
		if !ok {
			if entries, valid := value.([]interface{}); valid && len(entries) == 1 {
				text, ok = entries[0].(string)
			}
		}
		if !ok || strings.ContainsAny(name+text, "\r\n") {
			f.bad = true
			continue
		}
		result[name] = text
	}
	return result
}

func formatDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func formatEndpoint(protocol, name, address string, port int, user map[string]interface{}) (map[string]interface{}, error) {
	if strings.TrimSpace(address) == "" || port < 1 || port > 65535 {
		return nil, errFormatUnsupported
	}
	settings := map[string]interface{}{}
	endpoint := map[string]interface{}{"address": address, "port": port}
	switch protocol {
	case "vless", "vmess":
		if user["id"] == nil || user["id"] == "" {
			return nil, errFormatUnsupported
		}
		endpoint["users"] = []interface{}{user}
		settings["vnext"] = []interface{}{endpoint}
	case "trojan", "shadowsocks":
		if user["password"] == nil || user["password"] == "" {
			return nil, errFormatUnsupported
		}
		for k, v := range user {
			endpoint[k] = v
		}
		settings["servers"] = []interface{}{endpoint}
	case "socks", "http":
		username, _ := user["user"].(string)
		password, _ := user["pass"].(string)
		if username == "" && password != "" || protocol == "socks" && (len(username) > 255 || len(password) > 255) {
			return nil, errFormatUnsupported
		}
		if user["user"] != "" || user["pass"] != "" {
			endpoint["users"] = []interface{}{user}
		}
		settings["servers"] = []interface{}{endpoint}
	case "hysteria":
		settings = endpoint
		settings["version"] = 2
	default:
		return nil, errFormatUnsupported
	}
	return map[string]interface{}{"tag": name, "protocol": protocol, "settings": settings}, nil
}

func formatVMessSecurity(value string) bool {
	switch value {
	case "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305":
		return true
	}
	return false
}
func formatSSMethod(value string) bool {
	switch value {
	case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305", "xchacha20-ietf-poly1305", "xchacha20-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return true
	}
	return false
}

func formatWebSocket(stream map[string]interface{}, f *formatFields, pathKey, earlyKey, headerKey string, upgrade bool) {
	path := formatDefault(f.text(pathKey), "/")
	early := f.integer(earlyKey)
	header := f.text(headerKey)
	if early < 0 {
		f.bad = true
	}
	if early > 0 {
		// Xray uses the Sec-WebSocket-Protocol header. sing-box's default
		// path early-data mode is a different protocol and must be rejected.
		if !strings.EqualFold(header, "Sec-WebSocket-Protocol") {
			f.bad = true
		}
		parsed, err := url.Parse(path)
		if err != nil {
			f.bad = true
		} else {
			query := parsed.Query()
			query.Set("ed", strconv.Itoa(early))
			parsed.RawQuery = query.Encode()
			path = parsed.String()
		}
	}
	settings := map[string]interface{}{"path": path}
	headers := formatHeaders(f, "headers")
	for key, value := range headers {
		if strings.EqualFold(key, "Host") {
			settings["host"] = value
			delete(headers, key)
		}
	}
	if len(headers) > 0 {
		settings["headers"] = headers
	}
	if upgrade {
		stream["network"] = "httpupgrade"
		stream["httpupgradeSettings"] = settings
	} else {
		stream["network"] = "ws"
		stream["wsSettings"] = settings
	}
}

func formatSeconds(f *formatFields, key string) int {
	value := f.text(key)
	if value == "" {
		return 0
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 || duration%time.Second != 0 || duration/time.Second > 1<<31-1 {
		f.bad = true
		return 0
	}
	return int(duration / time.Second)
}

// Certificate pins are full leaf-certificate SHA256, never SPKI fingerprints.
func formatCertificatePin(value string) (string, bool) {
	compact := strings.ReplaceAll(strings.TrimSpace(value), ":", "")
	if len(compact) != 64 {
		return "", false
	}
	for _, r := range compact {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return "", false
		}
	}
	return strings.ToLower(compact), true
}

func formatApplyTLS(stream map[string]interface{}, enabled bool, settings map[string]interface{}, reality map[string]interface{}, insecure bool) bool {
	if !enabled {
		return len(settings) == 0 && len(reality) == 0 && !insecure
	}
	if len(reality) > 0 {
		if insecure {
			return false
		}
		stream["security"] = "reality"
		stream["realitySettings"] = reality
		return true
	}
	// v26.3.27 rejects allowInsecure after June 2026. A pin provides a
	// supported trust anchor; insecure-only endpoints cannot be represented.
	if insecure && settings["pinnedPeerCertSha256"] == nil {
		return false
	}
	stream["security"] = "tls"
	stream["tlsSettings"] = settings
	return true
}

func formatHysteria(stream map[string]interface{}, password string, up, down string, obfs, obfsPassword string) bool {
	if password == "" || stream["security"] != "tls" {
		return false
	}
	stream["network"] = "hysteria"
	stream["hysteriaSettings"] = map[string]interface{}{"version": 2, "auth": password}
	tls := mapOf(stream["tlsSettings"])
	if tls["alpn"] == nil {
		tls["alpn"] = []string{"h3"}
	}
	finalmask := map[string]interface{}{}
	quic := map[string]interface{}{}
	if up != "" {
		quic["brutalUp"] = up
	}
	if down != "" {
		quic["brutalDown"] = down
	}
	if up != "" || down != "" {
		quic["congestion"] = "brutal"
	}
	if len(quic) > 0 {
		finalmask["quicParams"] = quic
	}
	if obfs != "" {
		if obfs != "salamander" || obfsPassword == "" {
			return false
		}
		finalmask["udp"] = []interface{}{map[string]interface{}{"type": "salamander", "settings": map[string]interface{}{"password": obfsPassword}}}
	} else if obfsPassword != "" {
		return false
	}
	if len(finalmask) > 0 {
		stream["finalmask"] = finalmask
	}
	return true
}

func formatBandwidth(value interface{}, defaultMbps bool) (string, bool) {
	if value == nil {
		return "", true
	}
	var text string
	switch v := value.(type) {
	case string:
		text = v
	case json.Number:
		text = string(v)
	default:
		return "", false
	}
	text = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(text), " ", ""))
	if text == "" {
		return "", true
	}
	index := 0
	for index < len(text) && ((text[index] >= '0' && text[index] <= '9') || text[index] == '.') {
		index++
	}
	if index == 0 {
		return "", false
	}
	number, err := strconv.ParseFloat(text[:index], 64)
	if err != nil || number < 0 {
		return "", false
	}
	unit := text[index:]
	multiplier := float64(1)
	switch unit {
	case "":
		if defaultMbps {
			multiplier = 1e6
		}
	case "bps", "b":
	case "kbps", "k":
		multiplier = 1e3
	case "mbps", "m":
		multiplier = 1e6
	case "gbps", "g":
		multiplier = 1e9
	default:
		return "", false
	}
	bps := number * multiplier
	if bps == 0 {
		return "", true
	}
	if bps < 524288 || bps > 1e15 {
		return "", false
	}
	return strconv.FormatFloat(bps, 'f', 0, 64) + "bps", true
}

func formatHopPorts(entries []string) (string, int, bool) {
	var result []string
	first := 0
	for _, entry := range entries {
		for _, part := range strings.Split(entry, ",") {
			part = strings.ReplaceAll(strings.TrimSpace(part), ":", "-")
			bounds := strings.Split(part, "-")
			if len(bounds) < 1 || len(bounds) > 2 {
				return "", 0, false
			}
			start, err := strconv.Atoi(bounds[0])
			if err != nil || start < 1 || start > 65535 {
				return "", 0, false
			}
			end := start
			if len(bounds) == 2 {
				end, err = strconv.Atoi(bounds[1])
				if err != nil || end < start || end > 65535 {
					return "", 0, false
				}
			}
			if first == 0 {
				first = start
			}
			result = append(result, part)
			if len(result) > 1024 {
				return "", 0, false
			}
		}
	}
	return strings.Join(result, ","), first, len(result) > 0
}

func formatHysteriaHops(stream map[string]interface{}, ports, interval string) {
	finalmask := mapOf(stream["finalmask"])
	if finalmask == nil {
		finalmask = map[string]interface{}{}
		stream["finalmask"] = finalmask
	}
	quic := mapOf(finalmask["quicParams"])
	if quic == nil {
		quic = map[string]interface{}{}
		finalmask["quicParams"] = quic
	}
	quic["udpHop"] = map[string]interface{}{"ports": ports, "interval": interval}
}
