package xkeen

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"xkeen-panel/internal/models"
)

// These parsers intentionally return fixed errors: share links contain secrets.
func uriOutboundError() error {
	return fmt.Errorf("некорректная или неподдерживаемая ссылка сервера")
}

func decodeURIBase64(value string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, uriOutboundError()
}

func uriJSONObject(data []byte) (map[string]interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var object map[string]interface{}
	if decoder.Decode(&object) != nil || object == nil {
		return nil, uriOutboundError()
	}
	var trailing interface{}
	if decoder.Decode(&trailing) != io.EOF {
		return nil, uriOutboundError()
	}
	return object, nil
}

func uriScalar(value interface{}) (string, error) {
	switch value := value.(type) {
	case nil:
		return "", nil
	case string:
		return value, nil
	case json.Number:
		return string(value), nil
	case bool:
		return strconv.FormatBool(value), nil
	default:
		return "", uriOutboundError()
	}
}

func parseOutboundURI(raw, scheme string, defaultPort int) (*url.URL, url.Values, int, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != scheme || parsed.User == nil || parsed.Hostname() == "" ||
		strings.ContainsAny(parsed.Hostname(), " \t\r\n/?#@") || parsed.Opaque != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, nil, 0, uriOutboundError()
	}
	port := defaultPort
	if parsed.Port() != "" {
		port, err = strconv.Atoi(parsed.Port())
	}
	if err != nil || port < 1 || port > 65535 {
		return nil, nil, 0, uriOutboundError()
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return nil, nil, 0, uriOutboundError()
	}
	return parsed, query, port, nil
}

func buildTrojanURIOutbound(raw, tag string) (map[string]interface{}, error) {
	parsed, query, port, err := parseOutboundURI(raw, "trojan", 443)
	if err != nil {
		return nil, err
	}
	password := parsed.User.Username()
	if suffix, present := parsed.User.Password(); present {
		password += ":" + suffix
	}
	if password == "" || query.Get("flow") != "" || query.Has("encryption") {
		return nil, uriOutboundError()
	}
	stream, err := buildURIStream(query, "tls")
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"tag": tag, "protocol": "trojan", "settings": map[string]interface{}{
		"servers": []interface{}{map[string]interface{}{"address": parsed.Hostname(), "port": port, "password": password}},
	}, "streamSettings": stream}, nil
}

func buildVMessURIOutbound(raw, tag string) (map[string]interface{}, error) {
	var address, id, cipher string
	var port int
	var query url.Values
	if strings.Contains(strings.TrimPrefix(raw, "vmess://"), "@") {
		parsed, values, value, err := parseOutboundURI(raw, "vmess", 443)
		if err != nil {
			return nil, err
		}
		if _, present := parsed.User.Password(); present {
			return nil, uriOutboundError()
		}
		address, id, port, query = parsed.Hostname(), parsed.User.Username(), value, values
		cipher = query.Get("encryption")
	} else {
		encoded := strings.SplitN(strings.TrimPrefix(raw, "vmess://"), "#", 2)[0]
		data, err := decodeURIBase64(encoded)
		if err != nil {
			return nil, err
		}
		object, err := uriJSONObject(data)
		if err != nil {
			return nil, err
		}
		query = url.Values{}
		for key, value := range object {
			text, scalarErr := uriScalar(value)
			if scalarErr != nil {
				return nil, scalarErr
			}
			switch key {
			case "v":
				if text != "" && text != "2" {
					return nil, uriOutboundError()
				}
			case "ps":
			case "add":
				address = text
			case "id":
				id = text
			case "port":
				port, err = strconv.Atoi(text)
				if err != nil {
					return nil, uriOutboundError()
				}
			case "aid", "alterId":
				if text != "" && text != "0" {
					return nil, fmt.Errorf("устаревший VMess alterId не поддерживается Xray")
				}
			case "scy":
				cipher = text
			case "net":
				query.Set("type", text)
			case "tls":
				query.Set("security", text)
			case "type":
				query.Set("headerType", text)
			case "host", "path", "sni", "alpn", "fp", "insecure", "allowInsecure", "vcn", "pcs", "mode", "serviceName", "grpcServiceName", "authority", "multiMode", "extra", "pbk", "sid", "spx", "pqv":
				query.Set(key, text)
			default:
				return nil, uriOutboundError()
			}
		}
		// The v2rayN JSON format overloads type for gRPC/XHTTP modes.
		if kind := query.Get("type"); kind == "grpc" || kind == "xhttp" {
			if mode := query.Get("headerType"); mode != "" && mode != "none" {
				if query.Get("mode") != "" && query.Get("mode") != mode {
					return nil, uriOutboundError()
				}
				query.Set("mode", mode)
			}
			query.Del("headerType")
		}
	}
	if address == "" || strings.ContainsAny(address, " \t\r\n/?#@") || id == "" || port < 1 || port > 65535 {
		return nil, uriOutboundError()
	}
	if query.Get("flow") != "" {
		return nil, uriOutboundError()
	}
	if cipher == "" {
		cipher = "auto"
	}
	switch cipher {
	case "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero":
	default:
		return nil, uriOutboundError()
	}
	stream, err := buildURIStream(query, "none")
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"tag": tag, "protocol": "vmess", "settings": map[string]interface{}{
		"vnext": []interface{}{map[string]interface{}{"address": address, "port": port, "users": []interface{}{map[string]interface{}{"id": id, "security": cipher}}}},
	}, "streamSettings": stream}, nil
}

func buildShadowsocksURIOutbound(raw, tag string) (map[string]interface{}, error) {
	legacy := false
	encodedUserinfo := false
	if !strings.Contains(strings.SplitN(strings.TrimPrefix(raw, "ss://"), "#", 2)[0], "@") {
		parts := strings.SplitN(strings.TrimPrefix(raw, "ss://"), "#", 2)
		decoded, err := decodeURIBase64(parts[0])
		if err != nil {
			return nil, err
		}
		separator := strings.LastIndexByte(string(decoded), '@')
		if separator < 1 {
			return nil, uriOutboundError()
		}
		method, password, found := strings.Cut(string(decoded[:separator]), ":")
		if !found {
			return nil, uriOutboundError()
		}
		raw = "ss://" + url.UserPassword(method, password).String() + "@" + string(decoded[separator+1:])
		legacy = true
		if len(parts) == 2 {
			raw += "#" + parts[1]
		}
	}
	// Some deployed SIP002 exporters use standard Base64 rather than URL-safe
	// Base64. Decode before net/url interprets a '/' in userinfo as a path.
	end := len(raw)
	if suffix := strings.IndexAny(raw[len("ss://"):], "?#"); suffix >= 0 {
		end = len("ss://") + suffix
	}
	if at := strings.LastIndexByte(raw[:end], '@'); at >= len("ss://") {
		userinfo := raw[len("ss://"):at]
		if !strings.Contains(userinfo, ":") {
			decoded, err := decodeURIBase64(userinfo)
			if err != nil {
				return nil, err
			}
			method, password, found := strings.Cut(string(decoded), ":")
			if !found {
				return nil, uriOutboundError()
			}
			raw = "ss://" + url.UserPassword(method, password).String() + raw[at:]
			encodedUserinfo = true
		}
	}
	parsed, query, port, err := parseOutboundURI(raw, "ss", 0)
	if err != nil {
		return nil, err
	}
	method := parsed.User.Username()
	password, plain := parsed.User.Password()
	if !plain {
		decoded, err := decodeURIBase64(method)
		if err != nil {
			return nil, err
		}
		var found bool
		method, password, found = strings.Cut(string(decoded), ":")
		if !found {
			return nil, uriOutboundError()
		}
	}
	if password == "" {
		return nil, uriOutboundError()
	}
	switch method {
	case "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305", "xchacha20-poly1305", "xchacha20-ietf-poly1305":
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		if !plain || legacy || encodedUserinfo {
			return nil, uriOutboundError()
		}
		keys := strings.Split(password, ":")
		if method == "2022-blake3-chacha20-poly1305" && len(keys) != 1 {
			return nil, uriOutboundError()
		}
		for _, key := range keys {
			data, err := base64.StdEncoding.DecodeString(key)
			length := 32
			if method == "2022-blake3-aes-128-gcm" {
				length = 16
			}
			if err != nil || len(data) != length {
				return nil, uriOutboundError()
			}
		}
	default:
		return nil, fmt.Errorf("метод Shadowsocks не поддерживается Xray")
	}
	if query.Get("plugin") != "" {
		return nil, fmt.Errorf("внешний плагин Shadowsocks не поддерживается")
	}
	if query.Has("encryption") || query.Get("flow") != "" {
		return nil, uriOutboundError()
	}
	stream, err := buildURIStream(query, "none")
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"tag": tag, "protocol": "shadowsocks", "settings": map[string]interface{}{
		"servers": []interface{}{map[string]interface{}{"address": parsed.Hostname(), "port": port, "method": method, "password": password}},
	}, "streamSettings": stream}, nil
}

// The subscription metadata parser can use this without duplicating URI rules.
func parseBuiltURIServer(raw string) (*models.Server, error) {
	outbound, err := BuildServerOutbound(models.Server{RawURI: raw}, "", nil)
	if err != nil {
		return nil, err
	}
	address, port, protocol, err := outboundMetadata(outbound)
	if err != nil {
		return nil, err
	}
	name := ""
	if parsed, err := url.Parse(raw); err == nil {
		name = parsed.Fragment
	}
	if strings.HasPrefix(raw, "vmess://") && !strings.Contains(strings.TrimPrefix(raw, "vmess://"), "@") {
		if data, err := decodeURIBase64(strings.SplitN(strings.TrimPrefix(raw, "vmess://"), "#", 2)[0]); err == nil {
			if object, err := uriJSONObject(data); err == nil {
				name, _ = object["ps"].(string)
			}
		}
	}
	if name == "" {
		name = address
	}
	return &models.Server{Name: name, Address: address, Port: port, Protocol: protocol, Latency: -1}, nil
}
