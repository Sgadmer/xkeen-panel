package xkeen

import (
	"fmt"
	"net/url"
	"strings"
)

func uriQueryAlias(query url.Values, keys ...string) (string, error) {
	value := ""
	for _, key := range keys {
		if values, present := query[key]; present {
			if len(values) != 1 || (value != "" && values[0] != "" && value != values[0]) {
				return "", uriOutboundError()
			}
			if values[0] != "" {
				value = values[0]
			}
		}
	}
	return value, nil
}

func uriBool(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off", "":
		return false, nil
	default:
		return false, uriOutboundError()
	}
}

// Only representable transports are accepted. In particular, external plugin
// and global dialer references must not silently turn into a plain endpoint.
func buildURIStream(query url.Values, defaultSecurity string) (map[string]interface{}, error) {
	allowed := map[string]bool{}
	for _, key := range strings.Fields("type security sni peer serverName fp fingerprint alpn insecure allowInsecure skip-cert-verify pcs vcn pbk sid spx pqv host path headerType serviceName grpcServiceName authority multiMode mode extra encryption flow") {
		allowed[key] = true
	}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 {
			return nil, uriOutboundError()
		}
	}
	security := query.Get("security")
	if security == "" {
		security = defaultSecurity
	}
	if security != "none" && security != "tls" && security != "reality" {
		return nil, uriOutboundError()
	}
	network := query.Get("type")
	if network == "" {
		network = "tcp"
	}
	switch network {
	case "tcp", "raw", "ws", "grpc", "xhttp", "httpupgrade", "h2", "http":
	default:
		return nil, uriOutboundError()
	}
	stream := map[string]interface{}{"network": network}
	if security != "none" {
		stream["security"] = security
	}
	sni, err := uriQueryAlias(query, "sni", "peer", "serverName")
	if err != nil {
		return nil, err
	}
	fingerprint, err := uriQueryAlias(query, "fp", "fingerprint")
	if err != nil {
		return nil, err
	}
	insecure := false
	for _, key := range []string{"insecure", "allowInsecure", "skip-cert-verify"} {
		value, err := uriBool(query.Get(key))
		if err != nil {
			return nil, err
		}
		insecure = insecure || value
	}
	if insecure && (security != "tls" || query.Get("pcs") == "") {
		return nil, fmt.Errorf("allowInsecure удалён из Xray; нужен проверяемый сертификат или его отпечаток")
	}
	if security == "none" {
		for _, key := range []string{"sni", "peer", "serverName", "fp", "fingerprint", "alpn", "pcs", "vcn", "pbk", "sid", "spx", "pqv"} {
			if query.Get(key) != "" {
				return nil, uriOutboundError()
			}
		}
	} else if security == "tls" {
		for _, key := range []string{"pbk", "sid", "spx", "pqv"} {
			if query.Get(key) != "" {
				return nil, uriOutboundError()
			}
		}
		tls := map[string]interface{}{}
		for key, value := range map[string]string{"serverName": sni, "fingerprint": fingerprint, "pinnedPeerCertSha256": query.Get("pcs"), "verifyPeerCertByName": query.Get("vcn")} {
			if value != "" {
				tls[key] = value
			}
		}
		if pins := query.Get("pcs"); pins != "" {
			var normalized []string
			for _, pin := range strings.Split(pins, ",") {
				value, ok := formatCertificatePin(pin)
				if !ok {
					return nil, uriOutboundError()
				}
				normalized = append(normalized, value)
			}
			tls["pinnedPeerCertSha256"] = strings.Join(normalized, ",")
		}
		if value := query.Get("alpn"); value != "" {
			var protocols []string
			for _, protocol := range strings.Split(value, ",") {
				protocol = strings.TrimSpace(protocol)
				if protocol == "" {
					return nil, uriOutboundError()
				}
				protocols = append(protocols, protocol)
			}
			tls["alpn"] = protocols
		}
		stream["tlsSettings"] = tls
	} else {
		if query.Get("pbk") == "" || query.Get("pcs") != "" || query.Get("vcn") != "" || query.Get("alpn") != "" {
			return nil, uriOutboundError()
		}
		reality := map[string]interface{}{"publicKey": query.Get("pbk")}
		for key, value := range map[string]string{"serverName": sni, "fingerprint": fingerprint, "shortId": query.Get("sid"), "spiderX": query.Get("spx"), "mldsa65Verify": query.Get("pqv")} {
			if value != "" {
				reality[key] = value
			}
		}
		stream["realitySettings"] = reality
	}
	if network != "xhttp" && query.Get("extra") != "" {
		return nil, uriOutboundError()
	}
	if network != "grpc" && (query.Get("serviceName") != "" || query.Get("grpcServiceName") != "" || query.Get("authority") != "" || query.Has("multiMode")) {
		return nil, uriOutboundError()
	}
	if network != "grpc" && network != "xhttp" && query.Get("mode") != "" {
		return nil, uriOutboundError()
	}
	header := query.Get("headerType")
	if network != "tcp" && network != "raw" && header != "" && header != "none" {
		return nil, uriOutboundError()
	}
	switch network {
	case "tcp", "raw":
		if header != "" && header != "none" && header != "http" {
			return nil, uriOutboundError()
		}
		if header == "http" {
			path := query.Get("path")
			if path == "" {
				path = "/"
			}
			request := map[string]interface{}{"path": strings.Split(path, ",")}
			if host := query.Get("host"); host != "" {
				request["headers"] = map[string]interface{}{"Host": strings.Split(host, ",")}
			}
			settings := map[string]interface{}{"header": map[string]interface{}{"type": "http", "request": request}}
			key := "tcpSettings"
			if network == "raw" {
				key = "rawSettings"
			}
			stream[key] = settings
		} else if query.Get("host") != "" || (query.Get("path") != "" && query.Get("path") != "/") {
			return nil, uriOutboundError()
		}
	case "ws":
		settings := map[string]interface{}{}
		if host := query.Get("host"); host != "" {
			settings["host"] = host
		}
		if path := query.Get("path"); path != "" {
			settings["path"] = path
		}
		stream["wsSettings"] = settings
	case "grpc":
		service, err := uriQueryAlias(query, "serviceName", "grpcServiceName", "path")
		if err != nil {
			return nil, err
		}
		settings := map[string]interface{}{}
		if service != "" {
			settings["serviceName"] = service
		}
		if authority := query.Get("authority"); authority != "" {
			settings["authority"] = authority
		}
		if query.Get("host") != "" {
			return nil, uriOutboundError()
		}
		mode := query.Get("mode")
		if mode != "" && mode != "gun" && mode != "multi" {
			return nil, uriOutboundError()
		}
		multi, err := uriBool(query.Get("multiMode"))
		if err != nil || (query.Has("multiMode") && mode != "" && multi != (mode == "multi")) {
			return nil, uriOutboundError()
		}
		if mode != "" || query.Has("multiMode") {
			settings["multiMode"] = multi || mode == "multi"
		}
		stream["grpcSettings"] = settings
	case "xhttp":
		settings := map[string]interface{}{}
		if extra := query.Get("extra"); extra != "" {
			var err error
			settings, err = uriJSONObject([]byte(extra))
			if err != nil || uriHasGlobalReference(settings) {
				return nil, uriOutboundError()
			}
		}
		for _, key := range []string{"host", "path", "mode"} {
			if value := query.Get(key); value != "" {
				if existing, present := settings[key]; present && existing != value {
					return nil, uriOutboundError()
				}
				settings[key] = value
			}
		}
		if mode, _ := settings["mode"].(string); mode != "" && mode != "auto" && mode != "packet-up" && mode != "stream-up" && mode != "stream-one" {
			return nil, uriOutboundError()
		}
		stream["xhttpSettings"] = settings
	case "httpupgrade":
		settings := map[string]interface{}{}
		for _, key := range []string{"host", "path"} {
			if value := query.Get(key); value != "" {
				settings[key] = value
			}
		}
		stream["httpupgradeSettings"] = settings
	case "h2", "http":
		settings := map[string]interface{}{}
		if host := query.Get("host"); host != "" {
			settings["host"] = strings.Split(host, ",")
		}
		if path := query.Get("path"); path != "" {
			settings["path"] = path
		}
		stream["network"] = "http"
		stream["httpSettings"] = settings
	}
	return stream, nil
}

func uriHasGlobalReference(value interface{}) bool {
	switch value := value.(type) {
	case map[string]interface{}:
		for key, item := range value {
			if key == "dialerProxy" || key == "outboundTag" || key == "proxySettings" {
				return true
			}
			if uriHasGlobalReference(item) {
				return true
			}
		}
	case []interface{}:
		for _, item := range value {
			if uriHasGlobalReference(item) {
				return true
			}
		}
	}
	return false
}
