package xkeen

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
)

func convertSingBoxEndpoint(object map[string]interface{}) (map[string]interface{}, string, error) {
	f := newFormatFields(object)
	name, protocol := f.text("tag"), strings.ToLower(f.text("type"))
	switch protocol {
	case "direct", "block", "dns":
		return nil, name, nil
	case "selector", "urltest":
		return nil, name, errFormatComposite
	}
	if f.text("detour") != "" {
		return nil, name, errFormatComposite
	}
	address, port := f.text("server"), f.integer("server_port")
	if name == "" {
		name = address
	}
	network := f.text("network")
	if network != "" && network != "tcp" && network != "udp" {
		f.bad = true
	}
	tfo := f.boolean("tcp_fast_open")
	for _, key := range []string{"bind_interface", "inet4_bind_address", "inet6_bind_address", "routing_mark", "reuse_addr", "tcp_multi_path", "connect_timeout", "domain_strategy", "domain_resolver", "udp_fragment", "udp_timeout"} {
		f.zero(key)
	}
	mux := f.child("multiplex")
	if mux.boolean("enabled") {
		f.bad = true
	}
	var user map[string]interface{}
	switch protocol {
	case "vless":
		flow := f.text("flow")
		if flow != "" && flow != "xtls-rprx-vision" {
			f.bad = true
		}
		user = map[string]interface{}{"id": f.text("uuid"), "encryption": "none"}
		if flow != "" {
			user["flow"] = flow
		}
		packet := f.text("packet_encoding")
		if packet != "" && packet != "xudp" {
			f.bad = true
		}
	case "vmess":
		security := formatDefault(f.text("security"), "auto")
		if !formatVMessSecurity(security) {
			f.bad = true
		}
		if f.integer("alter_id") != 0 {
			f.bad = true
		}
		f.zero("global_padding")
		user = map[string]interface{}{"id": f.text("uuid"), "security": security}
		if f.boolean("authenticated_length") {
			user["experiments"] = "AuthenticatedLength"
		}
		packet := f.text("packet_encoding")
		if packet != "" && packet != "xudp" {
			f.bad = true
		}
	case "trojan":
		user = map[string]interface{}{"password": f.text("password")}
	case "shadowsocks":
		method := f.text("method")
		if !formatSSMethod(method) {
			f.bad = true
		}
		user = map[string]interface{}{"method": method, "password": f.text("password")}
		for _, key := range []string{"plugin", "plugin_opts", "udp_over_tcp"} {
			f.zero(key)
		}
	case "socks":
		version := f.text("version")
		if version != "" && version != "5" {
			f.bad = true
		}
		f.zero("udp_over_tcp")
		user = map[string]interface{}{"user": f.text("username"), "pass": f.text("password")}
	case "http":
		user = map[string]interface{}{"user": f.text("username"), "pass": f.text("password")}
	case "hysteria2":
		protocol = "hysteria"
	default:
		return nil, name, errFormatUnsupported
	}
	var hops string
	if protocol == "hysteria" {
		ports := f.list("server_ports")
		if len(ports) > 0 {
			var first int
			var ok bool
			hops, first, ok = formatHopPorts(ports)
			if !ok {
				f.bad = true
			}
			port = first
		}
	}
	outbound, err := formatEndpoint(protocol, name, address, port, user)
	if err != nil {
		return nil, name, err
	}
	stream := map[string]interface{}{"network": "tcp", "security": "none"}
	if tfo {
		stream["sockopt"] = map[string]interface{}{"tcpFastOpen": true}
	}
	tlsFields := f.child("tls")
	if (protocol == "shadowsocks" || protocol == "socks") && len(tlsFields.values) > 0 {
		f.bad = true
	}
	if !singBoxTLS(stream, tlsFields, address) {
		f.bad = true
	}
	if protocol == "hysteria" {
		up, ok := formatBandwidth(f.take("up_mbps"), true)
		if !ok {
			f.bad = true
		}
		down, ok := formatBandwidth(f.take("down_mbps"), true)
		if !ok {
			f.bad = true
		}
		obfs := f.child("obfs")
		if !formatHysteria(stream, f.text("password"), up, down, obfs.text("type"), obfs.text("password")) {
			f.bad = true
		}
		interval, maximum := formatSeconds(f, "hop_interval"), formatSeconds(f, "hop_interval_max")
		if hops != "" {
			if interval == 0 {
				interval = 30
			}
			if interval < 5 || maximum != 0 && maximum < interval {
				f.bad = true
			}
			text := strconv.Itoa(interval)
			if maximum > 0 {
				text += "-" + strconv.Itoa(maximum)
			}
			formatHysteriaHops(stream, hops, text)
		} else if interval != 0 || maximum != 0 {
			f.bad = true
		}
		if profile := f.text("bbr_profile"); profile != "" && profile != "standard" {
			f.bad = true
		}
		f.zero("brutal_debug")
		f.zero("disable_chrome_parrot")
	} else {
		transport := f.child("transport")
		if protocol != "vless" && protocol != "vmess" && protocol != "trojan" && len(transport.values) > 0 {
			f.bad = true
		}
		if !singBoxTransport(stream, transport) {
			f.bad = true
		}
	}
	if protocol == "http" {
		if headers := formatHeaders(f, "headers"); len(headers) > 0 {
			mapOf(outbound["settings"])["headers"] = headers
		}
		f.zero("path") // nonempty sing-box HTTP path has no Xray equivalent
	}
	if !f.valid() {
		return nil, name, errFormatUnsupported
	}
	outbound["streamSettings"] = stream
	return outbound, name, nil
}

func singBoxTLS(stream map[string]interface{}, f *formatFields, address string) bool {
	enabled, insecure := f.boolean("enabled"), f.boolean("insecure")
	engine := f.text("engine")
	if engine != "" && engine != "go" {
		return false
	}
	f.zero("disable_sni")
	serverName := formatDefault(f.text("server_name"), address)
	alpn := f.list("alpn")
	minimum, maximum := f.text("min_version"), f.text("max_version")
	for _, version := range []string{minimum, maximum} {
		if version != "" && version != "1.0" && version != "1.1" && version != "1.2" && version != "1.3" {
			return false
		}
	}
	ciphers := f.list("cipher_suites")
	f.zero("curve_preferences")
	certificate := f.list("certificate")
	f.zero("certificate_path")
	pins := f.list("certificate_sha256")
	f.zero("certificate_public_key_sha256")
	clientCertificate, clientKey := f.list("client_certificate"), f.list("client_key")
	for _, key := range []string{"client_certificate_path", "client_key_path", "fragment", "fragment_fallback_delay", "record_fragment", "spoof", "spoof_method", "kernel_tx", "kernel_rx", "handshake_timeout"} {
		f.zero(key)
	}
	ech := f.child("ech")
	if ech.boolean("enabled") {
		return false
	}
	for _, key := range []string{"config", "config_path", "query_server_name", "pq_signature_schemes_enabled", "dynamic_record_sizing_disabled"} {
		ech.zero(key)
	}
	utls := f.child("utls")
	useUTLS, fingerprint := utls.boolean("enabled"), utls.text("fingerprint")
	realityFields := f.child("reality")
	useReality := realityFields.boolean("enabled")
	publicKey, shortID := realityFields.text("public_key"), realityFields.text("short_id")
	settings, reality := map[string]interface{}{}, map[string]interface{}{}
	if enabled {
		settings["serverName"] = serverName
		if len(alpn) > 0 {
			settings["alpn"] = alpn
		}
		if minimum != "" {
			settings["minVersion"] = minimum
		}
		if maximum != "" {
			settings["maxVersion"] = maximum
		}
		if len(ciphers) > 0 {
			settings["cipherSuites"] = strings.Join(ciphers, ":")
		}
		if useUTLS {
			settings["fingerprint"] = formatDefault(fingerprint, "chrome")
		}
		if len(pins) > 0 {
			var converted []string
			for _, pin := range pins {
				decoded, err := base64.StdEncoding.DecodeString(pin)
				if err != nil || len(decoded) != 32 {
					return false
				}
				converted = append(converted, hex.EncodeToString(decoded))
			}
			settings["pinnedPeerCertSha256"] = strings.Join(converted, ",")
		}
		if len(certificate) > 0 {
			if !strings.Contains(strings.Join(certificate, "\n"), "-----BEGIN CERTIFICATE-----") {
				return false
			}
			settings["certificates"] = []interface{}{map[string]interface{}{"certificate": certificate, "usage": "verify"}}
			settings["disableSystemRoot"] = true
		}
		if len(clientCertificate) > 0 || len(clientKey) > 0 {
			if !strings.Contains(strings.Join(clientCertificate, "\n"), "-----BEGIN CERTIFICATE-----") || !strings.Contains(strings.Join(clientKey, "\n"), "PRIVATE KEY-----") {
				return false
			}
			certificates, _ := settings["certificates"].([]interface{})
			settings["certificates"] = append(certificates, map[string]interface{}{"certificate": clientCertificate, "key": clientKey, "usage": "encipherment"})
		}
		if useReality {
			if publicKey == "" || len(pins) > 0 || len(certificate) > 0 || len(clientCertificate) > 0 || len(alpn) > 0 || minimum != "" || maximum != "" || len(ciphers) > 0 {
				return false
			}
			reality = map[string]interface{}{"serverName": serverName, "publicKey": publicKey, "shortId": shortID, "fingerprint": formatDefault(fingerprint, "chrome")}
		}
	} else if useReality {
		return false
	}
	return formatApplyTLS(stream, enabled, settings, reality, insecure)
}

func singBoxTransport(stream map[string]interface{}, f *formatFields) bool {
	typeName := f.text("type")
	switch typeName {
	case "":
		return true
	case "ws":
		formatWebSocket(stream, f, "path", "max_early_data", "early_data_header_name", false)
	case "grpc":
		settings := map[string]interface{}{"serviceName": f.text("service_name")}
		if _, ok := f.values["idle_timeout"]; ok {
			settings["idle_timeout"] = formatSeconds(f, "idle_timeout")
		}
		if _, ok := f.values["ping_timeout"]; ok {
			settings["health_check_timeout"] = formatSeconds(f, "ping_timeout")
		}
		if _, ok := f.values["permit_without_stream"]; ok {
			settings["permit_without_stream"] = f.boolean("permit_without_stream")
		}
		stream["network"] = "grpc"
		stream["grpcSettings"] = settings
	case "httpupgrade":
		settings := map[string]interface{}{"path": formatDefault(f.text("path"), "/")}
		host := f.text("host")
		headers := formatHeaders(f, "headers")
		for key, value := range headers {
			if strings.EqualFold(key, "Host") {
				if host != "" && host != value {
					return false
				}
				host, _ = value.(string)
				delete(headers, key)
			}
		}
		if host != "" {
			settings["host"] = host
		}
		if len(headers) > 0 {
			settings["headers"] = headers
		}
		stream["network"] = "httpupgrade"
		stream["httpupgradeSettings"] = settings
	default:
		return false // sing-box HTTP and QUIC are not Xray XHTTP/QUIC
	}
	return true
}
