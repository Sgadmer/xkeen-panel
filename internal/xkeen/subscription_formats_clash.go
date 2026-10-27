package xkeen

import (
	"strconv"
	"strings"
)

// Field names follow MetaCubeX/Meta-Docs config/proxies. Only endpoint
// parameters are translated; the parent document's policies stay on the router.
func convertClashEndpoint(object map[string]interface{}) (map[string]interface{}, string, error) {
	f := newFormatFields(object)
	name, protocol := f.text("name"), strings.ToLower(f.text("type"))
	if f.text("dialer-proxy") != "" {
		return nil, name, errFormatComposite
	}
	address, port := f.text("server"), f.integer("port")
	if name == "" {
		name = address
	}
	f.text("icon")
	f.text("benchmark-url")
	f.boolean("udp") // capability/policy: explicitly covered by import warning
	tfo := f.boolean("tfo")
	f.zero("mptcp")
	f.zero("interface-name")
	f.zero("routing-mark")
	ipVersion := f.text("ip-version")
	if ipVersion != "" && ipVersion != "dual" {
		f.bad = true
	}
	smux := f.child("smux")
	if smux.boolean("enabled") {
		f.bad = true
	}
	var user map[string]interface{}
	switch protocol {
	case "vless":
		flow := f.text("flow")
		if flow == "xtls-rprx-vision" {
			flow += "-udp443"
		} else if flow != "" {
			f.bad = true
		}
		user = map[string]interface{}{"id": f.text("uuid"), "encryption": formatDefault(f.text("encryption"), "none")}
		if flow != "" {
			user["flow"] = flow
		}
		packet := f.text("packet-encoding")
		if packet != "" && packet != "xudp" {
			f.bad = true
		}
	case "vmess":
		security := formatDefault(f.text("cipher"), "auto")
		if !formatVMessSecurity(security) {
			f.bad = true
		}
		if f.integer("alterId") != 0 {
			f.bad = true
		}
		f.zero("global-padding")
		packet := f.text("packet-encoding")
		if packet != "" && packet != "xudp" {
			f.bad = true
		}
		user = map[string]interface{}{"id": f.text("uuid"), "security": security}
		if f.boolean("authenticated-length") {
			user["experiments"] = "AuthenticatedLength"
		}
	case "trojan":
		user = map[string]interface{}{"password": f.text("password")}
	case "ss", "shadowsocks":
		protocol = "shadowsocks"
		method := f.text("cipher")
		if !formatSSMethod(method) {
			f.bad = true
		}
		user = map[string]interface{}{"method": method, "password": f.text("password")}
		f.zero("plugin")
		f.zero("plugin-opts")
		f.zero("udp-over-tcp")
		version := f.integer("udp-over-tcp-version")
		if version != 0 && version != 1 && version != 2 {
			f.bad = true
		}
	case "socks5", "socks":
		protocol = "socks"
		user = map[string]interface{}{"user": f.text("username"), "pass": f.text("password")}
	case "http":
		user = map[string]interface{}{"user": f.text("username"), "pass": f.text("password")}
	case "hysteria2", "hy2":
		protocol = "hysteria"
	default:
		return nil, name, errFormatUnsupported
	}
	var hops string
	if protocol == "hysteria" {
		var first int
		var ok bool
		ports := f.text("ports")
		if ports != "" {
			hops, first, ok = formatHopPorts([]string{ports})
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
	if !clashTLS(stream, f, protocol, address) {
		f.bad = true
	}
	if protocol == "hysteria" {
		up, ok := formatBandwidth(f.take("up"), true)
		if !ok {
			f.bad = true
		}
		down, ok := formatBandwidth(f.take("down"), true)
		if !ok {
			f.bad = true
		}
		if !formatHysteria(stream, f.text("password"), up, down, f.text("obfs"), f.text("obfs-password")) {
			f.bad = true
		}
		interval := f.take("hop-interval")
		if hops != "" {
			value, ok := formatClashHopInterval(interval)
			if !ok {
				f.bad = true
			}
			formatHysteriaHops(stream, hops, value)
		} else if interval != nil {
			f.bad = true
		}
		// These explicit default values are inactive in Mihomo. Non-default
		// QUIC tuning, gecko and realm remain unsupported, not silently lost.
		if profile := f.text("bbr-profile"); profile != "" && profile != "standard" {
			f.bad = true
		}
	} else {
		network, _ := f.values["network"].(string)
		if protocol == "vmess" && network == "xhttp" {
			f.bad = true
		}
		if protocol == "trojan" && network != "" && network != "tcp" && network != "ws" && network != "grpc" {
			f.bad = true
		}
		if protocol != "vless" && protocol != "vmess" && protocol != "trojan" && network != "" && network != "tcp" {
			f.bad = true
		}
		if !clashTransport(stream, f) {
			f.bad = true
		}
	}
	if protocol == "http" {
		if headers := formatHeaders(f, "headers"); len(headers) > 0 {
			mapOf(outbound["settings"])["headers"] = headers
		}
	}
	if !f.valid() {
		return nil, name, errFormatUnsupported
	}
	outbound["streamSettings"] = stream
	return outbound, name, nil
}

func clashTLS(stream map[string]interface{}, f *formatFields, protocol, address string) bool {
	_, specified := f.values["tls"]
	enabled := f.boolean("tls")
	if !specified && (protocol == "trojan" || protocol == "hysteria") {
		enabled = true
	}
	if !enabled && (protocol == "trojan" || protocol == "hysteria") {
		return false
	}
	sni, servername := f.text("sni"), f.text("servername")
	if sni != "" && servername != "" && sni != servername {
		return false
	}
	serverName := formatDefault(servername, formatDefault(sni, address))
	// Mihomo WS TLS uses Host as SNI when no explicit servername was set,
	// and its WebSocket client always negotiates HTTP/1.1.
	websocket := f.values["network"] == "ws"
	if websocket && servername == "" && sni == "" {
		options, _ := f.values["ws-opts"].(map[string]interface{})
		headers, _ := options["headers"].(map[string]interface{})
		for key, raw := range headers {
			if strings.EqualFold(key, "Host") {
				if host, ok := raw.(string); ok && host != "" {
					serverName = host
				}
			}
		}
	}
	insecure := f.boolean("skip-cert-verify")
	alpn := f.list("alpn")
	if websocket {
		alpn = []string{"http/1.1"}
	}
	fingerprint := f.text("client-fingerprint")
	pin := f.text("fingerprint")
	verifyName := f.text("name-cert-verify")
	realityFields := f.child("reality-opts")
	publicKey, shortID := realityFields.text("public-key"), realityFields.text("short-id")
	if realityFields.boolean("support-x25519mlkem768") {
		f.bad = true
	}
	reality := map[string]interface{}{}
	if publicKey != "" {
		enabled = true
		reality = map[string]interface{}{"serverName": serverName, "publicKey": publicKey, "shortId": shortID, "fingerprint": formatDefault(fingerprint, "chrome")}
		if pin != "" || verifyName != "" || len(alpn) > 0 {
			f.bad = true
		}
	} else if shortID != "" {
		f.bad = true
	}
	settings := map[string]interface{}{}
	if enabled {
		settings["serverName"] = serverName
		if len(alpn) > 0 {
			settings["alpn"] = alpn
		}
		if fingerprint != "" {
			settings["fingerprint"] = fingerprint
		}
		if pin != "" {
			value, ok := formatCertificatePin(pin)
			if !ok {
				return false
			}
			settings["pinnedPeerCertSha256"] = value
		}
		if verifyName != "" {
			settings["verifyPeerCertByName"] = verifyName
		}
	}
	return formatApplyTLS(stream, enabled, settings, reality, insecure)
}

func clashTransport(stream map[string]interface{}, f *formatFields) bool {
	network := formatDefault(f.text("network"), "tcp")
	switch network {
	case "tcp", "raw":
		stream["network"] = "tcp"
	case "ws":
		options := f.child("ws-opts")
		upgrade := options.boolean("v2ray-http-upgrade")
		if options.boolean("v2ray-http-upgrade-fast-open") {
			return false
		}
		formatWebSocket(stream, options, "path", "max-early-data", "early-data-header-name", upgrade)
	case "grpc":
		options := f.child("grpc-opts")
		settings := map[string]interface{}{"serviceName": options.text("grpc-service-name")}
		if userAgent := options.text("grpc-user-agent"); userAgent != "" {
			settings["user_agent"] = userAgent
		}
		if options.integer("ping-interval") != 0 {
			return false
		}
		connections := options.integer("max-connections")
		if connections != 0 && connections != 1 {
			return false
		}
		options.zero("min-streams")
		options.zero("max-streams")
		stream["network"] = "grpc"
		stream["grpcSettings"] = settings
	case "http":
		// Mihomo's `http` option is raw TCP HTTP camouflage, not H2.
		options := f.child("http-opts")
		request := map[string]interface{}{}
		if method := options.text("method"); method != "" {
			request["method"] = method
		}
		if paths := options.list("path"); len(paths) > 0 {
			request["path"] = paths
		}
		if raw := options.take("headers"); raw != nil {
			headers, ok := raw.(map[string]interface{})
			if !ok {
				return false
			}
			for name, value := range headers {
				switch item := value.(type) {
				case string:
					headers[name] = []string{item}
				case []interface{}:
					for _, v := range item {
						if _, ok := v.(string); !ok {
							return false
						}
					}
				default:
					return false
				}
			}
			request["headers"] = headers
		}
		stream["network"] = "tcp"
		stream["tcpSettings"] = map[string]interface{}{"header": map[string]interface{}{"type": "http", "request": request}}
	case "xhttp":
		options := f.child("xhttp-opts")
		settings := map[string]interface{}{}
		for _, key := range []string{"path", "host", "mode"} {
			if value := options.text(key); value != "" {
				settings[key] = value
			}
		}
		if mode, _ := settings["mode"].(string); mode != "" && mode != "auto" && mode != "stream-one" && mode != "stream-up" && mode != "packet-up" {
			return false
		}
		if headers := formatHeaders(options, "headers"); len(headers) > 0 {
			settings["headers"] = headers
		}
		for _, pair := range [][2]string{{"no-grpc-header", "noGRPCHeader"}, {"x-padding-obfs-mode", "xPaddingObfsMode"}} {
			if _, ok := options.values[pair[0]]; ok {
				settings[pair[1]] = options.boolean(pair[0])
			}
		}
		for _, pair := range [][2]string{{"x-padding-bytes", "xPaddingBytes"}, {"x-padding-key", "xPaddingKey"}, {"x-padding-header", "xPaddingHeader"}, {"x-padding-placement", "xPaddingPlacement"}, {"x-padding-method", "xPaddingMethod"}, {"uplink-http-method", "uplinkHTTPMethod"}, {"session-placement", "sessionPlacement"}, {"session-key", "sessionKey"}, {"seq-placement", "seqPlacement"}, {"seq-key", "seqKey"}, {"uplink-data-placement", "uplinkDataPlacement"}, {"uplink-data-key", "uplinkDataKey"}, {"uplink-chunk-size", "uplinkChunkSize"}, {"sc-max-each-post-bytes", "scMaxEachPostBytes"}, {"sc-min-posts-interval-ms", "scMinPostsIntervalMs"}} {
			if value := options.text(pair[0]); value != "" {
				settings[pair[1]] = value
			}
		}
		if _, exists := options.values["download-settings"]; exists {
			return false
		}
		reuse := options.child("reuse-settings")
		xmux := map[string]interface{}{}
		for _, pair := range [][2]string{{"max-concurrency", "maxConcurrency"}, {"max-connections", "maxConnections"}, {"c-max-reuse-times", "cMaxReuseTimes"}, {"h-max-request-times", "hMaxRequestTimes"}, {"h-max-reusable-secs", "hMaxReusableSecs"}} {
			if value := reuse.text(pair[0]); value != "" {
				xmux[pair[1]] = value
			}
		}
		if _, exists := reuse.values["h-keep-alive-period"]; exists {
			xmux["hKeepAlivePeriod"] = reuse.integer("h-keep-alive-period")
		}
		if len(xmux) > 0 {
			settings["xmux"] = xmux
		}
		stream["network"] = "xhttp"
		stream["xhttpSettings"] = settings
	default:
		// Legacy H2/QUIC have been removed by Xray; replacing them with
		// XHTTP would change the wire protocol rather than fix the import.
		return false
	}
	return true
}

func formatClashHopInterval(value interface{}) (string, bool) {
	if value == nil {
		return "30", true
	}
	f := newFormatFields(map[string]interface{}{"interval": value})
	text := f.text("interval")
	if text == "0" || text == "" {
		return "30", f.valid()
	}
	parts := strings.Split(text, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return "", false
	}
	previous := 0
	for _, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 5 || number < previous {
			return "", false
		}
		previous = number
	}
	return text, f.valid()
}
