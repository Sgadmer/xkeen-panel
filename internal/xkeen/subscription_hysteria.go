package xkeen

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"xkeen-panel/internal/models"
)

func parseHysteria2(uri string) (*models.Server, error) {
	outbound, err := buildHysteria2Outbound(uri, "")
	if err != nil {
		return nil, err
	}
	address, port, proto, err := outboundMetadata(outbound)
	if err != nil {
		return nil, err
	}
	parsed, _ := url.Parse(uri)
	name := parsed.Fragment
	if name == "" {
		name = address
	}
	return &models.Server{Name: name, Address: address, Port: port, Protocol: proto, Latency: -1}, nil
}

func buildHysteria2Outbound(uri, tag string) (map[string]interface{}, error) {
	// Hysteria's official URI grammar permits a multi-port host, which
	// net/url rejects. Normalize only that port before standard URL parsing.
	hostHops := ""
	if schemeEnd := strings.Index(uri, "://"); schemeEnd >= 0 {
		authorityStart := schemeEnd + 3
		authorityEnd := len(uri)
		if end := strings.IndexAny(uri[authorityStart:], "/?#"); end >= 0 {
			authorityEnd = authorityStart + end
		}
		authority := uri[authorityStart:authorityEnd]
		if at := strings.LastIndexByte(authority, '@'); at >= 0 {
			if host, ports, err := net.SplitHostPort(authority[at+1:]); err == nil && strings.ContainsAny(ports, ",-") {
				normalized, first, ok := formatHopPorts([]string{ports})
				if !ok {
					return nil, uriOutboundError()
				}
				hostHops = normalized
				uri = uri[:authorityStart] + authority[:at+1] + net.JoinHostPort(host, strconv.Itoa(first)) + uri[authorityEnd:]
			}
		}
	}
	parsed, err := url.Parse(uri)
	if err != nil || (parsed.Scheme != "hy2" && parsed.Scheme != "hysteria2") || parsed.Hostname() == "" || parsed.User == nil ||
		strings.ContainsAny(parsed.Hostname(), " \t\r\n/?#@") || (parsed.Path != "" && parsed.Path != "/") {
		return nil, fmt.Errorf("некорректная Hysteria2-ссылка")
	}
	auth := parsed.User.Username()
	if password, present := parsed.User.Password(); present && password != "" {
		auth += ":" + password
	}
	if auth == "" {
		return nil, fmt.Errorf("в Hysteria2-ссылке отсутствует авторизация")
	}
	port := 443
	if value := parsed.Port(); value != "" {
		port, err = strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("некорректный порт Hysteria2")
		}
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return nil, uriOutboundError()
	}
	allowed := map[string]bool{}
	for _, key := range strings.Fields("sni peer fp fingerprint alpn insecure allowInsecure skip-cert-verify pinSHA256 pcs vcn ech obfs obfs-password obfs_password up down congestion mport ports hop-interval hopInterval fm") {
		allowed[key] = true
	}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 {
			return nil, uriOutboundError()
		}
	}
	sni, err := uriQueryAlias(query, "sni", "peer")
	if err != nil {
		return nil, err
	}
	if sni == "" {
		sni = parsed.Hostname()
	}
	fingerprint, err := uriQueryAlias(query, "fp", "fingerprint")
	if err != nil {
		return nil, err
	}
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	alpn := []string{"h3"}
	if value := query.Get("alpn"); value != "" {
		alpn = strings.Split(value, ",")
	}
	tls := map[string]interface{}{"serverName": sni, "fingerprint": fingerprint, "alpn": alpn}
	pin, err := uriQueryAlias(query, "pinSHA256", "pcs")
	if err != nil {
		return nil, err
	}
	if pin != "" {
		var normalized []string
		for _, value := range strings.Split(pin, ",") {
			value, ok := formatCertificatePin(value)
			if !ok {
				return nil, uriOutboundError()
			}
			normalized = append(normalized, value)
		}
		tls["pinnedPeerCertSha256"] = strings.Join(normalized, ",")
	}
	for _, key := range []string{"insecure", "allowInsecure", "skip-cert-verify"} {
		value, err := uriBool(query.Get(key))
		if err != nil {
			return nil, err
		}
		if value && pin == "" {
			return nil, fmt.Errorf("allowInsecure удалён из Xray; для Hysteria2 нужен проверяемый сертификат или его отпечаток")
		}
	}
	if value := query.Get("vcn"); value != "" {
		tls["verifyPeerCertByName"] = value
	}
	if value := query.Get("ech"); value != "" {
		tls["echConfigList"] = value
	}
	hysteria := map[string]interface{}{"version": 2, "auth": auth}
	stream := map[string]interface{}{"network": "hysteria", "security": "tls", "tlsSettings": tls,
		"hysteriaSettings": hysteria}
	if extra := query.Get("fm"); extra != "" {
		finalmask, err := uriJSONObject([]byte(extra))
		if err != nil {
			return nil, fmt.Errorf("некорректные параметры маскировки Hysteria2")
		}
		stream["finalmask"] = finalmask
	}
	if obfs := strings.ToLower(query.Get("obfs")); obfs != "" {
		if obfs != "salamander" {
			return nil, fmt.Errorf("неподдерживаемая маскировка Hysteria2")
		}
		password, err := uriQueryAlias(query, "obfs-password", "obfs_password")
		if err != nil {
			return nil, err
		}
		if password == "" {
			return nil, fmt.Errorf("для Salamander требуется пароль")
		}
		if query.Get("fm") != "" {
			return nil, uriOutboundError()
		}
		stream["finalmask"] = map[string]interface{}{"udp": []interface{}{
			map[string]interface{}{"type": "salamander", "settings": map[string]interface{}{"password": password}},
		}}
	} else if query.Get("obfs-password") != "" || query.Get("obfs_password") != "" {
		return nil, uriOutboundError()
	}
	up, upOK := formatBandwidth(query.Get("up"), true)
	down, downOK := formatBandwidth(query.Get("down"), true)
	if !upOK || !downOK {
		return nil, uriOutboundError()
	}
	congestion := strings.ToLower(query.Get("congestion"))
	switch congestion {
	case "", "reno", "bbr", "brutal", "force-brutal":
	default:
		return nil, uriOutboundError()
	}
	if up != "" || down != "" {
		if congestion == "" {
			congestion = "brutal"
		}
		if congestion != "brutal" && congestion != "force-brutal" {
			return nil, uriOutboundError()
		}
	}
	if congestion == "force-brutal" && up == "" {
		return nil, uriOutboundError()
	}
	if up != "" || down != "" || congestion != "" {
		finalmask := mapOf(stream["finalmask"])
		if finalmask == nil {
			finalmask = map[string]interface{}{}
			stream["finalmask"] = finalmask
		}
		quic := mapOf(finalmask["quicParams"])
		if quic == nil {
			if finalmask["quicParams"] != nil {
				return nil, uriOutboundError()
			}
			quic = map[string]interface{}{}
			finalmask["quicParams"] = quic
		}
		for key, value := range map[string]string{"brutalUp": up, "brutalDown": down, "congestion": congestion} {
			if value != "" {
				if previous, exists := quic[key]; exists && previous != value {
					return nil, uriOutboundError()
				}
				quic[key] = value
			}
		}
	}
	hops, err := uriQueryAlias(query, "mport", "ports")
	if err != nil {
		return nil, err
	}
	if hops != "" {
		var ok bool
		hops, _, ok = formatHopPorts([]string{hops})
		if !ok || (hostHops != "" && hops != hostHops) {
			return nil, uriOutboundError()
		}
	} else {
		hops = hostHops
	}
	interval, err := uriQueryAlias(query, "hop-interval", "hopInterval")
	if err != nil {
		return nil, err
	}
	if hops != "" {
		if interval == "" {
			interval = "30"
		}
		if duration, err := time.ParseDuration(interval); err == nil {
			if duration%time.Second != 0 {
				return nil, uriOutboundError()
			}
			interval = strconv.FormatInt(int64(duration/time.Second), 10)
		}
		for _, part := range strings.Split(interval, "-") {
			value, err := strconv.Atoi(part)
			if err != nil || value < 5 || value > 86400 {
				return nil, uriOutboundError()
			}
		}
		bounds := strings.Split(interval, "-")
		if len(bounds) > 2 {
			return nil, uriOutboundError()
		}
		if len(bounds) == 2 {
			a, _ := strconv.Atoi(bounds[0])
			b, _ := strconv.Atoi(bounds[1])
			if a > b {
				return nil, uriOutboundError()
			}
		}
		if existing := mapOf(mapOf(stream["finalmask"])["quicParams"])["udpHop"]; existing != nil {
			return nil, uriOutboundError()
		}
		formatHysteriaHops(stream, hops, interval)
	} else if interval != "" {
		return nil, uriOutboundError()
	}
	return map[string]interface{}{"tag": tag, "protocol": "hysteria",
		"settings":       map[string]interface{}{"version": 2, "address": parsed.Hostname(), "port": port},
		"streamSettings": stream}, nil
}

func boolQuery(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}
