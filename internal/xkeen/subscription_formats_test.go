package xkeen

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xkeen-panel/internal/models"
)

func formatFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "subscription-formats", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func formatFixtureServers(t *testing.T, name string) []models.Server {
	t.Helper()
	servers, report, err := ParseSubscriptionDetailed(formatFixture(t, name))
	if err != nil || len(servers) != 7 || report.Imported != 7 || report.SkippedUnsupported != 0 || report.SkippedComposite != 1 {
		t.Fatalf("fixture %s: servers=%d report=%+v err=%v", name, len(servers), report, err)
	}
	if !strings.Contains(strings.Join(report.Warnings, " "), "не переносятся") {
		t.Fatal("client policy limitation was not reported")
	}
	counts := map[string]int{}
	for _, server := range servers {
		counts[server.Protocol]++
		if !CanBuildServer(server) {
			t.Fatal("imported node cannot be built")
		}
		if !strings.HasPrefix(server.RawURI, "xray-json://") {
			t.Fatal("foreign endpoint identity must be opaque")
		}
	}
	for _, protocol := range []string{"vless", "vmess", "trojan", "shadowsocks", "socks", "http", "hysteria2"} {
		if counts[protocol] != 1 {
			t.Fatalf("protocol %s count=%d", protocol, counts[protocol])
		}
	}
	return servers
}

func formatOutbound(t *testing.T, servers []models.Server, protocol string) map[string]interface{} {
	t.Helper()
	for _, server := range servers {
		if server.Protocol == protocol {
			ob, err := BuildServerOutbound(server, "test-node", map[string]interface{}{"streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": 255}}})
			if err != nil {
				t.Fatal(err)
			}
			if mapOf(mapOf(ob["streamSettings"])["sockopt"])["mark"] != 255 {
				t.Fatal("local mark was not applied")
			}
			return ob
		}
	}
	t.Fatal("protocol not found")
	return nil
}

func TestForeignSubscriptionClashFixturePreservesTLSAndTransports(t *testing.T) {
	servers := formatFixtureServers(t, "clash.yaml")
	vless := formatOutbound(t, servers, "vless")
	stream := mapOf(vless["streamSettings"])
	if stream["security"] != "reality" || mapOf(stream["realitySettings"])["serverName"] != "reality.example.invalid" || mapOf(stream["realitySettings"])["shortId"] != "0102" {
		t.Fatal("REALITY mapping lost settings")
	}
	users := mapOf(mapOf(vless["settings"])["vnext"].([]interface{})[0])["users"].([]interface{})
	if mapOf(users[0])["flow"] != "xtls-rprx-vision-udp443" {
		t.Fatal("Mihomo Vision UDP443 semantics were not retained")
	}
	vmess := formatOutbound(t, servers, "vmess")
	ws := mapOf(mapOf(vmess["streamSettings"])["wsSettings"])
	if ws["path"] != "/synthetic?ed=1024" || ws["host"] != "cdn.example.invalid" || mapOf(ws["headers"])["X-Synthetic"] != "fixture" {
		t.Fatal("WebSocket settings were not retained")
	}
	grpc := mapOf(mapOf(formatOutbound(t, servers, "trojan")["streamSettings"])["grpcSettings"])
	if grpc["serviceName"] != "synthetic-service" || grpc["user_agent"] != "synthetic-client" {
		t.Fatal("gRPC service/user-agent lost")
	}
	hy := mapOf(formatOutbound(t, servers, "hysteria2")["streamSettings"])
	if mapOf(hy["hysteriaSettings"])["auth"] != "synthetic-hy2-password" {
		t.Fatal("Hysteria auth lost")
	}
	quic := mapOf(mapOf(hy["finalmask"])["quicParams"])
	if quic["brutalUp"] != "30000000bps" || quic["brutalDown"] != "100000000bps" || mapOf(quic["udpHop"])["ports"] != "5000-5002,8443" || mapOf(quic["udpHop"])["interval"] != "20" {
		t.Fatal("Hysteria bandwidth/port hopping mapping incorrect")
	}
	if mapOf(hy["hysteriaSettings"])["up"] != nil {
		t.Fatal("deprecated ignored Hysteria parameters emitted")
	}
}

func TestForeignSubscriptionSingBoxFixturePreservesSettings(t *testing.T) {
	servers := formatFixtureServers(t, "singbox.json")
	grpc := mapOf(mapOf(formatOutbound(t, servers, "vmess")["streamSettings"])["grpcSettings"])
	if grpc["serviceName"] != "synthetic-service" || jsonPort(grpc["idle_timeout"]) != 30 || jsonPort(grpc["health_check_timeout"]) != 15 || grpc["permit_without_stream"] != true {
		t.Fatal("sing-box gRPC mapping incorrect")
	}
	upgrade := mapOf(mapOf(formatOutbound(t, servers, "trojan")["streamSettings"])["httpupgradeSettings"])
	if upgrade["host"] != "cdn.example.invalid" || upgrade["path"] != "/synthetic" {
		t.Fatal("HTTPUpgrade mapping incorrect")
	}
	socks := mapOf(formatOutbound(t, servers, "socks")["settings"])["servers"].([]interface{})
	if mapOf(socks[0])["users"] != nil {
		t.Fatal("no-auth SOCKS acquired fake credentials")
	}
	http := mapOf(formatOutbound(t, servers, "http")["settings"])
	if mapOf(http["headers"])["X-Synthetic"] != "fixture" {
		t.Fatal("HTTP CONNECT custom header lost")
	}
}

func TestForeignSubscriptionJSONClashAndBase64YAML(t *testing.T) {
	for _, body := range []string{
		`{"proxies":[{"name":"Synthetic","type":"trojan","server":"example.invalid","port":443,"password":"synthetic"}]}`,
		"// sing-box JSONC\n" + `{"outbounds":[{"type":"socks","server":"example.invalid","server_port":1080}]}`,
		"  proxies:\n    - {name: indented, type: http, server: example.invalid, port: 8080}\n",
		base64.StdEncoding.EncodeToString([]byte(formatFixture(t, "clash.yaml"))),
	} {
		servers, _, err := ParseSubscriptionDetailed(body)
		if err != nil || len(servers) == 0 {
			t.Fatalf("foreign container/base64 rejected: %v", err)
		}
	}
}

func TestForeignSubscriptionRejectsUnknownAndNonEquivalentFields(t *testing.T) {
	base := `{"type":"vless","tag":"synthetic","server":"example.invalid","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001"}`
	var good map[string]interface{}
	_ = json.Unmarshal([]byte(base), &good)
	cases := []map[string]interface{}{
		{"future_secret_option": "SECRET_MARKER"},
		{"transport": map[string]interface{}{"type": "ws", "path": "/", "future_key": "SECRET_MARKER"}},
		{"transport": map[string]interface{}{"type": "ws", "max_early_data": 1024}}, // sing-box defaults to incompatible path early data
		{"transport": map[string]interface{}{"type": "http", "path": "/"}},
		{"transport": map[string]interface{}{"type": "quic"}},
		{"tls": map[string]interface{}{"enabled": true, "insecure": true}},
		{"tls": map[string]interface{}{"enabled": true, "certificate_public_key_sha256": []string{"SECRET_MARKER"}}},
		{"tls": map[string]interface{}{"enabled": true, "certificate_path": "/SECRET_MARKER"}},
		{"tls": map[string]interface{}{"enabled": true, "ech": map[string]interface{}{"enabled": true, "config": []string{"SECRET_MARKER"}}}},
	}
	for index, changes := range cases {
		bad := map[string]interface{}{}
		for key, value := range good {
			bad[key] = value
		}
		for key, value := range changes {
			bad[key] = value
		}
		raw, _ := json.Marshal([]interface{}{good, bad})
		servers, report, err := ParseSubscriptionDetailed(string(raw))
		if err != nil || len(servers) != 1 || report.SkippedUnsupported != 1 {
			t.Fatalf("case %d silently ignored unsupported option: count=%d report=%+v err=%v", index, len(servers), report, err)
		}
		if strings.Contains(strings.Join(report.Warnings, " "), "SECRET_MARKER") {
			t.Fatal("unsupported parameters leaked")
		}
	}
}

func TestForeignSubscriptionClashUnsupportedCountsAndNoGroupsFlattened(t *testing.T) {
	body := `proxies:
  - {name: good, type: trojan, server: good.invalid, port: 443, password: synthetic}
  - {name: chain, type: trojan, server: chain.invalid, port: 443, password: synthetic, dialer-proxy: good}
  - {name: unknown, type: anytls, server: future.invalid, port: 443, password: SECRET_MARKER}
  - {name: insecure, type: trojan, server: insecure.invalid, port: 443, password: synthetic, skip-cert-verify: true}
  - {name: plugin, type: ss, server: plugin.invalid, port: 443, cipher: aes-128-gcm, password: synthetic, plugin: obfs}
proxy-groups:
  - {name: SECRET_MARKER, type: relay, proxies: [good, chain]}
proxy-providers:
  private: {type: http, url: https://SECRET_MARKER.invalid/sub}
`
	servers, report, err := ParseSubscriptionDetailed(body)
	if err != nil || len(servers) != 1 || report.SkippedComposite != 2 || report.SkippedUnsupported != 4 {
		t.Fatalf("counts=%d report=%+v err=%v", len(servers), report, err)
	}
	if strings.Contains(strings.Join(report.Warnings, " "), "SECRET_MARKER") {
		t.Fatal("source names/URL leaked into warnings")
	}
}

func TestForeignSubscriptionCertificatePinsAreNotSPKIAndPreserveMultiplePins(t *testing.T) {
	first := base64.StdEncoding.EncodeToString(make([]byte, 32))
	second := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	body := `{"type":"trojan","server":"example.invalid","server_port":443,"password":"synthetic","tls":{"enabled":true,"server_name":"tls.invalid","certificate_sha256":["` + first + `","` + second + `"]}}`
	servers, _, err := ParseSubscriptionDetailed(body)
	if err != nil || len(servers) != 1 {
		t.Fatal("valid full-certificate pins rejected", err)
	}
	outbound, err := BuildServerOutbound(servers[0], "synthetic", nil)
	if err != nil {
		t.Fatal(err)
	}
	pins, _ := mapOf(mapOf(outbound["streamSettings"])["tlsSettings"])["pinnedPeerCertSha256"].(string)
	if len(strings.Split(pins, ",")) != 2 || len(pins) != 129 {
		t.Fatal("certificate pins collapsed or changed kind")
	}
}

func TestForeignSubscriptionMalformedYAMLDoesNotEchoPayload(t *testing.T) {
	for _, body := range []string{"proxies: [SECRET_MARKER", "proxies: []\n---\nproxies: [SECRET_MARKER]", "proxies:\n  - {type: trojan, type: SECRET_MARKER}"} {
		_, report, err := ParseSubscriptionDetailed(body)
		if err == nil || strings.Contains(err.Error(), "SECRET_MARKER") || strings.Contains(strings.Join(report.Warnings, " "), "SECRET_MARKER") {
			t.Fatal("malformed YAML was accepted or exposed")
		}
	}
}

func TestForeignSubscriptionClashRawHTTPXHTTPAndWebSocketDefaults(t *testing.T) {
	body := `proxies:
  - name: raw-http
    type: vmess
    server: raw.invalid
    port: 80
    uuid: 00000000-0000-4000-8000-000000000001
    network: http
    http-opts: {method: GET, path: [/one, /two], headers: {Host: [front.invalid], X-Test: [one, two]}}
  - name: xhttp
    type: vless
    server: xhttp.invalid
    port: 443
    uuid: 00000000-0000-4000-8000-000000000002
    tls: true
    network: xhttp
    xhttp-opts:
      path: /synthetic
      host: cdn.invalid
      mode: stream-up
      no-grpc-header: true
      sc-max-each-post-bytes: 1000000
      reuse-settings: {max-concurrency: 16-32, h-keep-alive-period: 20}
  - name: ws-host-sni
    type: trojan
    server: origin.invalid
    port: 443
    password: synthetic
    network: ws
    ws-opts: {path: /socket, headers: {Host: cdn.invalid}}
`
	servers, report, err := ParseSubscriptionDetailed(body)
	if err != nil || len(servers) != 3 || report.SkippedUnsupported != 0 {
		t.Fatalf("transport cases=%d report=%+v err=%v", len(servers), report, err)
	}
	rawHTTP := mapOf(mapOf(formatOutbound(t, servers, "vmess")["streamSettings"])["tcpSettings"])
	if mapOf(rawHTTP["header"])["type"] != "http" {
		t.Fatal("raw HTTP became removed H2 transport")
	}
	xhttp := mapOf(mapOf(formatOutbound(t, servers, "vless")["streamSettings"])["xhttpSettings"])
	if xhttp["mode"] != "stream-up" || xhttp["noGRPCHeader"] != true || xhttp["scMaxEachPostBytes"] != "1000000" || mapOf(xhttp["xmux"])["maxConcurrency"] != "16-32" {
		t.Fatal("XHTTP options dropped")
	}
	tls := mapOf(mapOf(formatOutbound(t, servers, "trojan")["streamSettings"])["tlsSettings"])
	if tls["serverName"] != "cdn.invalid" {
		t.Fatal("Clash WebSocket Host was not the implicit TLS SNI")
	}
	alpn := tls["alpn"].([]interface{})
	if len(alpn) != 1 || alpn[0] != "http/1.1" {
		t.Fatal("WebSocket HTTP/1.1 ALPN lost")
	}
}

func TestForeignSubscriptionMihomoPinUsesSupportedTrustInsteadOfInsecure(t *testing.T) {
	pin := strings.Repeat("AB:", 31) + "AB"
	body := `proxies:
  - name: pinned
    type: trojan
    server: pinned.invalid
    port: 443
    password: synthetic
    skip-cert-verify: true
    fingerprint: "` + pin + `"
    name-cert-verify: verified.invalid
`
	servers, _, err := ParseSubscriptionDetailed(body)
	if err != nil || len(servers) != 1 {
		t.Fatal("supported certificate pin rejected", err)
	}
	tls := mapOf(mapOf(formatOutbound(t, servers, "trojan")["streamSettings"])["tlsSettings"])
	if tls["pinnedPeerCertSha256"] != strings.Repeat("ab", 32) || tls["verifyPeerCertByName"] != "verified.invalid" || tls["allowInsecure"] != nil {
		t.Fatal("TLS trust changed or obsolete insecure flag emitted")
	}
}

func TestForeignSubscriptionYAMLAnchorsAndExpansionBounds(t *testing.T) {
	body := `defaults: &endpoint
  type: trojan
  server: example.invalid
  port: 443
  password: synthetic
proxies:
  - <<: *endpoint
    name: First
  - <<: *endpoint
    name: SameEndpoint
`
	servers, _, err := ParseSubscriptionDetailed(body)
	if err != nil || len(servers) != 1 {
		t.Fatal("ordinary YAML merge anchor was rejected or endpoint was not deduplicated", err)
	}
	for _, invalid := range []string{"proxies: &cycle [*cycle]", "proxies: []\nmetadata: " + strings.Repeat("[", 80) + "SECRET_MARKER" + strings.Repeat("]", 80)} {
		_, _, err := ParseSubscriptionDetailed(invalid)
		if err == nil || strings.Contains(err.Error(), "SECRET_MARKER") {
			t.Fatal("cyclic/deep YAML accepted or leaked")
		}
	}
}
