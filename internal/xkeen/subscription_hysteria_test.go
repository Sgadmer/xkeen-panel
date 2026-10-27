package xkeen

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"xkeen-panel/internal/models"
)

func TestHysteriaURIUsesNativeXrayFormatAndPreservesAuthTLSObfs(t *testing.T) {
	uri := "hysteria2://user%3Aencoded:pass%40word@[2001:db8::1]:8443?sni=tls.invalid&obfs=salamander&obfs-password=mask%2Bpassword&alpn=h3%2Ch3-29&insecure=1&pinSHA256=" + strings.Repeat("ab", 32) + "#DE-HY2"
	servers, err := ParseSubscription(uri)
	if err != nil || len(servers) != 1 || servers[0].Protocol != "hysteria2" || servers[0].Port != 8443 {
		t.Fatalf("HY2 subscription rejected: %v", err)
	}
	outbound, err := BuildServerOutbound(servers[0], "selected-hy2", nil)
	if err != nil || outbound["protocol"] != "hysteria" {
		t.Fatalf("native HY2 build failed: %v", err)
	}
	stream := mapOf(outbound["streamSettings"])
	if stream["network"] != "hysteria" || mapOf(stream["hysteriaSettings"])["auth"] != "user:encoded:pass@word" || mapOf(stream["tlsSettings"])["allowInsecure"] != nil || mapOf(stream["tlsSettings"])["pinnedPeerCertSha256"] != strings.Repeat("ab", 32) {
		t.Fatal("native HY2 authentication or TLS options differ")
	}
	masks := mapOf(stream["finalmask"])["udp"].([]interface{})
	if mapOf(mapOf(masks[0])["settings"])["password"] != "mask+password" {
		t.Fatal("Salamander password differs")
	}
	if !CanBuildServer(servers[0]) {
		t.Fatal("HY2 cannot join the native pool")
	}
	raw, _ := json.Marshal(outbound)
	parsed, _, err := ParseSubscriptionDetailed(string(raw))
	if err != nil || len(parsed) != 1 || parsed[0].Protocol != "hysteria2" {
		t.Fatal("native HY2 JSON did not round trip")
	}
}

func TestHysteriaURIMapsBandwidthAndPortHopsForPinnedXray(t *testing.T) {
	for _, uri := range []string{
		"hy2://secret@example.invalid:443,5000-6000/?up=10&down=20Mbps&congestion=brutal&hop-interval=30s&obfs=salamander&obfs-password=mask",
		"hy2://secret@example.invalid:443/?mport=443,5000-6000&up=10&down=20Mbps&congestion=brutal&hopInterval=30&obfs=salamander&obfs-password=mask",
	} {
		outbound, err := buildHysteria2Outbound(uri, "")
		if err != nil {
			t.Fatal(err)
		}
		stream := mapOf(outbound["streamSettings"])
		legacy := mapOf(stream["hysteriaSettings"])
		quic := mapOf(mapOf(stream["finalmask"])["quicParams"])
		hop := mapOf(quic["udpHop"])
		if legacy["up"] != nil || legacy["down"] != nil || legacy["congestion"] != nil || quic["brutalUp"] != "10000000bps" || quic["brutalDown"] != "20000000bps" || quic["congestion"] != "brutal" || hop["ports"] != "443,5000-6000" || hop["interval"] != "30" {
			t.Fatal("HY2 URI emitted ignored legacy settings")
		}
		if len(mapOf(stream["finalmask"])["udp"].([]interface{})) != 1 {
			t.Fatal("port hopping lost Salamander")
		}
	}
	for _, uri := range []string{
		"hy2://SECRET_MARKER@example.invalid?insecure=true",
		"hy2://SECRET_MARKER@example.invalid?up=oops",
		"hy2://SECRET_MARKER@example.invalid?up=10&congestion=bbr",
		"hy2://SECRET_MARKER@example.invalid?mport=443,5000-6000&hopInterval=1s",
		"hy2://SECRET_MARKER@example.invalid?pinSHA256=invalid",
		"hy2://SECRET_MARKER@example.invalid?unknown-secret-option=1",
	} {
		_, err := buildHysteria2Outbound(uri, "")
		if err == nil || strings.Contains(err.Error(), "SECRET_MARKER") {
			t.Fatal("invalid HY2 settings accepted or exposed")
		}
	}
}

func TestHysteriaFinalMaskJSONPreservedAndErrorsAreSanitized(t *testing.T) {
	mask := `{"udp":[{"type":"salamander","settings":{"password":"synthetic"}}],"futureOption":true}`
	outbound, err := buildHysteria2Outbound("hy2://synthetic@example.invalid?fm="+url.QueryEscape(mask), "")
	if err != nil || mapOf(mapOf(outbound["streamSettings"])["finalmask"])["futureOption"] != true {
		t.Fatal("finalmask extension was lost")
	}
	for _, uri := range []string{"hy2://example.invalid", "hy2://SECRET_MARKER@example.invalid:65536", "hy2://SECRET_MARKER@example.invalid?obfs=salamander"} {
		_, err := BuildServerOutbound(models.Server{RawURI: uri}, "", nil)
		if err == nil || strings.Contains(err.Error(), "SECRET_MARKER") {
			t.Fatal("invalid HY2 was accepted or leaked credentials")
		}
	}
}
