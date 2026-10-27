package xkeen

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"xkeen-panel/internal/models"
)

const uriTestID = "11111111-2222-3333-4444-555555555555"

func vmessTestLink(t *testing.T, config map[string]interface{}) string {
	t.Helper()
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return "vmess://" + base64.RawURLEncoding.EncodeToString(data)
}

func TestURIOutboundVMessJSONPreservesWSTLSAndAuth(t *testing.T) {
	raw := vmessTestLink(t, map[string]interface{}{"v": "2", "add": "2001:db8::1", "port": 8443, "id": uriTestID, "aid": 0,
		"scy": "aes-128-gcm", "net": "ws", "type": "none", "host": "cdn.example", "path": "/socket?ed=2048",
		"tls": "tls", "sni": "origin.example", "alpn": "h2,http/1.1", "fp": "chrome", "ps": "Example", "vcn": "origin.example", "pcs": strings.Repeat("a", 64)})
	outbound, err := BuildServerOutbound(models.Server{RawURI: raw}, "local-node", map[string]interface{}{"streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": 255}}})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := mapOf(mapOf(outbound["settings"])["vnext"].([]interface{})[0])
	user := mapOf(endpoint["users"].([]interface{})[0])
	stream := mapOf(outbound["streamSettings"])
	tls := mapOf(stream["tlsSettings"])
	if endpoint["address"] != "2001:db8::1" || endpoint["port"] != 8443 || user["id"] != uriTestID || user["security"] != "aes-128-gcm" || outbound["tag"] != "local-node" {
		t.Fatal("VMess endpoint or authentication changed")
	}
	if !reflect.DeepEqual(mapOf(stream["wsSettings"]), map[string]interface{}{"host": "cdn.example", "path": "/socket?ed=2048"}) ||
		tls["serverName"] != "origin.example" || tls["fingerprint"] != "chrome" || tls["verifyPeerCertByName"] != "origin.example" || tls["pinnedPeerCertSha256"] != strings.Repeat("a", 64) ||
		!reflect.DeepEqual(tls["alpn"], []string{"h2", "http/1.1"}) || mapOf(stream["sockopt"])["mark"] != 255 {
		t.Fatal("VMess transport/security/policy parameters were lost")
	}
	server, err := parseBuiltURIServer(raw)
	if err != nil || server.Name != "Example" || server.Protocol != "vmess" {
		t.Fatal("VMess metadata no longer matches its builder")
	}
}

func TestURIOutboundTrojanAndVMessGRPC(t *testing.T) {
	for _, scheme := range []string{"trojan", "vmess"} {
		t.Run(scheme, func(t *testing.T) {
			credential := "p%40ss%3Aword"
			if scheme == "vmess" {
				credential = uriTestID
			}
			raw := scheme + "://" + credential + "@example.invalid:443?security=tls&type=grpc&serviceName=svc%2Fone&authority=grpc.example&mode=multi&sni=tls.example&fp=firefox"
			outbound, err := BuildServerOutbound(models.Server{RawURI: raw}, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			stream := mapOf(outbound["streamSettings"])
			grpc := mapOf(stream["grpcSettings"])
			if grpc["serviceName"] != "svc/one" || grpc["authority"] != "grpc.example" || grpc["multiMode"] != true || mapOf(stream["tlsSettings"])["serverName"] != "tls.example" {
				t.Fatal("gRPC/TLS values lost")
			}
			if scheme == "trojan" {
				endpoint := mapOf(mapOf(outbound["settings"])["servers"].([]interface{})[0])
				if endpoint["password"] != "p@ss:word" {
					t.Fatal("Trojan password was reinterpreted")
				}
			}
		})
	}
}

func TestURIOutboundXHTTPExtraKeepsExactNumbersAndDownloadSettings(t *testing.T) {
	extra := `{"xmux":{"cMaxReuseTimes":9007199254740993},"downloadSettings":{"address":"download.example","port":443,"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"download.example"}}}}`
	raw := "trojan://pass@example.invalid:443?type=xhttp&security=tls&host=upload.example&path=%2Fup&mode=stream-up&extra=" + url.QueryEscape(extra)
	outbound, err := BuildServerOutbound(models.Server{RawURI: raw}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	xhttp := mapOf(mapOf(outbound["streamSettings"])["xhttpSettings"])
	if mapOf(xhttp["xmux"])["cMaxReuseTimes"] != json.Number("9007199254740993") || mapOf(xhttp["downloadSettings"])["address"] != "download.example" || xhttp["host"] != "upload.example" || xhttp["path"] != "/up" || xhttp["mode"] != "stream-up" {
		t.Fatal("XHTTP settings were reduced or rounded")
	}
}

func TestURIOutboundShadowsocksSIP002AndLegacyCredentials(t *testing.T) {
	password := "p@ss:#%? word"
	credentials := "aes-256-gcm:" + password
	for name, raw := range map[string]string{
		"sip002":          "ss://" + base64.RawURLEncoding.EncodeToString([]byte(credentials)) + "@[2001:db8::2]:8388#Example",
		"plain":           "ss://" + url.UserPassword("aes-256-gcm", password).String() + "@example.invalid:8388/#Example",
		"legacy":          "ss://" + base64.StdEncoding.EncodeToString([]byte(credentials+"@example.invalid:8388")) + "#Example",
		"standard-base64": "ss://" + base64.StdEncoding.EncodeToString([]byte(credentials)) + "@example.invalid:8388#Example",
	} {
		t.Run(name, func(t *testing.T) {
			outbound, err := BuildServerOutbound(models.Server{RawURI: raw}, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := mapOf(mapOf(outbound["settings"])["servers"].([]interface{})[0])
			if endpoint["password"] != password || endpoint["method"] != "aes-256-gcm" || endpoint["port"] != 8388 {
				t.Fatal("Shadowsocks credentials did not round-trip")
			}
		})
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	raw := "ss://" + url.UserPassword("2022-blake3-aes-128-gcm", key).String() + "@example.invalid:8388"
	if _, err := BuildServerOutbound(models.Server{RawURI: raw}, "", nil); err != nil {
		t.Fatal("valid SIP022 plain credentials rejected")
	}
}

func TestURIOutboundUnsupportedAndMalformedFailWithoutSecrets(t *testing.T) {
	for _, raw := range []string{
		"trojan://private-secret@example.invalid:443?type=quic",
		"trojan://private-secret@example.invalid:443?type=ws&allowInsecure=true",
		"trojan://private-secret@example.invalid:443?type=grpc&serviceName=a&path=b",
		"trojan://private-secret@example.invalid:443?security=reality",
		"trojan://private-secret@example.invalid:443?security=tls&unknown-private-secret=1",
		"trojan://private-secret@example.invalid:443?type=xhttp&extra=" + url.QueryEscape(`{"downloadSettings":{"sockopt":{"dialerProxy":"private-secret"}}}`),
		"trojan://private-secret@example.invalid:70000",
		"trojan://@example.invalid:443",
		"vmess://private-secret@example.invalid:443?encryption=invalid",
		"vmess://%%%%private-secret",
		vmessTestLink(t, map[string]interface{}{"add": "example.invalid", "port": 443, "id": uriTestID, "aid": 64}),
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:private-secret")) + "@example.invalid:8388?plugin=v2ray-plugin",
		"ss://" + url.UserPassword("rc4-md5", "private-secret").String() + "@example.invalid:8388",
		"ss://" + url.UserPassword("2022-blake3-aes-128-gcm", "private-secret").String() + "@example.invalid:8388",
	} {
		_, err := BuildServerOutbound(models.Server{RawURI: raw}, "", nil)
		if err == nil || strings.Contains(err.Error(), "private-secret") || strings.Contains(err.Error(), "example.invalid") {
			t.Fatal("unsupported URI accepted or error exposed a credential")
		}
	}
}

func TestURIOutboundSubscriptionParsersUseSupportedBuilders(t *testing.T) {
	raw := "vmess://" + uriTestID + "@example.invalid:443?type=ws&security=tls&path=%2Fws#VMess\n" +
		"trojan://password@example.invalid:443?type=grpc&serviceName=svc#Trojan\n" +
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:password")) + "@example.invalid:8388#SS"
	servers, err := ParseSubscription(raw)
	if err != nil || len(servers) != 3 {
		t.Fatal("supported URI formats did not reach the catalog")
	}
	for _, server := range servers {
		if !CanBuildServer(server) {
			t.Fatal("catalog contains an unbuildable URI")
		}
	}
}

func TestRawHTTPAndSOCKSEndpointsAllowAnonymousAuthentication(t *testing.T) {
	for _, protocol := range []string{"http", "socks"} {
		for _, flat := range []bool{true, false} {
			endpoint := map[string]interface{}{"address": "example.invalid", "port": 1080}
			settings := endpoint
			if !flat {
				settings = map[string]interface{}{"servers": []interface{}{endpoint}}
			}
			raw, _ := json.Marshal(map[string]interface{}{"protocol": protocol, "settings": settings})
			if _, err := BuildServerOutbound(models.Server{RawOutbound: raw}, "", nil); err != nil {
				t.Fatal("anonymous native HTTP/SOCKS outbound rejected")
			}
		}
	}
}
