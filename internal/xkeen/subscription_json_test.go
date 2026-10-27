package xkeen

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const rawEndpointFixture = `{
 "tag":"provider-name", "protocol":"vless",
 "settings":{"vnext":[{"address":"example.invalid","port":443,"users":[{"id":"synthetic-id","flow":"xtls-rprx-vision","encryption":"none"}]}]},
 "streamSettings":{"network":"xhttp","security":"reality",
  "realitySettings":{"serverName":"tls.invalid","publicKey":"synthetic-public-key","shortId":"0102","mldsa65Verify":"synthetic-mldsa"},
  "xhttpSettings":{"mode":"stream-up","path":"/synthetic","extra":{"xmux":{"maxConcurrency":"16-32"},"downloadSettings":{"address":"download.invalid","port":443}}},
  "sockopt":{"mark":123,"tcpFastOpen":true}},
 "newFutureField":{"largeInteger":9007199254740993,"nested":[{"enabled":true}]}
}`

func TestJSONSubscriptionNativeProfilePreservesEveryOutboundField(t *testing.T) {
	profile := `{"remarks":"🇩🇪 Germany Full","inbounds":[{"protocol":"socks"}],"routing":{"rules":[]},"outbounds":[` + rawEndpointFixture + `,{"tag":"direct","protocol":"freedom"}]}`
	servers, report, err := ParseSubscriptionDetailed(profile)
	if err != nil || len(servers) != 1 || report.Imported != 1 {
		t.Fatalf("import = %d, report = %+v, error = %v", len(servers), report, err)
	}
	server := servers[0]
	if server.Name != "🇩🇪 Germany Full" || server.Protocol != "vless" || server.Address != "example.invalid" || server.Country != "DE" {
		t.Fatal("profile metadata was not retained")
	}
	if !strings.HasPrefix(server.RawURI, "xray-json://") || strings.Contains(server.RawURI, "synthetic-id") || len(server.RawURI) != len("xray-json://")+64 {
		t.Fatal("JSON identity is not an opaque digest")
	}
	source, _ := decodeServerOutbound(json.RawMessage(rawEndpointFixture))
	preserved, _ := decodeServerOutbound(server.RawOutbound)
	sourceJSON, _ := json.Marshal(source)
	preservedJSON, _ := json.Marshal(preserved)
	if string(sourceJSON) != string(preservedJSON) {
		t.Fatal("native outbound fields were changed during import")
	}
}

func TestJSONSubscriptionImports24EndpointsAndReportsTwoComposites(t *testing.T) {
	var profiles []interface{}
	for i := 0; i < 24; i++ {
		var outbound map[string]interface{}
		if i < 21 {
			outbound = map[string]interface{}{"protocol": "vless", "tag": fmt.Sprint("node-", i),
				"settings": map[string]interface{}{"address": fmt.Sprintf("node-%d.invalid", i), "port": 443, "id": "synthetic"}}
		} else {
			outbound, _ = buildHysteria2Outbound(fmt.Sprintf("hy2://synthetic@hy-%d.invalid:443?sni=tls.invalid", i), "proxy")
		}
		profiles = append(profiles, map[string]interface{}{"remarks": fmt.Sprint("Node ", i), "outbounds": []interface{}{outbound, map[string]interface{}{"protocol": "freedom"}}})
	}
	profiles = append(profiles,
		map[string]interface{}{"outbounds": []interface{}{
			map[string]interface{}{"protocol": "vless", "settings": map[string]interface{}{"address": "one.invalid", "port": 443, "id": "synthetic"}},
			map[string]interface{}{"protocol": "vless", "settings": map[string]interface{}{"address": "two.invalid", "port": 443, "id": "synthetic"}},
		}},
		map[string]interface{}{"outbounds": []interface{}{
			map[string]interface{}{"protocol": "vless", "settings": map[string]interface{}{"address": "three.invalid", "port": 443, "id": "synthetic"}},
		}, "routing": map[string]interface{}{"balancers": []interface{}{map[string]interface{}{"tag": "automatic"}}}},
	)
	body, _ := json.Marshal(map[string]interface{}{"configs": profiles})
	servers, report, err := ParseSubscriptionDetailed(string(body))
	if err != nil || len(servers) != 24 || report.SkippedComposite != 2 || len(report.Warnings) != 1 {
		t.Fatalf("import = %d, report = %+v, error = %v", len(servers), report, err)
	}
	counts := map[string]int{}
	for _, server := range servers {
		counts[server.Protocol]++
		if !CanBuildServer(server) {
			t.Fatal("imported endpoint cannot be built")
		}
	}
	if counts["vless"] != 21 || counts["hysteria2"] != 3 {
		t.Fatalf("protocol counts = %v", counts)
	}
}

func TestJSONSubscriptionAllBase64Forms(t *testing.T) {
	body := " \ufeff[" + rawEndpointFixture + "]\n"
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		encoded := encoding.EncodeToString([]byte(body))
		if len(encoded) > 40 {
			encoded = encoded[:40] + "\n" + encoded[40:]
		}
		servers, _, err := ParseSubscriptionDetailed(encoded)
		if err != nil || len(servers) != 1 {
			t.Fatalf("base64 input was rejected: %v", err)
		}
	}
}

func TestJSONSubscriptionDoesNotFlattenChainedOrBalancerProfiles(t *testing.T) {
	for _, body := range []string{
		`{"protocol":"vless","settings":{"address":"example.invalid","port":443,"id":"synthetic"},"proxySettings":{"tag":"another-proxy"}}`,
		`{"protocol":"vless","settings":{"address":"example.invalid","port":443,"id":"synthetic"},"streamSettings":{"sockopt":{"dialerProxy":"another-proxy"}}}`,
		`{"outbounds":[` + rawEndpointFixture + `],"routing":{"rules":[{"balancerTag":"automatic"}]}}`,
	} {
		servers, report, err := ParseSubscriptionDetailed(body)
		if err == nil || len(servers) != 0 || report.SkippedComposite != 1 || len(report.Warnings) == 0 {
			t.Fatalf("composite profile was not reported: count=%d, report=%+v, error=%v", len(servers), report, err)
		}
	}
}

func TestJSONSubscriptionCanonicalIdentityIgnoresTagButKeepsTransport(t *testing.T) {
	body := `[` + rawEndpointFixture + `,` + strings.Replace(rawEndpointFixture, "provider-name", "renamed", 1) + `,` + strings.Replace(rawEndpointFixture, "stream-up", "packet-up", 1) + `]`
	servers, _, err := ParseSubscriptionDetailed(body)
	if err != nil || len(servers) != 2 {
		t.Fatalf("expected two distinct transport configurations, got %d: %v", len(servers), err)
	}
}

func TestJSONSubscriptionInvalidJSONAndEndpointErrorsDoNotEchoCredentials(t *testing.T) {
	for _, body := range []string{`[{"protocol":"SECRET_MARKER"`, `[{"protocol":"vless","settings":{"id":"SECRET_MARKER"}}]`} {
		_, report, err := ParseSubscriptionDetailed(body)
		if err == nil || strings.Contains(err.Error(), "SECRET_MARKER") || strings.Contains(strings.Join(report.Warnings, ""), "SECRET_MARKER") {
			t.Fatal("invalid subscription was accepted or appeared in diagnostics")
		}
	}
}
