package xkeen

import (
	"encoding/json"
	"testing"
	"time"

	"xkeen-panel/internal/models"
)

func testEndpoint(t *testing.T, server models.Server) endpoint {
	t.Helper()
	ep, ok := endpointOfServer(server)
	if !ok {
		t.Fatalf("cannot derive endpoint for %s", server.Name)
	}
	return ep
}

func testRawServer(t *testing.T, name string, outbound map[string]interface{}) models.Server {
	t.Helper()
	raw, err := json.Marshal(outbound)
	if err != nil {
		t.Fatal(err)
	}
	return models.Server{Name: name, RawURI: "xray-json://test-" + name, RawOutbound: raw, Latency: -1}
}

func testHysteriaServer(t *testing.T) models.Server {
	t.Helper()
	return testRawServer(t, "HY2", map[string]interface{}{
		"protocol": "hysteria",
		"settings": map[string]interface{}{"address": "hy.example", "port": 443, "version": 2},
		"streamSettings": map[string]interface{}{
			"network": "hysteria", "security": "tls",
			"tlsSettings":      map[string]interface{}{"serverName": "hy.example"},
			"hysteriaSettings": map[string]interface{}{"version": 2, "auth": "test-only-password"},
		},
	})
}

func TestPoolIncludesRawHysteriaAndPreservesIt(t *testing.T) {
	rt, path := liveConfDir(t)
	server := testHysteriaServer(t)
	state, err := EnablePool(rt, path, []models.Server{server}, PoolOptions{})
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := PoolNodes(path, state.Selector, []models.Server{server})
	if err != nil || len(nodes) != 1 || nodes[0].Server == nil {
		t.Fatalf("HY2 did not match its pool entry: nodes=%+v err=%v", nodes, err)
	}
	if nodes[0].NodeKey != NodeKeyOfServer(server) {
		t.Fatal("generated policy mark changed node identity")
	}
	matches, err := PoolMatchesSubscription(path, []models.Server{server}, state.Selector)
	if err != nil || !matches {
		t.Fatalf("unchanged HY2 reported drift: matches=%v err=%v", matches, err)
	}
	if err := DisablePool(rt, path, &server, state); err != nil {
		t.Fatalf("cannot return to a single HY2 outbound: %v", err)
	}
	config, err := ReadOutboundsConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	_, single := findProxyOutbound(asSlice(config["outbounds"]))
	if single["protocol"] != "hysteria" || outboundTag(single) != state.OriginalTag {
		t.Fatal("pool disable lost HY2 or the original routing tag")
	}
}

func TestPoolIdentityDetectsTransportAndAuthenticationChanges(t *testing.T) {
	base := models.Server{Protocol: "vless", RawURI: "vless://11111111-2222-3333-4444-555555555555@node.example:443?type=grpc&security=reality&pbk=old-key&sni=sni.example&serviceName=old"}
	variants := []string{
		"vless://11111111-2222-3333-4444-555555555555@node.example:443?type=grpc&security=reality&pbk=new-key&sni=sni.example&serviceName=old",
		"vless://11111111-2222-3333-4444-555555555555@node.example:443?type=grpc&security=reality&pbk=old-key&sni=other.example&serviceName=old",
		"vless://11111111-2222-3333-4444-555555555555@node.example:443?type=grpc&security=reality&pbk=old-key&sni=sni.example&serviceName=new",
		"vless://11111111-2222-3333-4444-555555555555@node.example:443?type=tcp&security=reality&pbk=old-key&sni=sni.example",
	}
	baseEndpoint := testEndpoint(t, base)
	for _, uri := range variants {
		changed := models.Server{Protocol: "vless", RawURI: uri}
		if baseEndpoint == testEndpoint(t, changed) {
			t.Error("different transport/authentication collapsed into one node")
		}
	}
}

func TestPoolRefreshDetectsChangedServiceOnSameAddress(t *testing.T) {
	rt, path := liveConfDir(t)
	server := models.Server{Protocol: "vless", RawURI: "vless://11111111-2222-3333-4444-555555555555@node.example:443?type=grpc&serviceName=first"}
	if _, err := EnablePool(rt, path, []models.Server{server}, PoolOptions{}); err != nil {
		t.Fatal(err)
	}
	server.RawURI = "vless://11111111-2222-3333-4444-555555555555@node.example:443?type=grpc&serviceName=second"
	matches, err := PoolMatchesSubscription(path, []models.Server{server}, DefaultPoolSelector)
	if err != nil || matches {
		t.Fatalf("service change must trigger refresh: matches=%v err=%v", matches, err)
	}
}

func TestPoolHTTPSFailureOnlyRemovesAutomaticEligibility(t *testing.T) {
	failed := testHysteriaServer(t)
	failed.ProbeKind = "https"
	failed.Latency = -1
	good := serverAt("good.example")
	good.ProbeKind = "https"
	good.Latency = 50
	got := SelectPoolServers([]models.Server{failed, good}, PoolSelection{})
	if len(got) != 1 || got[0].Address != good.Address {
		t.Fatalf("confirmed failed HTTPS tunnel entered the automatic pool: %+v", got)
	}
	if !CanBuildServer(failed) {
		t.Fatal("a failed probe must not make manual selection impossible")
	}
}

func TestPoolRawHTTPSMeasurementNeverReplacedByTCP(t *testing.T) {
	server := testHysteriaServer(t)
	server.ProbeKind = "https"
	server.Latency = 37
	server.LastChecked = time.Now()
	got := checkPoolLatencies([]models.Server{server}, 10*time.Millisecond, 1)
	if len(got) != 1 || got[0].Latency != 37 || !got[0].LastChecked.Equal(server.LastChecked) {
		t.Fatal("HTTPS tunnel measurement was overwritten by a TCP endpoint probe")
	}
}
