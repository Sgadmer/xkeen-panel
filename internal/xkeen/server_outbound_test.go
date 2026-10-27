package xkeen

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"xkeen-panel/internal/models"
)

func TestNativeBuilderChangesOnlyTagAndLocalPolicyMark(t *testing.T) {
	server := models.Server{RawOutbound: json.RawMessage(rawEndpointFixture)}
	before := append([]byte(nil), server.RawOutbound...)
	template := map[string]interface{}{"protocol": "hysteria", "streamSettings": map[string]interface{}{
		"network": "grpc", "security": "tls", "tlsSettings": map[string]interface{}{"serverName": "wrong.invalid"},
		"sockopt": map[string]interface{}{"mark": 255, "tcpFastOpen": false, "tproxy": "tproxy"},
	}}
	actual, err := BuildServerOutbound(server, "selected", template)
	if err != nil {
		t.Fatal(err)
	}
	wanted, _ := decodeServerOutbound(server.RawOutbound)
	wanted["tag"] = "selected"
	mapOf(mapOf(wanted["streamSettings"])["sockopt"])["mark"] = 255
	actualJSON, _ := json.Marshal(actual)
	wantedJSON, _ := json.Marshal(wanted)
	if string(actualJSON) != string(wantedJSON) || !bytes.Equal(before, server.RawOutbound) {
		t.Fatal("builder changed endpoint options or mutated the original")
	}
	if !bytes.Contains(actualJSON, []byte("9007199254740993")) {
		t.Fatal("unknown integer field lost precision")
	}
}

func TestNativeIdentityIgnoresOnlyLocalTagAndMark(t *testing.T) {
	server := models.Server{RawOutbound: json.RawMessage(rawEndpointFixture)}
	key := ServerIdentity(server)
	generated, err := BuildServerOutbound(server, "different-tag", map[string]interface{}{"streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": 255}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(generated)
	if ServerIdentity(models.Server{RawOutbound: raw}) != key {
		t.Fatal("local mark/tag changed identity")
	}
	mapOf(mapOf(generated["streamSettings"])["sockopt"])["tcpFastOpen"] = false
	raw, _ = json.Marshal(generated)
	if ServerIdentity(models.Server{RawOutbound: raw}) == key {
		t.Fatal("functional socket option change was ignored")
	}
}

func TestVLESSIdentityMatchesFlatClassicAndTransportAlias(t *testing.T) {
	uri := "vless://synthetic@example.invalid:443?type=tcp&security=none"
	server := models.Server{RawURI: uri, Protocol: "vless"}
	flat, err := BuildServerOutbound(server, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	classicTemplate := map[string]interface{}{"settings": map[string]interface{}{"vnext": []interface{}{}}}
	classic, err := BuildServerOutbound(server, "another", classicTemplate)
	if err != nil {
		t.Fatal(err)
	}
	mapOf(classic["streamSettings"])["network"] = "raw"
	a, _ := json.Marshal(flat)
	b, _ := json.Marshal(classic)
	if ServerIdentity(models.Server{RawOutbound: a}) != ServerIdentity(models.Server{RawOutbound: b}) {
		t.Fatal("equivalent flat/vnext or tcp/raw shapes differ")
	}
	if ServerIdentity(server) != uri {
		t.Fatal("legacy URI identity changed")
	}
}

func TestNativeBuilderRejectsUnsupportedOrDependentEndpoints(t *testing.T) {
	for _, raw := range []string{
		`{"protocol":"freedom"}`,
		`{"protocol":"vless","settings":{"address":"example.invalid","port":443,"id":"synthetic"},"proxySettings":{"tag":"dependent"}}`,
		`{"protocol":"vless","settings":{"address":"example.invalid","port":0,"id":"synthetic"}}`,
	} {
		if CanBuildServer(models.Server{RawOutbound: json.RawMessage(raw)}) {
			t.Fatal("unsupported endpoint was considered buildable")
		}
	}
	_, err := BuildServerOutbound(models.Server{RawURI: "vless://SECRET_MARKER@%invalid"}, "", nil)
	if err == nil || strings.Contains(err.Error(), "SECRET_MARKER") {
		t.Fatal("invalid URI was accepted or leaked into diagnostics")
	}
}
