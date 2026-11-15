package cardcontroller

import (
	"strings"
	"testing"
	"time"

	"xkeen-panel/internal/trafficlog"
)

func TestTrafficRecorderNormalAndGuardMetadata(t *testing.T) {
	tag := nodePrefix + strings.Repeat("a", 64)
	r := trafficRecorder{names: map[string]string{cardPrefix + "openai": "ChatGPT", tag: "Example server", "DIRECT": "Напрямую"}, exits: map[string]ConnectionExit{tag: {Kind: "server", Name: "Example server", Country: "US", Source: "Example VPN"}, "DIRECT": {Kind: "direct"}}}
	message := "[TCP] 192.0.2.10:53430 --> ios.chat.openai.com:443 match RuleSet(XKP-service-openai) using " + cardPrefix + "openai[" + tag + "]"
	e, ok := r.parse("info", message, nil)
	if !ok || e.ServiceID != "openai" || e.Host != "ios.chat.openai.com" || e.Device != "192.0.2.10" || e.Exit.Source != "Example VPN" || e.Rule != "RuleSet(XKP-service-openai)" {
		t.Fatalf("connection metadata lost: %#v", e)
	}
	if len(e.Route) != 2 || e.Route[1] != "Example server" {
		t.Fatal("did not freeze friendly route")
	}
	blocked := GuardEvent{At: time.Now(), Device: "192.0.2.10", Host: "192.0.2.20", Port: "443", Network: "UDP", Reason: "protocol_guard"}
	e, ok = r.parse("info", "[UDP] 192.0.2.10:50000 --> 192.0.2.20:443 using XKP-card-guard-quic[REJECT]", &blocked)
	if !ok || e.Kind != "quic" || e.Exit.Kind != "reject" {
		t.Fatal("QUIC was conflated with a VPN outage")
	}
	blocked.Reason = "guard_reject"
	blocked.ServiceID = "openai"
	e, ok = r.parse("info", "", &blocked)
	if !ok || e.Kind != "kill_switch" || e.ServiceID != "openai" {
		t.Fatal("guard event metadata lost")
	}
	for _, text := range []string{"provider failure https://example.com/?token=secret", "[TCP] invalid --> https://example.com/?secret:443 using DIRECT"} {
		if _, ok = r.parse("error", text, nil); ok {
			t.Fatal("archived raw non-connection log")
		}
	}
}

func TestTrafficRecorderDisabledDoesNotProjectOrRecord(t *testing.T) {
	c := &Controller{}
	called := false
	c.SetTrafficRecorder(func() bool { return false }, func(trafficlog.Entry) { called = true })
	c.recordTraffic("info", "[TCP] 192.0.2.10:30000 --> example.com:443 using DIRECT", profile{}, nil)
	if called || c.traffic.names != nil {
		t.Fatal("disabled history allocated a projection or recorded traffic")
	}
}
