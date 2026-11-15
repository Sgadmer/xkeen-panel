package cardcontroller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xkeen-panel/internal/trafficlog"
	"xkeen-panel/internal/xkeen"
)

func guardFixture() profile {
	hash := strings.Repeat("a", 64)
	return profile{assigned: map[string]string{"openai": hash}, doc: map[string]interface{}{
		stateKey:  map[string]interface{}{"openai": hash},
		"proxies": []interface{}{map[string]interface{}{"name": nodePrefix + hash, "type": "vless"}},
		"proxy-groups": []interface{}{
			map[string]interface{}{"name": cardPrefix + "openai", "type": "select", "proxies": []string{nodePrefix + hash}},
			map[string]interface{}{"name": cardPrefix + "guard-openai", "type": "select", "proxies": []string{"REJECT"}},
			map[string]interface{}{"name": cardPrefix + "guard-quic", "type": "select", "proxies": []string{"REJECT"}},
		},
	}}
}

func TestGuardEventsRequireOwnedProtectedAttempt(t *testing.T) {
	warning := "[TCP] dial XKP-card-openai (match DomainSuffix/openai.com) 192.0.2.10:52132 --> ios.chat.openai.com:443 error: internal endpoint with PRIVATE_AUTH_VALUE"
	rejection := "[UDP] 192.0.2.10:52132 --> ios.chat.openai.com:443 match DomainSuffix(openai.com) using XKP-card-guard-openai[REJECT]"
	for _, test := range []struct {
		name, level, line, want string
		change                  func(*profile)
	}{
		{name: "failed protected dial", level: "warning", line: warning, want: "vpn_unavailable"},
		{name: "managed terminal stop", level: "info", line: rejection, want: "guard_reject"},
		{name: "protocol stop remains distinct", level: "info", line: strings.ReplaceAll(rejection, "guard-openai", "guard-quic"), want: "protocol_guard"},
		{name: "ad block is not kill switch", level: "info", line: strings.ReplaceAll(rejection, "XKP-card-guard-openai", "AdBlock")},
		{name: "generic rejection is not attributed", level: "info", line: strings.ReplaceAll(rejection, "guard-openai", "reject")},
		{name: "plain REJECT not evidence", level: "info", line: strings.ReplaceAll(rejection, "guard-openai", "openai")},
		{name: "missing pinned worker", level: "info", line: strings.ReplaceAll(rejection, "guard-openai", "openai"), want: "guard_reject", change: func(p *profile) {
			object(list(p.doc["proxy-groups"])[0])["proxies"] = []string{"REJECT"}
		}},
		{name: "healthy route not evidence", level: "info", line: strings.ReplaceAll(rejection, "[REJECT]", "[US node]")},
		{name: "foreign prefix cannot forge owner", level: "info", line: strings.ReplaceAll(rejection, "guard-openai", "guard-openai-other")},
		{name: "disabled service", level: "warning", line: warning, change: func(p *profile) {
			p.doc[killSwitchKey] = map[string]interface{}{"enabled": true, "services": map[string]interface{}{"openai": "off"}}
		}},
		{name: "manual direct", level: "warning", line: warning, change: func(p *profile) { p.assigned["openai"] = directTarget }},
		{name: "unowned profile", level: "warning", line: warning, change: func(p *profile) { delete(p.doc, stateKey) }},
		{name: "manual block", level: "warning", line: warning, change: func(p *profile) { object(list(p.doc["proxy-groups"])[0])["proxies"] = []string{"REJECT"} }},
		{name: "nested manual block", level: "warning", line: warning, change: func(p *profile) {
			object(list(p.doc["proxy-groups"])[0])["proxies"] = []string{"OwnerBlock"}
			p.doc["proxy-groups"] = append(list(p.doc["proxy-groups"]), map[string]interface{}{"name": "OwnerBlock", "type": "select", "proxies": []string{"REJECT"}})
		}},
		{name: "nested direct fallback", level: "warning", line: warning, change: func(p *profile) {
			object(list(p.doc["proxy-groups"])[0])["proxies"] = []string{"OwnerFallback"}
			p.doc["proxy-groups"] = append(list(p.doc["proxy-groups"]), map[string]interface{}{"name": "OwnerFallback", "type": "fallback", "proxies": []string{nodePrefix + strings.Repeat("a", 64), "DIRECT"}})
		}},
		{name: "error URL discarded", level: "warning", line: strings.Replace(warning, "ios.chat.openai.com:443", "https://example.com/private?token=PRIVATE_AUTH_VALUE", 1)},
		{name: "unknown format discarded", level: "info", line: "VPN health check failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := guardFixture()
			if test.change != nil {
				test.change(&p)
			}
			event, ok := parseGuardLog(test.level, test.line, p)
			if ok != (test.want != "") || event.Reason != test.want {
				t.Fatalf("got %+v, %t", event, ok)
			}
			if ok {
				if event.Device != "192.0.2.10" || event.Host != "ios.chat.openai.com" || event.Port != "443" {
					t.Fatalf("wrong addresses: %+v", event)
				}
				raw, _ := json.Marshal(event)
				if strings.Contains(string(raw), "PRIVATE_AUTH_VALUE") {
					t.Fatal("raw core error escaped into diagnostic event")
				}
			}
		})
	}
}

func TestGuardJournalBoundsDedupAndNotificationIdentity(t *testing.T) {
	c := &Controller{}
	now := time.Now()
	event := GuardEvent{At: now, ServiceID: "openai", Device: "192.0.2.10", Host: "chatgpt.com", Network: "TCP", Reason: "vpn_unavailable"}
	c.guard.add(event)
	first := c.guard.events[0].ID
	c.guard.add(event)
	if len(c.guard.events) != 1 || c.guard.events[0].Count != 2 {
		t.Fatal("repeated packet not merged")
	}
	c.guard.add(GuardEvent{At: now, Reason: "protocol_guard", Network: "UDP"})
	if id, _ := c.LatestGuardEvent(); id != first {
		t.Fatal("QUIC policy generated a kill-switch notification")
	}
	for i := 0; i < 200; i++ {
		event.Host = fmt.Sprintf("n%d.example", i)
		c.guard.add(event)
	}
	if len(c.guard.events) != 128 {
		t.Fatalf("unbounded ring: %d", len(c.guard.events))
	}
	c.guard.trim(now.Add(guardEventTTL + time.Second))
	if len(c.guard.events) != 0 {
		t.Fatal("expired diagnostic addresses retained")
	}
}

func TestGuardStreamKeepsOnlyValidatedSanitizedEvents(t *testing.T) {
	sent := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/logs" || r.URL.Query().Get("level") != "info" || r.Header.Get("Authorization") != "Bearer fixture-secret" {
			t.Error("log stream was not authenticated or used wrong endpoint")
			w.WriteHeader(401)
			return
		}
		for _, line := range []map[string]string{
			{"type": "info", "payload": "[TCP] 192.0.2.10:50000 --> ads.example:443 match DomainSuffix(ads.example) using AdBlock[REJECT]"},
			{"type": "warning", "payload": "[TCP] dial XKP-card-openai (match DomainSuffix/openai.com) 192.0.2.10:50001 --> chatgpt.com:443 error: PRIVATE_AUTH_VALUE"},
		} {
			_ = json.NewEncoder(w).Encode(line)
		}
		w.(http.Flusher).Flush()
		close(sent)
		<-r.Context().Done()
	}))
	defer server.Close()
	p := guardFixture()
	p.doc["external-controller"] = strings.TrimPrefix(server.URL, "http://")
	p.doc["secret"], p.doc["mode"], p.doc["log-level"] = "fixture-secret", "rule", "info"
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw, _ := json.Marshal(p.doc)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	c := New(path, dir, xkeen.Runtime{}, nil)
	archived := make(chan trafficlog.Entry, 128)
	c.SetTrafficRecorder(func() bool { return true }, func(entry trafficlog.Entry) {
		select {
		case archived <- entry:
		default:
		}
	})
	live, err := c.read()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { c.readGuardStream(ctx, live); close(done) }()
	select {
	case <-sent:
	case <-done:
		t.Fatal("local log stream failed to connect")
	case <-ctx.Done():
		t.Fatal("local log stream did not start")
	}
	deadline := time.Now().Add(time.Second)
	for {
		status := c.GuardEvents()
		if len(status.Events) == 1 {
			if status.Events[0].Host != "chatgpt.com" || !status.Complete {
				t.Fatalf("wrong stream event %+v", status)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stream did not record the protected failed attempt")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream did not stop when panel stopped")
	}
}

// Exercise the real core's log format and rejection path, with synthetic
// loopback SOCKS traffic only. Every destination is REJECT; no WAN is used.
func TestMihomoGuardObserverRecordsOnlyOwnedRejection(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("set MIHOMO_TEST_BINARY for the isolated real-core test")
	}
	port := func() *net.TCPAddr {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := listener.Addr().(*net.TCPAddr)
		listener.Close()
		return addr
	}
	socks, controller := port(), port()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	hash := strings.Repeat("a", 64)
	doc := map[string]interface{}{
		"mode": "rule", "log-level": "info", "allow-lan": false, "bind-address": "127.0.0.1", "ipv6": false,
		"socks-port": socks.Port, "external-controller": controller.String(), "secret": "fixture-secret",
		stateKey: map[string]interface{}{"openai": hash, "claude": hash},
		"proxy-groups": []interface{}{
			map[string]interface{}{"name": cardPrefix + "guard-openai", "type": "select", "proxies": []string{"REJECT"}},
			map[string]interface{}{"name": cardPrefix + "claude", "type": "select", "proxies": []string{"REJECT"}},
			map[string]interface{}{"name": "OwnerAdBlock", "type": "select", "proxies": []string{"REJECT"}},
		},
		"rules": []string{"DOMAIN-SUFFIX,guard-fixture.example," + cardPrefix + "guard-openai", "DOMAIN-SUFFIX,missing-worker.example," + cardPrefix + "claude", "DOMAIN-SUFFIX,ad-fixture.example,OwnerAdBlock", "MATCH,REJECT"},
	}
	raw, _ := json.Marshal(doc)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	proc := exec.CommandContext(ctx, core, "-d", dir, "-f", path)
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = proc.Wait() }()
	c := New(path, dir, xkeen.Runtime{}, nil)
	archived := make(chan trafficlog.Entry, 128)
	c.SetTrafficRecorder(func() bool { return true }, func(entry trafficlog.Entry) {
		select {
		case archived <- entry:
		default:
		}
	})
	live, err := c.read()
	if err != nil {
		t.Fatal(err)
	}
	for live.api.request(ctx, "GET", "/version", nil, nil) != nil {
		if ctx.Err() != nil {
			t.Fatal("isolated core did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	done := make(chan struct{})
	go func() { c.RunGuardObserver(ctx); close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("observer did not stop")
		}
	}()
	send := func(host string) {
		conn, err := net.DialTimeout("tcp4", socks.String(), 100*time.Millisecond)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(150 * time.Millisecond))
		_, _ = conn.Write([]byte{5, 1, 0})
		var reply [10]byte
		if _, err := io.ReadFull(conn, reply[:2]); err != nil || reply[1] != 0 {
			return
		}
		request := append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
		_, _ = conn.Write(append(request, 1, 187))
		_, _ = io.ReadFull(conn, reply[:])
		_, _ = conn.Write([]byte("fixture"))
	}
	recorded := map[string]string{}
	for {
		send("ad-fixture.example")
		send("guard-fixture.example")
		send("missing-worker.example")
		state := c.GuardEvents()
		for len(archived) > 0 {
			entry := <-archived
			recorded[entry.Host] = entry.Kind
		}
		if len(state.Events) > 0 {
			seen := map[string]bool{}
			for _, event := range state.Events {
				want := map[string]string{"guard-fixture.example": "openai", "missing-worker.example": "claude"}
				if want[event.Host] == "" || event.ServiceID != want[event.Host] || event.Reason != "guard_reject" {
					t.Fatalf("core log misclassified: %+v", event)
				}
				seen[event.Host] = true
			}
			if len(seen) == 2 && recorded["ad-fixture.example"] == "connection" && recorded["guard-fixture.example"] == "kill_switch" && recorded["missing-worker.example"] == "kill_switch" {
				return
			}
		}
		if ctx.Err() != nil {
			t.Fatal("real-core rejection was not observed")
		}
		time.Sleep(25 * time.Millisecond)
	}
}
