package cardcontroller

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"xkeen-panel/internal/xkeen"
)

// Exercise Mihomo's actual rule loop with a controlled UDP-incapable member
// and a receiving local target. The unassigned port must receive the control
// packet while the matched port must receive nothing, despite MATCH,DIRECT.
func TestMihomoRejectsUnsupportedUDPBeforeDirect(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("set MIHOMO_TEST_BINARY")
	}
	port, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	local := port.Addr().(*net.TCPAddr)
	port.Close()
	receiver := func() *net.UDPConn {
		socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { socket.Close() })
		return socket
	}
	blocked, control := receiver(), receiver()
	p := profile{doc: map[string]interface{}{
		"socks-port": local.Port, "mode": "rule", "allow-lan": false,
		"proxies":      []interface{}{map[string]interface{}{"name": "test-tcp-only", "type": "http", "server": "127.0.0.1", "port": 1}},
		"proxy-groups": []interface{}{map[string]interface{}{"name": "ChatGPT", "type": "select", "proxies": []string{"DIRECT"}}},
		"rules":        []interface{}{"DST-PORT," + portOf(blocked.LocalAddr()) + ",ChatGPT", "MATCH,DIRECT"},
	}, assigned: map[string]string{"openai": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	_, err = render(&p, []xkeen.ServiceRouteView{{RoutingService: xkeen.RoutingService{ID: "openai"}}}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range list(p.doc["proxy-groups"]) {
		g := object(raw)
		if str(g["name"]) == cardPrefix+"openai" {
			g["proxies"] = []string{"test-tcp-only"}
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body, err := json.Marshal(p.doc)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(core, "-d", dir, "-f", path)
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	send := func(dst *net.UDPConn) {
		// Use a separate association/UDP sender for each case so the previous
		// connection's NAT cache cannot determine the outcome.
		var ctrl net.Conn
		until := time.Now().Add(3 * time.Second)
		for time.Now().Before(until) {
			ctrl, err = net.DialTimeout("tcp4", local.String(), 80*time.Millisecond)
			if err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer ctrl.Close()
		ctrl.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = ctrl.Write([]byte{5, 1, 0}); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 10)
		if _, err = io.ReadFull(ctrl, response[:2]); err != nil || response[1] != 0 {
			t.Fatal("SOCKS handshake", err)
		}
		if _, err = ctrl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
			t.Fatal(err)
		}
		if _, err = io.ReadFull(ctrl, response); err != nil || response[1] != 0 || response[3] != 1 {
			t.Fatal("UDP association", err)
		}
		relay, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(binary.BigEndian.Uint16(response[8:10]))})
		if err != nil {
			t.Fatal(err)
		}
		defer relay.Close()
		dgram := []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 0, 42}
		binary.BigEndian.PutUint16(dgram[8:10], uint16(dst.LocalAddr().(*net.UDPAddr).Port))
		// Mihomo can accept the SOCKS handshake before its UDP rule engine is
		// running. Use the DIRECT control as the readiness probe.
		until = time.Now().Add(5 * time.Second)
		var readErr error
		for {
			if _, err = relay.Write(dgram); err != nil {
				t.Fatal(err)
			}
			window := time.Second
			if dst == control {
				window = 200 * time.Millisecond
			}
			dst.SetReadDeadline(time.Now().Add(window))
			var byteBuf [8]byte
			var n int
			n, _, readErr = dst.ReadFromUDP(byteBuf[:])
			if dst != control || readErr == nil {
				if dst == control && (n != 1 || byteBuf[0] != 42) {
					t.Fatal("invalid DIRECT control packet")
				}
				break
			}
			if timeout, ok := readErr.(net.Error); !ok || !timeout.Timeout() || time.Now().After(until) {
				t.Fatal("DIRECT control packet failed", readErr)
			}
		}
		if dst == blocked {
			if e, ok := readErr.(net.Error); !ok || !e.Timeout() {
				t.Fatal("unsupported UDP reached the direct receiver", readErr)
			}
		}
	}
	send(control)
	send(blocked)
}

func portOf(addr net.Addr) string { _, port, _ := net.SplitHostPort(addr.String()); return port }
