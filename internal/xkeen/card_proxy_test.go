package xkeen

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"xkeen-panel/internal/models"
)

func TestServiceProfileCardUsesMihomoTransportMark(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mihomo.yaml")
	if err := os.WriteFile(path, []byte("routing-mark: 911\n"), 0600); err != nil {
		t.Fatal(err)
	}
	template, err := cardTransportTemplate(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := newServiceWorkerKey(10001)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := serviceWorkerConfig(profileServer(t, profileFixture()), template, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range asSlice(cfg["outbounds"]) {
		out := mapOf(raw)
		mark := mapOf(mapOf(out["streamSettings"])["sockopt"])["mark"]
		if out["protocol"] == "vless" && mark != uint32(911) {
			t.Fatal("provider-facing mark not retained")
		}
		if out["protocol"] == "blackhole" && mark != nil {
			t.Fatal("block created a marked socket")
		}
	}
}

func TestServiceProfileMihomoUDP(t *testing.T) {
	xray, mihomo := os.Getenv("XRAY_TEST_BINARY"), os.Getenv("MIHOMO_TEST_BINARY")
	if xray == "" || mihomo == "" {
		t.Skip("set XRAY_TEST_BINARY and MIHOMO_TEST_BINARY")
	}
	root := t.TempDir()
	freePort := func() int {
		ls, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ls.Close()
		return ls.Addr().(*net.TCPAddr).Port
	}
	start := func(bin, name string, cfg map[string]interface{}, args ...string) {
		path := filepath.Join(root, name)
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, bin, append(args, path)...)
		if err = cmd.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		t.Cleanup(func() { cancel(); cmd.Wait() })
	}
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 128)
		for {
			n, src, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(append([]byte("provider/"), buf[:n]...), src)
		}
	}()
	key, err := newServiceWorkerKey(freePort())
	if err != nil {
		t.Fatal(err)
	}
	// This synthetic provider alone can redirect the documentation IP to the
	// echo service. A direct path to 192.0.2.8 cannot return its response.
	start(xray, "provider.json", map[string]interface{}{
		"inbounds":  []interface{}{map[string]interface{}{"listen": "127.0.0.1", "port": key.Port, "protocol": "vless", "settings": map[string]interface{}{"clients": []interface{}{map[string]interface{}{"id": key.User}}, "decryption": "none"}}},
		"outbounds": []interface{}{map[string]interface{}{"protocol": "freedom", "settings": map[string]interface{}{"redirect": echo.LocalAddr().String()}}},
	}, "run", "-config")
	if err = waitListening(key.Port, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	tr := Runtime{Core: CoreXray, CoreBin: xray, XrayConfDir: filepath.Join(root, "configs")}
	raw, _ := json.Marshal(map[string]interface{}{"protocol": "vless", "settings": map[string]interface{}{"address": "127.0.0.1", "port": key.Port, "id": key.User, "encryption": "none"}})
	server := models.Server{RawOutbound: raw}
	entry, err := PrepareCardProxy(tr, ServiceTargetID(server), server)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := PruneCardProxies(tr, nil); err != nil {
			t.Error(err)
		}
	}()
	localPort := freePort()
	start(mihomo, "mihomo.yaml", map[string]interface{}{"mixed-port": localPort, "mode": "rule", "log-level": "silent", "rules": []string{"MATCH,card"}, "proxies": []interface{}{map[string]interface{}{"name": "card", "type": "vless", "server": "127.0.0.1", "port": entry.Port, "uuid": entry.UUID, "tls": true, "servername": entry.ServerName, "fingerprint": entry.Fingerprint, "udp": true}}}, "-d", root, "-f")
	if err = waitListening(localPort, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	ctl, err := net.Dial("tcp4", "127.0.0.1:"+strconv.Itoa(localPort))
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	ctl.SetDeadline(time.Now().Add(4 * time.Second))
	ctl.Write([]byte{5, 1, 0})
	resp := make([]byte, 10)
	if _, err = io.ReadFull(ctl, resp[:2]); err != nil || resp[1] != 0 {
		t.Fatal("SOCKS5 greeting", err)
	}
	ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	if _, err = io.ReadFull(ctl, resp); err != nil || resp[1] != 0 || resp[3] != 1 {
		t.Fatal("UDP association", err)
	}
	peer := net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(resp[8])*256 + int(resp[9])}
	udp, err := net.DialUDP("udp4", nil, &peer)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(4 * time.Second))
	// UDP target 192.0.2.8:1234, outside loopback, never contacted by provider.
	datagram := append([]byte{0, 0, 0, 1, 192, 0, 2, 8, 4, 210}, []byte("card")...)
	if _, err = udp.Write(datagram); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, err := udp.Read(buf)
	if err != nil || n < 10 || string(buf[10:n]) != "provider/card" {
		t.Fatalf("UDP did not traverse authenticated VLESS/TLS: %v", err)
	}
}
