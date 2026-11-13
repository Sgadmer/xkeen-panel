package xkeen

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"xkeen-panel/internal/models"
)

func TestServiceProfileMemoryAdmission(t *testing.T) {
	for _, test := range []struct {
		input    string
		admitted bool
	}{
		{"MemAvailable: 49000 kB\nMemFree: 999999 kB", false},
		{"MemAvailable: 65536 kB", true},
		{"MemFree: 28000 kB\nCached: 25000 kB\nShmem: 500 kB", true},
		{"MemFree: 28000 kB\nCached: 25000 kB\nShmem: 6000 kB", false},
		{"MemAvailable: unknown", false},
	} {
		if got := workerMemoryAvailable([]byte(test.input)); got != test.admitted {
			t.Errorf("worker admission=%t, expected %t", got, test.admitted)
		}
	}
}

func TestServiceProfileIsolatesResolverAndDirectFallback(t *testing.T) {
	profile := profileFixture()
	mapOf(mapOf(profile["burstObservatory"])["pingConfig"])["connectivity"] = "https://not-allowed.example/"
	mapOf(profile["dns"])["servers"] = []string{"localhost", "https+local://outside.example/"}
	key, err := newServiceWorkerKey(12345)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := serviceWorkerConfig(profileServer(t, profile), nil, key)
	if err != nil {
		t.Fatal(err)
	}
	routing := mapOf(cfg["routing"])
	bal := mapOf(asSlice(routing["balancers"])[0])
	outs := asSlice(cfg["outbounds"])
	if mapOf(outs[0])["protocol"] != "blackhole" || mapOf(mapOf(bal["strategy"])["settings"])["maxRTT"] != "2s" {
		t.Fatal("lost provider weights or default guard")
	}
	protos := map[string]interface{}{}
	for _, v := range outs {
		ob := mapOf(v)
		protos[ob["tag"].(string)] = ob["protocol"]
		if ob["protocol"] == "freedom" || ob["protocol"] == "direct" {
			t.Fatal("direct remained")
		}
	}
	if protos[bal["fallbackTag"].(string)] != "blackhole" {
		t.Fatal("unprotected fallback")
	}
	dnsRule := mapOf(asSlice(routing["rules"])[0])
	if dnsRule["balancerTag"] != bal["tag"] || dnsRule["inboundTag"].([]string)[0] != workerDNS {
		t.Fatal("DNS did not use the provider's group")
	}
	if _, ok := mapOf(mapOf(cfg["burstObservatory"])["pingConfig"])["connectivity"]; ok {
		t.Fatal("direct connectivity probe remained")
	}
	data, _ := json.Marshal(cfg)
	if strings.Contains(string(data), "outside.example") || strings.Contains(string(data), "not-allowed.example") {
		t.Fatal("unprotected probe or resolver remained")
	}
	local, _ := json.Marshal(key.outbound("service"))
	if strings.Contains(string(local), "PRIVATE KEY") {
		t.Fatal("worker key leaked to main core")
	}
}

// XRAY_TEST_BINARY runs both real cores on loopback; the upstream fake proxy
// reports the hostname it actually received. There is no outside connection.
func TestServiceProfilesRealCore(t *testing.T) {
	bin := os.Getenv("XRAY_TEST_BINARY")
	if bin == "" {
		t.Skip("set XRAY_TEST_BINARY to enable Xray integration")
	}
	root := t.TempDir()
	rt := Runtime{Core: CoreXray, CoreBin: bin, XrayConfDir: filepath.Join(root, "configs")}
	defer func() {
		if err := PruneServiceProfiles(rt, map[string]bool{}); err != nil {
			t.Error(err)
		}
	}()
	targets := []string{}
	var cardServer models.Server
	ports := []int{}
	outbounds := []interface{}{}
	inbounds := []interface{}{}
	rules := []interface{}{}
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "direct-leak") }))
	defer direct.Close()
	directAddress := direct.Listener.Addr().String()
	for i := 0; i < 2; i++ {
		label := fmt.Sprintf("service-%d", i)
		provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "CONNECT" {
				http.Error(w, "CONNECT expected", 400)
				return
			}
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			rw.WriteString("HTTP/1.1 200 OK\r\n\r\n")
			rw.Flush()
			if _, err := http.ReadRequest(rw.Reader); err != nil {
				return
			}
			body := label + "/" + r.Host
			fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
			rw.Flush()
		}))
		t.Cleanup(provider.Close)
		p := provider.Listener.Addr().(*net.TCPAddr).Port
		server := profileServer(t, map[string]interface{}{"outbounds": []interface{}{
			map[string]interface{}{"tag": "node", "protocol": "http", "settings": map[string]interface{}{"servers": []interface{}{map[string]interface{}{"address": "127.0.0.1", "port": p}}}},
			map[string]interface{}{"tag": "bypass", "protocol": "freedom"},
		}, "routing": map[string]interface{}{"rules": []interface{}{map[string]interface{}{"type": "field", "ip": []string{"127.0.0.1/32"}, "outboundTag": "bypass"}}}})
		id := ServiceTargetID(server)
		if i == 0 {
			cardServer = server
		}
		ob, err := PrepareServiceProfile(rt, id, server, label, nil)
		if err != nil {
			t.Fatal(err)
		}
		second, err := PrepareServiceProfile(rt, id, server, label, nil)
		if err != nil || mapOf(second["settings"])["port"] != mapOf(ob["settings"])["port"] {
			t.Fatal("worker not reused", err)
		}
		targets = append(targets, id)
		outbounds = append(outbounds, ob)
		ls, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p = ls.Addr().(*net.TCPAddr).Port
		ls.Close()
		ports = append(ports, p)
		inbounds = append(inbounds, map[string]interface{}{"tag": label, "listen": "127.0.0.1", "port": p, "protocol": "http"})
		rules = append(rules, map[string]interface{}{"type": "field", "inboundTag": []string{label}, "outboundTag": label})
	}
	directListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	directPort := directListener.Addr().(*net.TCPAddr).Port
	directListener.Close()
	inbounds = append(inbounds, map[string]interface{}{"tag": "ordinary", "listen": "127.0.0.1", "port": directPort, "protocol": "http"})
	outbounds = append(outbounds, map[string]interface{}{"tag": "ordinary", "protocol": "freedom"})
	rules = append(rules, map[string]interface{}{"type": "field", "inboundTag": []string{"ordinary"}, "outboundTag": "ordinary"})
	config := map[string]interface{}{"inbounds": inbounds, "outbounds": outbounds, "routing": map[string]interface{}{"rules": rules}}
	data, _ := json.Marshal(config)
	file := filepath.Join(root, "main.json")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	main := exec.CommandContext(ctx, bin, "run", "-config", file)
	main.Env = workerEnv(rt)
	if err := main.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); main.Wait() }()
	if err := waitListening(ports[0], 6*time.Second); err != nil {
		t.Fatal(err)
	}
	get := func(p int, host string) string {
		proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(p))
		tr := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
		defer tr.CloseIdleConnections()
		client := &http.Client{Timeout: 3 * time.Second, Transport: tr}
		res, err := client.Get("http://" + host + "/")
		if err != nil {
			return ""
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1024))
		return string(b)
	}
	for i, p := range ports {
		expected := fmt.Sprintf("service-%d/protected.invalid:80", i)
		if got := get(p, "protected.invalid"); got != expected {
			t.Fatalf("expected %q, got %q", expected, got)
		}
		if got := get(p, directAddress); strings.Contains(got, "service-") || got == "direct-leak" {
			t.Fatal("protected direct exception was not blocked")
		}
	}
	if get(directPort, directAddress) != "direct-leak" {
		t.Fatal("ordinary DIRECT unavailable")
	}
	if err := PruneServiceProfiles(rt, map[string]bool{targets[1]: true}); err != nil {
		t.Fatal(err)
	}
	// Occupying a stopped worker's port cannot receive VLESS account or
	// destination data. Only a TLS client hello is allowed on this socket.
	port := mapOf(mapOf(outbounds[0])["settings"])["port"].(int)
	var fake net.Listener
	for i := 0; i < 25; i++ {
		fake, _ = net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port))
		if fake != nil {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if fake == nil {
		t.Fatal("stopped worker did not release port")
	}
	defer fake.Close()
	wrong, err := newServiceWorkerKey(port)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair([]byte(wrong.Cert), []byte(wrong.Key))
	if err != nil {
		t.Fatal(err)
	}
	presented := make(chan bool, 1)
	go func() {
		conn, err := fake.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fakeTLS := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		presented <- fakeTLS.Handshake() == nil
	}()
	if got := get(ports[0], "protected.invalid"); strings.HasPrefix(got, "service-") {
		t.Fatal("lost worker fell back")
	}
	select {
	case trusted := <-presented:
		if trusted {
			t.Fatal("main core accepted the wrong profile certificate")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client did not attempt TLS")
	}
	if got := get(ports[1], "protected.invalid"); got != "service-1/protected.invalid:80" {
		t.Fatal("pruning affected the other service")
	}
	if get(directPort, directAddress) != "direct-leak" {
		t.Fatal("ordinary DIRECT failed when a worker died")
	}
	t.Run("MihomoCards", func(t *testing.T) {
		mihomo := os.Getenv("MIHOMO_TEST_BINARY")
		if mihomo == "" {
			t.Skip("set MIHOMO_TEST_BINARY to enable Mihomo integration")
		}
		doc, err := decodeServerOutbound(cardServer.RawProfile)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(asSlice(doc["outbounds"])[0])
		if err != nil {
			t.Fatal(err)
		}
		single := models.Server{RawOutbound: raw}
		entries := []interface{}{}
		defer func() {
			if err := PruneCardProxies(rt, nil); err != nil {
				t.Error(err)
			}
		}()
		for i, server := range []models.Server{single, cardServer} {
			entry, err := PrepareCardProxy(rt, ServiceTargetID(server), server)
			if err != nil {
				t.Fatal(err)
			}
			entries = append(entries, map[string]interface{}{"name": fmt.Sprintf("card%d", i), "type": "vless", "server": "127.0.0.1", "port": entry.Port, "uuid": entry.UUID, "network": "tcp", "tls": true, "servername": entry.ServerName, "fingerprint": entry.Fingerprint, "skip-cert-verify": false, "udp": true})
		}
		bad, _ := cloneProfileRule(mapOf(entries[0]))
		bad["name"] = "wrongpin"
		bad["fingerprint"] = strings.Repeat("ab", 32)
		entries = append(entries, bad)
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		config := map[string]interface{}{"mixed-port": port, "mode": "rule", "log-level": "silent", "proxies": entries, "rules": []string{"DOMAIN,single.invalid,card0", "DOMAIN,composite.invalid,card1", "DOMAIN,wrongpin.invalid,wrongpin", "MATCH,DIRECT"}}
		yaml, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "mihomo.yaml")
		if err := os.WriteFile(path, yaml, 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, mihomo, "-d", root, "-f", path)
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		defer func() { cancel(); cmd.Wait() }()
		if err := waitListening(port, 6*time.Second); err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{"single.invalid", "composite.invalid"} {
			if got := get(port, target); got != "service-0/"+target+":80" {
				t.Fatalf("Mihomo %s did not reach selected VPN: %q", target, got)
			}
		}
		if got := get(port, "wrongpin.invalid"); strings.HasPrefix(got, "service-") {
			t.Fatal("Mihomo accepted a mismatched TLS fingerprint")
		}
		if get(port, directAddress) != "direct-leak" {
			t.Fatal("Mihomo lost DIRECT")
		}
	})
}
