package xkeen

import (
	"context"
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
	"sync/atomic"
	"testing"
	"time"

	"xkeen-panel/internal/models"
)

func TestMultiPoolWorkerUsesMeasuredMember(t *testing.T) {
	bin := os.Getenv("XRAY_TEST_BINARY")
	if bin == "" {
		t.Skip("set XRAY_TEST_BINARY")
	}
	var observed atomic.Bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			http.Error(w, "expected a tunnel", 400)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprint(rw, "HTTP/1.1 200 OK\r\n\r\n")
		rw.Flush()
		if _, err := http.ReadRequest(rw.Reader); err != nil {
			return
		}
		switch r.Host {
		case "probe.invalid:80":
			observed.Store(true)
			fmt.Fprint(rw, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
		case "app.invalid:80":
			fmt.Fprint(rw, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 8\r\n\r\nvpn-only")
		}
		rw.Flush()
	}))
	defer provider.Close()
	raw, _ := json.Marshal(map[string]interface{}{"protocol": "http", "settings": map[string]interface{}{
		"servers": []interface{}{map[string]interface{}{"address": "127.0.0.1", "port": provider.Listener.Addr().(*net.TCPAddr).Port}},
	}})
	pool, err := MultiPoolProfile([]models.Server{{RawOutbound: raw}})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := addr.Addr().(*net.TCPAddr).Port
	addr.Close()
	key, err := newServiceWorkerKey(port)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := serviceWorkerConfig(pool, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	bal := mapOf(asSlice(mapOf(cfg["routing"])["balancers"])[0])
	if bal["fallbackTag"] != workerBlock || mapOf(bal["strategy"])["type"] != "leastPing" {
		t.Fatal("unprotected balancer fallback")
	}
	// Use a synthetic observation destination and accept a loopback HTTP client
	// on the normal worker input tag. Routing, resolver and outbounds are unchanged.
	mapOf(cfg["observatory"])["probeURL"] = "http://probe.invalid/test"
	mapOf(cfg["observatory"])["probeInterval"] = "1s"
	cfg["inbounds"] = []interface{}{map[string]interface{}{"protocol": "http", "tag": workerInput, "listen": "127.0.0.1", "port": port}}
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "worker.json")
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	process := exec.CommandContext(ctx, bin, "run", "-config", path)
	if err = process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); process.Wait() }()
	if err = waitListening(port, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	client := http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
	for ctx.Err() == nil {
		if observed.Load() {
			if res, e := client.Get("http://app.invalid/"); e == nil {
				data, _ := io.ReadAll(io.LimitReader(res.Body, 64))
				res.Body.Close()
				if string(data) == "vpn-only" {
					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("measured member did not carry test traffic, observed=%v", observed.Load())
}
