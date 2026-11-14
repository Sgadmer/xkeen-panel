package cardcontroller

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

// Use real .dat wire messages and Mihomo's rule provider on loopback. The
// test HTTP proxy receives the matched hostname without resolving it.
// Other names (including the manual exception) must never reach that proxy.
func TestRefilterLivePolicyAndRollback(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("set MIHOMO_TEST_BINARY")
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	data := filepath.Join(dir, "dat")
	if err := os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	field := func(key byte, b []byte) []byte {
		return append(binary.AppendUvarint([]byte{key}, uint64(len(b))), b...)
	}
	file := func(items ...[]byte) []byte {
		section := field(10, []byte("REFILTER"))
		for _, data := range items {
			section = append(section, field(18, data)...)
		}
		return field(10, section)
	}
	domain := func(s string) []byte { return append([]byte{8, 2}, field(18, []byte(s))...) }
	siteFile := filepath.Join(data, "geosite_refilter.dat")
	ipFile := filepath.Join(data, "geoip_refilter.dat")
	write := func(path string, raw []byte) {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(siteFile, file(domain("blocked.test"), domain("habr.test"), domain("192.0.2.12"), domain("habr.test")))
	write(ipFile, file(append(field(10, []byte{192, 0, 2, 0}), 16, 24)))
	port := func() *net.TCPAddr {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr)
	}
	api, proxy := port(), port()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(204)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 200 OK\r\n\r\n")
		rw.Flush()
		if _, err := http.ReadRequest(bufio.NewReader(rw)); err == nil {
			rw.WriteString("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
			rw.Flush()
		}
	}))
	defer upstream.Close()
	u := upstream.Listener.Addr().(*net.TCPAddr)
	base := map[string]interface{}{"mode": "rule", "mixed-port": proxy.Port, "external-controller": api.String(), "secret": "test-only",
		"hosts":        map[string]string{"blocked.test": "192.0.2.2", "habr.test": "192.0.2.2", "ordinary.test": "192.0.2.2"},
		"proxies":      []interface{}{map[string]interface{}{"name": "Dead", "type": "http", "server": "127.0.0.1", "port": u.Port}},
		"proxy-groups": []interface{}{map[string]interface{}{"name": "General", "type": "select", "proxies": []string{"Dead"}}},
		"rules":        []string{"DOMAIN-SUFFIX,habr.test,DIRECT", "DOMAIN-SUFFIX,ordinary.test,General", "MATCH,General"}}
	b, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	write(config, b)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "-d", dir, "-f", config)
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	c := New(config, dir, xkeen.Runtime{XrayConfDir: filepath.Join(dir, "configs")}, func() []models.Server { return nil })
	c.validate = func(ctx context.Context, path string) error {
		msg, err := exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", path).CombinedOutput()
		if err != nil {
			t.Log(string(msg))
		}
		return err
	}
	p, err := c.read()
	if err != nil {
		t.Fatal(err)
	}
	for !p.api.ruleMode(ctx) {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err(), logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	on, off := true, false
	check := func(enabled *bool, force bool) RefilterStatus {
		s, err := c.UpdateRefilter(ctx, enabled, force)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := check(&on, false)
	if !s.Enabled || s.Domains != 4 || s.Prefixes != 1 {
		t.Fatal(s)
	}
	var providers struct {
		Providers map[string]struct{ RuleCount int }
	}
	if err := p.api.request(ctx, "GET", "/providers/rules", nil, &providers); err != nil || providers.Providers[refilterSites].RuleCount != 4 || providers.Providers[refilterIPs].RuleCount != 1 {
		t.Fatalf("providers: %+v, %v", providers, err)
	}
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer dst.Close()
	proxyURL, _ := url.Parse("http://" + proxy.String())
	hc := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}, Timeout: 2 * time.Second}
	assertDirect := func(host string, want bool) {
		t.Helper()
		res, err := hc.Get("http://" + host + ":" + portOf(dst.Listener.Addr()) + "/")
		usedProxy := err == nil && res.StatusCode == 204
		if err == nil {
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}
		if usedProxy == want {
			t.Fatalf("%s proxy=%t wantDirect=%t; err=%v", host, usedProxy, want, err)
		}
	}
	assertDirect("blocked.test", false)
	assertDirect("habr.test", true)
	assertDirect("ordinary.test", true)
	assertDirect("192.0.2.2", false)
	first, _ := os.ReadFile(config)
	if !strings.Contains(string(first), "MATCH,General") {
		t.Fatal("owner MATCH lost")
	}
	write(siteFile, []byte("invalid"))
	if _, err = c.UpdateRefilter(ctx, nil, true); err == nil {
		t.Fatal("accepted corrupt update")
	}
	after, _ := os.ReadFile(config)
	if string(after) != string(first) {
		t.Fatal("corrupt update changed profile")
	}
	assertDirect("blocked.test", false)
	assertDirect("ordinary.test", true)
	write(siteFile, file(domain("ordinary.test"), domain("habr.test")))
	check(nil, true)
	assertDirect("ordinary.test", false)
	assertDirect("blocked.test", true)
	assertDirect("habr.test", true)
	check(&off, false)
	assertDirect("ordinary.test", false)
	assertDirect("habr.test", true)
	restored, _ := c.read()
	for _, r := range list(restored.doc["rules"]) {
		if strings.Contains(str(r), "RULE-SET,XKP-refilter") {
			t.Fatal("rule provider remained active after disabling")
		}
	}
}

func TestRefilterDrainResumesAfterPanelRestartWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	token := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	cfg := filepath.Join(dir, "config.yaml")
	attempts, refuse := 0, true
	ctl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/configs":
			io.WriteString(w, `{"mode":"rule"}`)
		case "/rules":
			io.WriteString(w, `{"rules":[{"type":"DomainSuffix","payload":"habr.test","proxy":"DIRECT"},{"type":"Match","proxy":"XKP-card-default"}]}`)
		case "/connections":
			json.NewEncoder(w).Encode(map[string]any{"connections": []map[string]any{
				{"id": "needs-drain", "chains": []string{"OldVPN"}, "metadata": map[string]string{"host": "vpn.test"}},
				{"id": "stable-habr", "chains": []string{"DIRECT"}, "metadata": map[string]string{"host": "habr.test"}},
				{"id": "new-request", "chains": []string{"OldVPN"}, "start": time.Now().Add(time.Hour)},
			}})
		case "/connections/needs-drain":
			attempts++
			if refuse {
				http.Error(w, "unavailable", 503)
				return
			}
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer ctl.Close()
	base := map[string]any{"external-controller": strings.TrimPrefix(ctl.URL, "http://"), "secret": "fixture", "mode": "rule", "rules": []string{"DOMAIN-SUFFIX,habr.test,DIRECT", "MATCH," + cardPrefix + defaultID},
		refilterKey: refilterCache{Enabled: false, SiteHash: strings.Repeat("a", 64), IPHash: strings.Repeat("b", 64), Domains: 10, Prefixes: 1, DomainBehavior: "domain", DrainToken: token}}
	b, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg, b, 0600); err != nil {
		t.Fatal(err)
	}
	newController := func() *Controller { return New(cfg, dir, xkeen.Runtime{}, nil) }
	if _, err := newController().UpdateRefilter(context.Background(), nil, false); err == nil || attempts != 1 {
		t.Fatalf("first attempt %v, requests %d", err, attempts)
	}
	refuse = false
	off := false
	if _, err := newController().UpdateRefilter(context.Background(), &off, false); err != nil || attempts != 2 {
		t.Fatalf("retry %v, requests %d", err, attempts)
	}
	if _, err := newController().UpdateRefilter(context.Background(), nil, false); err != nil || attempts != 2 {
		t.Fatalf("retry after ack %v, requests %d", err, attempts)
	}
}
