package cardcontroller

import (
	"bufio"
	"bytes"
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
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestKillSwitchRealMihomoPolicy(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("set MIHOMO_TEST_BINARY")
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
	var hits atomic.Int32
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "received-direct")
	}))
	defer dest.Close()
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer health.Close()
	api, client, dead := port(), port(), port()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := map[string]interface{}{
		"mode": "rule", "mixed-port": client.Port, "external-controller": api.String(), "secret": "fixture-password",
		"proxies": []interface{}{map[string]interface{}{"type": "http", "name": "Dead", "server": "127.0.0.1", "port": dead.Port}},
		"proxy-groups": []interface{}{
			map[string]interface{}{"type": "fallback", "name": "Inner", "proxies": []string{"Dead", "DIRECT"}, "url": health.URL, "interval": 60, "lazy": false},
			map[string]interface{}{"type": "url-test", "name": "Outer", "proxies": []string{"Inner"}, "url": health.URL, "interval": 60},
			map[string]interface{}{"type": "select", "name": "ChatGPT", "proxies": []string{"Outer", "DIRECT"}},
		},
		"rules": []string{"DST-PORT," + portOf(dest.Listener.Addr()) + ",ChatGPT", "MATCH,DIRECT"},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, core, "-d", dir, "-f", path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	c := New(path, dir, xkeen.Runtime{Core: xkeen.CoreMihomo}, func() []models.Server { return nil })
	c.probeURL = health.URL
	c.validate = func(ctx context.Context, path string) error {
		return exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", path).Run()
	}
	p, err := c.read()
	if err != nil {
		t.Fatal(err)
	}
	for !p.api.ruleMode(ctx) {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(20 * time.Millisecond)
	}
	proxy, _ := url.Parse("http://" + client.String())
	tr := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: time.Second}
	received := func() bool {
		response, err := hc.Get(dest.URL)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		return string(raw) == "received-direct"
	}
	desired := true
	set := func(flag *bool, id, mode string) {
		t.Helper()
		if _, err := c.SetKillSwitch(ctx, flag, id, mode); err != nil {
			t.Fatal(err)
		}
	}
	waitDirect := func() {
		t.Helper()
		deadline := time.Now().Add(6 * time.Second)
		for !received() {
			if time.Now().After(deadline) {
				t.Fatal("direct fallback did not deliver")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	reject := func() {
		t.Helper()
		before := hits.Load()
		if received() || hits.Load() != before {
			t.Fatal("protected request reached the direct destination")
		}
	}
	set(&desired, "", "")
	live, err := p.api.selectors(ctx)
	if err != nil || strings.Join(live["Inner"].All, ",") != "Dead" {
		t.Fatalf("unsafe automatic members: %+v %v", live["Inner"], err)
	}
	reject()
	if err := p.api.request(ctx, "PUT", "/proxies/ChatGPT", map[string]string{"name": "DIRECT"}, nil); err != nil {
		t.Fatal(err)
	}
	waitDirect()
	if err := p.api.request(ctx, "PUT", "/proxies/ChatGPT", map[string]string{"name": "Outer"}, nil); err != nil {
		t.Fatal(err)
	}
	reject()
	set(nil, "openai", "off")
	waitDirect()
	if c.CheckCoreInterruption() == nil {
		t.Fatal("global protection allowed removal of interception")
	}
	set(nil, "openai", "on")
	reject()
	desired = false
	set(&desired, "", "")
	reject()
	if c.CheckCoreInterruption() == nil {
		t.Fatal("service override allowed removal of interception")
	}
	set(nil, "openai", "inherit")
	waitDirect()
	if err := c.CheckCoreInterruption(); err != nil {
		t.Fatal(err)
	}
	// A CONNECT remains live across a config reload on several Mihomo builds.
	// Once protection returns, the old connection must stop delivering bytes.
	tunnel, err := net.DialTimeout("tcp4", client.String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	dst := dest.Listener.Addr().String()
	fmt.Fprintf(tunnel, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dst, dst)
	reader := bufio.NewReader(tunnel)
	_ = tunnel.SetDeadline(time.Now().Add(3 * time.Second))
	reply, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || reply.StatusCode != 200 {
		t.Fatal("CONNECT", err)
	}
	// Establish the outbound before tightening. A CONNECT 200 can precede dial.
	fmt.Fprintf(tunnel, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", dst)
	reply, err = http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, reply.Body)
	reply.Body.Close()
	desired = true
	set(&desired, "", "")
	reject()
	before := hits.Load()
	_ = tunnel.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprintf(tunnel, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", dst)
	if _, err = http.ReadResponse(reader, &http.Request{Method: "GET"}); err == nil || hits.Load() != before {
		t.Fatal("preexisting DIRECT connection survived rearming")
	}
}

func TestKillSwitchRefilterConditionalRuleIsAccepted(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("set MIHOMO_TEST_BINARY")
	}
	hash := strings.Repeat("a", 64)
	doc := map[string]interface{}{
		"mode":         "rule",
		"proxies":      []interface{}{map[string]interface{}{"name": "FixtureVPN", "type": "http", "server": "127.0.0.1", "port": 1}},
		"rules":        []interface{}{"IP-CIDR,203.0.113.0/25,ChatGPT,no-resolve", "MATCH,FixtureVPN"},
		"proxy-groups": []interface{}{map[string]interface{}{"name": "ChatGPT", "type": "select", "proxies": []string{"FixtureVPN"}}},
		refilterKey:    map[string]interface{}{"enabled": true, "domain_behavior": "domain", "site_hash": hash, "ip_hash": hash, "domains": 1, "prefixes": 1},
		killSwitchKey:  map[string]interface{}{"enabled": true, "services": map[string]interface{}{"openai": "off"}},
	}
	p := profile{doc: doc, assigned: map[string]string{}}
	card := xkeen.ServiceRouteView{RoutingService: xkeen.RoutingService{ID: "openai", Domains: []string{"domain:example.invalid"}}}
	if _, err := render(&p, []xkeen.ServiceRouteView{card}, nil, true); err != nil {
		t.Fatal(err)
	}
	rules := namesOf(doc["rules"])
	dst := cardPrefix + "openai-inherited"
	domain := slices.Index(rules, "AND,((DOMAIN-SUFFIX,example.invalid),(RULE-SET,"+refilterSites+")),"+dst)
	noDomain := slices.Index(rules, "DOMAIN-REGEX,.+,"+cardPrefix+"direct")
	ip := slices.Index(rules, "AND,((IP-CIDR,203.0.113.0/25,no-resolve),(RULE-SET,"+refilterIPs+")),"+dst)
	if domain < 0 || noDomain <= domain || ip <= noDomain {
		t.Fatal("conditional rules missed the service or overrode named direct traffic")
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, contents := range map[string]string{refilterSites: "+.example.invalid\n", refilterIPs: "203.0.113.0/24\n"} {
		if err := os.WriteFile(filepath.Join(dir, refilterPath(name, hash)), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(core, "-t", "-d", dir, "-f", path).CombinedOutput()
	if err != nil || bytes.Contains(output, []byte("error")) {
		t.Fatalf("conditional routing rule rejected: %s", output)
	}
}
