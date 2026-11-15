package cardcontroller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func serviceListFixture(t *testing.T) map[string]interface{} {
	t.Helper()
	info := serviceListsCache{Version: serviceListsVersion, Enabled: true, UpdatedAt: "2026-01-01T00:00:00Z", CheckedAt: "2026-01-01T00:00:00Z", Files: map[string]serviceListFile{}}
	for id := range serviceListTags {
		info.Files[id] = serviceListFile{strings.Repeat("a", 64), 1}
	}
	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestServiceListStrictNormalization(t *testing.T) {
	file, err := normalizeServiceList([]byte("# upstream comment\r\n+.OpenAI.Com\r\napi.example.com\n+.openai.com\n+.youtube\n"))
	if err != nil || file.Count != 3 || file.Behavior != "domain" || string(file.Data) != "+.openai.com\n+.youtube\napi.example.com\n" {
		t.Fatalf("file=%+v err=%v", file, err)
	}
	for _, input := range []string{"", "# empty\n", "<html>temporarily unavailable</html>", "MATCH", "+.", "*", "regexp:.*", "domain:openai.com", "https://example.com", "*.example.com", "IP-CIDR,104.16.0.0/13", "+..com", "a..com", "-a.com", "a-.com", "a.com,DIRECT", "a\x00.com", strings.Repeat("a", 64) + ".com"} {
		if _, err := normalizeServiceList([]byte(input)); err == nil {
			t.Errorf("accepted unsupported upstream line %q", input)
		}
	}
}

func TestServiceListsMetadataRequiresWholeSnapshot(t *testing.T) {
	doc := map[string]interface{}{serviceListsKey: serviceListFixture(t)}
	if info, err := readServiceLists(doc); err != nil || !info.Enabled || len(info.Files) != len(serviceListTags) {
		t.Fatalf("%+v %v", info, err)
	}
	delete(object(object(doc[serviceListsKey])["files"]), "openai")
	if _, err := readServiceLists(doc); err == nil {
		t.Fatal("accepted missing critical service file")
	}
}

func TestServiceListRenderingPreservesPinnedCardsAndScopesDiscord(t *testing.T) {
	services := cardCatalogForTest(t)
	key := strings.Repeat("b", 64)
	peerName := nodePrefix + key
	p := profile{assigned: map[string]string{"openai": key, "claude": key, "ai": key, "google": key, "discord": key, "youtube": key}, doc: map[string]interface{}{
		serviceListsKey: serviceListFixture(t),
		"proxies":       []interface{}{map[string]interface{}{"name": "Base", "type": "http", "server": "127.0.0.1", "port": 1}},
		"proxy-groups":  []interface{}{map[string]interface{}{"name": "Discord", "type": "select", "proxies": []interface{}{"Base"}}},
		"rules":         []interface{}{"DOMAIN-SUFFIX,habr.test,DIRECT", "IP-CIDR,104.16.0.0/13,Discord,no-resolve", "MATCH,Base"},
	}}
	if err := configureDomainPolicy(p.doc, true); err != nil {
		t.Fatal(err)
	}
	wanted, err := render(&p, services, map[string]cardEndpoint{key: {name: peerName}}, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"openai", "claude", "ai", "google", "discord"} {
		if wanted[cardPrefix+id] != peerName || wanted[serviceGuardName(id)] != "REJECT" {
			t.Fatalf("assignment %s was changed: %v", id, wanted)
		}
	}
	rules := namesOf(p.doc["rules"])
	if len(rules) < 2 || !strings.Contains(rules[0], "DST-PORT,443") || !strings.HasSuffix(rules[0], quicGuardGroup) {
		t.Fatal("QUIC guard was not placed before service/direct rules", rules[:2])
	}
	for _, rule := range rules {
		if strings.HasPrefix(rule, "IP-CIDR,104.16.0.0/13,") {
			t.Fatal("unqualified shared CDN classifier survived", rule)
		}
	}
	voice := discordVoicePredicate("IP-CIDR,104.16.0.0/13,no-resolve")
	if !slices.Contains(rules, voice+","+cardPrefix+"discord") || !slices.Contains(rules, voice+",Discord") {
		t.Fatal("Discord voice constraints were not applied to both card and owner rules")
	}
	position := func(rule string) int { return slices.Index(rules, rule) }
	claude, openai, ai, google := position("RULE-SET,"+serviceProviderName("claude")+","+cardPrefix+"claude"), position("RULE-SET,"+serviceProviderName("openai")+","+cardPrefix+"openai"), position("RULE-SET,"+serviceProviderName("ai")+","+cardPrefix+"ai"), position("RULE-SET,"+serviceProviderName("google")+","+cardPrefix+"google")
	if claude < 0 || openai <= claude || ai <= openai || google <= ai {
		t.Fatalf("specific service priority is wrong: Claude=%d OpenAI=%d AI=%d Google=%d", claude, openai, ai, google)
	}
	for _, id := range []string{"claude", "openai", "ai"} {
		first := position("RULE-SET," + serviceProviderName(id) + "," + cardPrefix + id)
		if rules[first+1] != "RULE-SET,"+serviceProviderName(id)+","+serviceGuardName(id) {
			t.Fatal("dataset predicate can fall through without a service-specific guard", id)
		}
	}
	if !slices.Contains(rules, "DOMAIN,api.revenuecat.com,"+cardPrefix+"openai") {
		t.Fatal("shared purchases dependency has no explicit OpenAI policy")
	}
	before, _ := json.Marshal(p.doc)
	if err := json.Unmarshal(before, &p.doc); err != nil {
		t.Fatal(err)
	}
	if _, err := render(&p, services, map[string]cardEndpoint{key: {name: peerName}}, true); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(p.doc)
	if string(before) != string(after) {
		t.Fatal("service list rendering is not idempotent")
	}
}

func TestServiceListTransitionOnlyTouchesAffectedExternalFlows(t *testing.T) {
	known := map[string]bool{"+.owned.test": true, "shared.test": true}
	flow := func(host, ip, network, port string) connectionTracker {
		var f connectionTracker
		f.Metadata.Host, f.Metadata.DestinationIP, f.Metadata.Network, f.Metadata.DestinationPort = host, ip, network, port
		return f
	}
	for _, tc := range []struct {
		flow connectionTracker
		want bool
	}{
		{flow("", "104.18.39.85", "udp", "443"), true},
		{flow("ios.owned.test", "192.0.2.1", "tcp", "443"), true},
		{flow("shared.test", "192.0.2.1", "tcp", "443"), true},
		{flow("unknown.test", "192.0.2.1", "tcp", "443"), false},
		{flow("", "192.0.2.1", "udp", "50001"), false},
		{flow("shared.test", "192.168.1.1", "udp", "443"), false},
		{flow("", "fe80::1", "udp", "443"), false},
	} {
		if got := serviceListsFlowAffected(tc.flow, true, known); got != tc.want {
			t.Errorf("flow=%+v affected=%t want %t", tc.flow, got, tc.want)
		}
	}
}

type serviceListRoundTrip func(*http.Request) (*http.Response, error)

func (fn serviceListRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func TestServiceListsDownloadLeavesStatusResponsive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	base := []byte(`{"mode":"rule","external-controller":"127.0.0.1:1","secret":"synthetic","rules":["MATCH,DIRECT"]}`)
	if err := os.WriteFile(path, base, 0600); err != nil {
		t.Fatal(err)
	}
	c := New(path, dir, xkeen.Runtime{}, func() []models.Server { return nil })
	started := make(chan struct{})
	var once sync.Once
	c.http.Transport = serviceListRoundTrip(func(req *http.Request) (*http.Response, error) {
		once.Do(func() { close(started) })
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		on := true
		_, err := c.UpdateServiceLists(ctx, &on, false)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("download was not started")
	}
	read := make(chan ServiceListsStatus, 1)
	go func() {
		status, _ := c.ServiceListsStatus()
		read <- status
	}()
	select {
	case status := <-read:
		if !status.Updating || status.Enabled {
			t.Fatal("pending download published an active policy", status)
		}
	case <-time.After(time.Second):
		t.Fatal("public source outage blocks status reads")
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled source download was accepted")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(base) {
		t.Fatal("cancelled source download changed the active configuration")
	}
}

type serviceListTestTransport struct {
	fallback http.RoundTripper
	fail     atomic.Bool
}

func (t *serviceListTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == "raw.githubusercontent.com" {
		if t.fail.Load() {
			return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("upstream unavailable")), Header: http.Header{}}, nil
		}
		tag := strings.TrimSuffix(filepath.Base(r.URL.Path), ".list")
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("+." + strings.ReplaceAll(tag, "!", "") + ".fixture\n")), Header: http.Header{}}, nil
	}
	return t.fallback.RoundTrip(r)
}

// Real core acceptance verifies domain-provider counts, custom guard groups,
// rollback on failed refresh and actual absence of a direct HTTP fallback.
func TestServiceListsRealMihomoPolicyAndLastGoodCache(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("set MIHOMO_TEST_BINARY")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	apiServer := httptest.NewServer(http.NotFoundHandler())
	apiAddr := apiServer.Listener.Addr().String()
	apiServer.Close()
	proxyServer := httptest.NewServer(http.NotFoundHandler())
	proxyAddr := proxyServer.Listener.Addr().String()
	proxyServer.Close()
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	var directHits atomic.Int32
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer dest.Close()
	key := strings.Repeat("b", 64)
	base := map[string]interface{}{
		"mode": "rule", "external-controller": apiAddr, "secret": "test-only", "mixed-port": mustPort(t, proxyAddr),
		stateKey: map[string]string{"openai": key, "claude": key},
		"hosts":  map[string]string{"ios.openai.fixture": "127.0.0.1", "www.anthropic.fixture": "127.0.0.1"},
		"rules":  []string{"MATCH,DIRECT"},
	}
	raw, _ := json.Marshal(base)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "-d", dir, "-f", path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	c := New(path, dir, xkeen.Runtime{Core: xkeen.CoreMihomo, XrayConfDir: filepath.Join(dir, "configs")}, func() []models.Server { return nil })
	transport := &serviceListTestTransport{fallback: c.http.Transport}
	c.http.Transport = transport
	c.validate = func(ctx context.Context, path string) error {
		output, err := exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", path).CombinedOutput()
		if err != nil {
			t.Log(string(output))
		}
		return err
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
	on := true
	status, err := c.UpdateServiceLists(ctx, &on, false)
	if err != nil || !status.Enabled || status.Sources != len(serviceListTags) || status.Domains != len(serviceListTags) {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	p, err = c.read()
	if err != nil {
		t.Fatal(err)
	}
	if !p.api.serviceListsReady(ctx, p.doc) {
		t.Fatal("live providers do not match the installed snapshot")
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}, Timeout: time.Second}
	control, err := client.Get(dest.URL)
	if err != nil || control.StatusCode != http.StatusNoContent {
		t.Fatalf("the direct control destination is not reachable: %v", err)
	}
	control.Body.Close()
	baselineHits := directHits.Load()
	for _, host := range []string{"ios.openai.fixture", "www.anthropic.fixture"} {
		response, err := client.Get("http://" + host + ":" + portOf(dest.Listener.Addr()) + "/")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				t.Fatalf("protected service %s reached a direct destination", host)
			}
		}
	}
	if directHits.Load() != baselineHits {
		t.Fatal("protected requests leaked directly")
	}
	before, _ := os.ReadFile(path)
	transport.fail.Store(true)
	if _, err := c.UpdateServiceLists(ctx, nil, true); err == nil {
		t.Fatal("failed source refresh was accepted")
	}
	after, _ := os.ReadFile(path)
	if !reflect.DeepEqual(before, after) || !p.api.serviceListsReady(ctx, p.doc) {
		t.Fatal("source outage replaced the last working snapshot")
	}
	transport.fail.Store(false)
	priorValidate := c.validate
	c.validate = func(context.Context, string) error { return errors.New("rejected synthetic candidate") }
	off := false
	if _, err := c.UpdateServiceLists(ctx, &off, false); err == nil {
		t.Fatal("invalid reload was accepted")
	}
	c.validate = priorValidate
	after, _ = os.ReadFile(path)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("rejected config changed the installed profile")
	}
}

func mustPort(t *testing.T, addr string) int {
	t.Helper()
	u, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	if _, err := fmt.Sscanf(u.Port(), "%d", &n); err != nil {
		t.Fatal(err)
	}
	return n
}
