package cardcontroller

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func analyticsSnapshot(t *testing.T, dir string) map[string]interface{} {
	t.Helper()
	info := serviceListsCache{Version: serviceListsVersion, Enabled: true, UpdatedAt: "2026-01-01T00:00:00Z", CheckedAt: "2026-01-01T00:00:00Z", Files: map[string]serviceListFile{}}
	for id, tag := range serviceListTags {
		data := "+." + strings.ReplaceAll(tag, "!", "") + ".fixture\n"
		if id == "analytics" {
			data = "collector.anthropic.fixture\n+.collector.fixture\n"
		}
		file, err := normalizeServiceList([]byte(data))
		if id == openAIVoiceListID {
			file, err = normalizeOpenAIVoiceList([]byte(`{"creationTime":"2026-01-01T00:00:00Z","prefixes":[{"ipv4Prefix":"198.51.100.1/32"}]}`))
		}
		if err != nil {
			t.Fatal(err)
		}
		hash, err := saveRuleFile(dir, serviceProviderName(id), file)
		if err != nil {
			t.Fatal(err)
		}
		info.Files[id] = serviceListFile{hash, file.Count}
	}
	raw, _ := json.Marshal(info)
	var metadata map[string]interface{}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		t.Fatal(err)
	}
	return metadata
}

func TestAnalyticsLegacyCacheSurvivesMissingNewDatasetAndSourceOutage(t *testing.T) {
	metadata := serviceListFixture(t)
	delete(object(metadata["files"]), "analytics")
	base := map[string]interface{}{"mode": "rule", "external-controller": "127.0.0.1:1", "secret": "fixture", "rules": []interface{}{"MATCH,DIRECT"}, serviceListsKey: metadata}
	info, err := readServiceLists(base)
	if err != nil || len(info.Files) != len(serviceListTags)-1 || info.status("").Ready {
		t.Fatal("the previous complete cache must remain readable during upgrade", info, err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw, _ := json.Marshal(base)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	c := New(path, dir, xkeen.Runtime{}, func() []models.Server { return nil })
	transport := &serviceListTestTransport{}
	transport.fail.Store(true)
	c.http.Transport = transport
	if status, err := c.EnsureServiceLists(context.Background()); err == nil || status.Ready {
		t.Fatal("an unavailable new dataset was advertised as ready", status, err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(raw, after) {
		t.Fatal("upgrade source failure replaced the old working profile")
	}
	if _, err := c.read(); err != nil {
		t.Fatal("working routes became unreadable during upgrade", err)
	}
	services := cardCatalogForTest(t)
	key := strings.Repeat("a", 64)
	p := profile{doc: base, assigned: map[string]string{"analytics": key}}
	if _, err := render(&p, services, nil, true); err != nil {
		t.Fatal(err)
	}
	for _, rule := range namesOf(p.doc["rules"]) {
		if strings.Contains(rule, "RULE-SET,"+serviceProviderName("analytics")) {
			t.Fatal("legacy render referenced a provider that has not been downloaded")
		}
	}
	if !slices.Contains(namesOf(p.doc["rules"]), "DOMAIN,api3.siftscience.com,"+cardPrefix+"analytics") {
		t.Fatal("known collector protection disappeared during source outage")
	}
}

func TestAnalyticsDrainsOnlyDisplacedCollectorsAndKeepsDedicatedProxy(t *testing.T) {
	dir := t.TempDir()
	var closed []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			closed = append(closed, strings.TrimPrefix(r.URL.Path, "/connections/"))
			w.WriteHeader(204)
			return
		}
		type row = map[string]interface{}
		flow := func(id, host, rule, payload, inbound string, chains ...string) row {
			ip := ""
			if id == "old-listed" {
				// The domain rule is earlier than Claude's network classifier.
				ip = "160.79.104.10"
			}
			return row{"id": id, "metadata": row{"host": host, "inboundName": inbound, "destinationIP": ip}, "rule": rule, "rulePayload": payload, "chains": chains}
		}
		json.NewEncoder(w).Encode(row{"connections": []row{
			flow("old-sift", "api3.siftscience.com", "Match", "", "", "OldPool", cardPrefix+defaultID),
			flow("old-listed", "collector.anthropic.fixture", "RuleSet", serviceProviderName("claude"), "", "OldPool", cardPrefix+"claude"),
			flow("old-suffix", "child.collector.fixture", "Match", "", "", "OldPool"),
			flow("already-correct", "api3.siftscience.com", "Domain", "api3.siftscience.com", "", "AnalyticsExit", cardPrefix+"analytics"),
			flow("explicit-direct", "allowed.collector.fixture", "DomainSuffix", "allowed.collector.fixture", "", "DIRECT"),
			flow("dedicated-openai", "api3.siftscience.com", "InName", serviceInbound("openai"), serviceInbound("openai"), "OtherAppExit", dedicatedGroup("openai")),
			flow("ordinary", "normal.fixture", "Match", "", "", "OldPool"),
			flow("not-a-collector", "child.api3.siftscience.com", "Match", "", "", "OldPool"),
		}})
	}))
	defer server.Close()
	p := profile{api: coreAPI{base: server.URL, client: server.Client()}, assigned: map[string]string{"analytics": strings.Repeat("a", 64)}, doc: map[string]interface{}{
		serviceListsKey: analyticsSnapshot(t, dir),
		"rules":         []interface{}{"DOMAIN-SUFFIX,allowed.collector.fixture,DIRECT", "MATCH,DIRECT"},
	}}
	c := &Controller{path: filepath.Join(dir, "config.yaml")}
	failed := c.drainChanged(context.Background(), p, map[string]string{"analytics": "AnalyticsExit"}, cardCatalogForTest(t))
	if len(failed) != 0 || !slices.Equal(closed, []string{"old-sift", "old-listed", "old-suffix"}) {
		t.Fatal("collector route transition touched the wrong connections", closed, failed)
	}
}

func TestServiceListsKeepCorrectDedicatedApplicationConnections(t *testing.T) {
	var flow connectionTracker
	flow.Metadata.Host, flow.Metadata.InboundName = "api3.siftscience.com", serviceInbound("claude")
	flow.Metadata.Network, flow.Metadata.DestinationPort = "tcp", "443"
	flow.Chains = []string{"PrivateExit", dedicatedGroup("claude")}
	known := map[string]bool{"api3.siftscience.com": true}
	if serviceListsFlowAffected(flow, true, known) {
		t.Fatal("dataset refresh would disconnect an unchanged dedicated app proxy")
	}
	flow.Chains = []string{"OldExit", cardPrefix + "claude"}
	if !serviceListsFlowAffected(flow, true, known) {
		t.Fatal("legacy classifier connection would survive the new analytics policy")
	}
}

func TestAnalyticsRealMihomoCollectorPriorityExceptionsAndNoDirectFallback(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("set MIHOMO_TEST_BINARY")
	}
	dir := t.TempDir()
	var directHits, proxyHits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { directHits.Add(1); w.WriteHeader(204) }))
	defer destination.Close()
	transport := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		if r.Method != http.MethodConnect {
			w.WriteHeader(204)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = rw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		_ = rw.Flush()
		if request, err := http.ReadRequest(bufio.NewReader(conn)); err == nil {
			request.Body.Close()
			_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
		}
	}))
	defer transport.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := listener.Addr().String()
	listener.Close()
	controller := httptest.NewServer(http.NotFoundHandler())
	controllerAddr := controller.Listener.Addr().String()
	controller.Close()
	key := strings.Repeat("a", 64)
	hosts := map[string]string{"collector.anthropic.fixture": "127.0.0.1", "allowed.collector.fixture": "127.0.0.1", "ordinary.fixture": "127.0.0.1"}
	for _, host := range xkeen.AnalyticsHosts() {
		hosts[host] = "127.0.0.1"
	}
	p := profile{assigned: map[string]string{"analytics": key, "claude": strings.Repeat("b", 64)}, doc: map[string]interface{}{
		"mode": "rule", "mixed-port": mustPort(t, proxyAddr), "bind-address": "127.0.0.1", "allow-lan": false, "ipv6": false,
		"external-controller": controllerAddr, "secret": "synthetic-analytics",
		"proxies": []interface{}{},
		"hosts":   hosts, serviceListsKey: analyticsSnapshot(t, dir),
		"rules": []interface{}{"DOMAIN-SUFFIX,allowed.collector.fixture,DIRECT", "MATCH,DIRECT"},
	}}
	if _, err := render(&p, cardCatalogForTest(t), map[string]cardEndpoint{key: {name: nodePrefix + key}}, true); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(p.doc)
	if err := json.Unmarshal(before, &p.doc); err != nil {
		t.Fatal(err)
	}
	if _, err := render(&p, cardCatalogForTest(t), map[string]cardEndpoint{key: {name: nodePrefix + key}}, true); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(p.doc)
	if !reflect.DeepEqual(before, after) {
		var prior, next map[string]interface{}
		_ = json.Unmarshal(before, &prior)
		_ = json.Unmarshal(after, &next)
		for field, value := range next {
			if !reflect.DeepEqual(prior[field], value) {
				t.Logf("changed %s: before=%v after=%v", field, prior[field], value)
			}
		}
		t.Fatal("analytics rules are not idempotent")
	}
	// Replace the isolated worker transport with a loopback HTTP fixture. All
	// rule ordering and guards are production output; no external server is used.
	for i, raw := range list(p.doc["proxies"]) {
		if str(object(raw)["name"]) == nodePrefix+key {
			list(p.doc["proxies"])[i] = map[string]interface{}{"name": nodePrefix + key, "type": "http", "server": "127.0.0.1", "port": mustPort(t, transport.Listener.Addr().String())}
		}
	}
	finalBody, _ := json.Marshal(p.doc)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, finalBody, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "-d", dir, "-f", path)
	var coreLog bytes.Buffer
	cmd.Stdout, cmd.Stderr = &coreLog, &coreLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Log(coreLog.String())
		}
	}()
	api := coreAPI{base: "http://" + controllerAddr, secret: "synthetic-analytics", client: &http.Client{Timeout: time.Second}}
	for {
		probe, err := net.DialTimeout("tcp4", proxyAddr, 100*time.Millisecond)
		if err == nil {
			probe.Close()
			if api.ruleMode(ctx) && api.serviceListsReady(ctx, p.doc) {
				break
			}
		}
		if ctx.Err() != nil {
			t.Fatal("isolated core did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}, Timeout: 2 * time.Second}
	check := func(host string, allowed bool) {
		t.Helper()
		response, err := client.Get("http://" + host + ":" + portOf(destination.Listener.Addr()) + "/")
		if allowed {
			if err != nil || response.StatusCode != 204 {
				t.Fatal(host, err)
			}
		} else if err == nil && response.StatusCode == 204 {
			t.Fatal("collector escaped after its proxy stopped", host)
		}
		if response != nil {
			response.Body.Close()
		}
	}
	for _, host := range append(xkeen.AnalyticsHosts(), "collector.anthropic.fixture") {
		check(host, true)
	}
	if directHits.Load() != 0 || proxyHits.Load() != 5 {
		t.Fatal("collector did not use analytics transport", directHits.Load(), proxyHits.Load())
	}
	check("allowed.collector.fixture", true)
	check("ordinary.fixture", true)
	if directHits.Load() != 2 {
		t.Fatal("explicit direct exception or ordinary internet broke")
	}
	transport.Close()
	check("api3.siftscience.com", false)
	if directHits.Load() != 2 {
		t.Fatal("failed analytics proxy fell back to DIRECT")
	}
}
