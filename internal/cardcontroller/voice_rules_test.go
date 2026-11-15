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
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"xkeen-panel/internal/geoip"
)

func voiceJSON(prefixes string) []byte {
	return []byte(`{"creationTime":"2026-01-01T00:00:00Z","prefixes":` + prefixes + `}`)
}

func TestOpenAIVoiceFeedStrictNormalization(t *testing.T) {
	file, err := normalizeOpenAIVoiceList(voiceJSON(`[{"ipv4Prefix":"198.51.100.7/24"},{"ipv4Prefix":"198.51.100.0/24"},{"ipv4Prefix":"203.0.113.9/32"},{"ipv6Prefix":"2001:db8::2/128"},{"ipv6Prefix":"2001:db8::2/128"}]`))
	if err != nil || file.Behavior != "ipcidr" || file.Count != 3 || string(file.Data) != "198.51.100.0/24\n2001:db8::2/128\n203.0.113.9/32\n" {
		t.Fatalf("normalized=%+v err=%v", file, err)
	}
	invalid := [][]byte{
		nil, []byte("<html>upstream error</html>"), []byte(`{`),
		[]byte(`{"prefixes":[{"ipv4Prefix":"198.51.100.1/32"}]}`),
		[]byte(`{"creationTime":"yesterday","prefixes":[{"ipv4Prefix":"198.51.100.1/32"}]}`),
		voiceJSON(`[]`), voiceJSON(`null`), voiceJSON(`[{}]`),
		voiceJSON(`[{"ipv4Prefix":"198.51.100.1"}]`),
		voiceJSON(`[{"ipv4Prefix":"not-an-ip/32"}]`),
		voiceJSON(`[{"ipv4Prefix":"127.0.0.1/32"}]`),
		voiceJSON(`[{"ipv4Prefix":"10.0.0.1/32"}]`),
		voiceJSON(`[{"ipv4Prefix":"192.168.1.1/32"}]`),
		voiceJSON(`[{"ipv4Prefix":"169.254.1.1/32"}]`),
		voiceJSON(`[{"ipv4Prefix":"224.0.0.1/32"}]`),
		voiceJSON(`[{"ipv4Prefix":"0.0.0.0/0"}]`),
		voiceJSON(`[{"ipv4Prefix":"1.0.0.0/7"}]`),
		voiceJSON(`[{"ipv6Prefix":"2001::/15"}]`),
		voiceJSON(`[{"ipv6Prefix":"fc00::1/128"}]`),
		voiceJSON(`[{"ipv6Prefix":"fe80::1/128"}]`),
		voiceJSON(`[{"ipv4Prefix":"2001:db8::1/128"}]`),
		voiceJSON(`[{"ipv6Prefix":"198.51.100.1/32"}]`),
		voiceJSON(`[{"ipv6Prefix":"::ffff:198.51.100.1/128"}]`),
		voiceJSON(`[{"cidr":"198.51.100.1/32"}]`),
		voiceJSON(`[{"ipv4Prefix":"198.51.100.1/32","ipv6Prefix":"2001:db8::1/128"}]`),
		append(voiceJSON(`[{"ipv4Prefix":"198.51.100.1/32"}]`), []byte(` {"extra":true}`)...),
		bytes.Repeat([]byte(" "), serviceListMaxBytes+1),
	}
	for i, input := range invalid {
		if _, err := normalizeOpenAIVoiceList(input); err == nil {
			t.Errorf("invalid input %d accepted", i)
		}
	}
}

func TestVoiceUpgradeKeepsLegacyCacheReadable(t *testing.T) {
	metadata := serviceListFixture(t)
	delete(object(metadata["files"]), openAIVoiceListID)
	doc := map[string]interface{}{serviceListsKey: metadata}
	info, err := readServiceLists(doc)
	if err != nil || info.status("").Ready || info.status("").VoicePrefixes != 0 {
		t.Fatal("legacy cache became unreadable or falsely advertised voice coverage", info, err)
	}
	p := profile{doc: map[string]interface{}{
		serviceListsKey: metadata,
		"rules":         []interface{}{"MATCH,DIRECT"},
	}, assigned: map[string]string{"openai": strings.Repeat("a", 64)}}
	if _, err := render(&p, cardCatalogForTest(t), nil, true); err != nil {
		t.Fatal(err)
	}
	for _, rule := range namesOf(p.doc["rules"]) {
		if strings.Contains(rule, "RULE-SET,"+serviceProviderName(openAIVoiceListID)+",") {
			t.Fatal("legacy render referenced a missing voice provider", rule)
		}
	}
	delete(object(metadata["files"]), "openai")
	if _, err := readServiceLists(map[string]interface{}{serviceListsKey: metadata}); err == nil {
		t.Fatal("an incomplete original domain snapshot was accepted")
	}
}

func TestVoiceRulesFollowSeparateCardsAndRetainTerminalGuards(t *testing.T) {
	openai, claude := strings.Repeat("a", 64), strings.Repeat("b", 64)
	p := profile{doc: map[string]interface{}{
		serviceListsKey: serviceListFixture(t),
		"rules":         []interface{}{"MATCH,DIRECT"},
	}, assigned: map[string]string{"openai": openai, "claude": claude}}
	wanted, err := render(&p, cardCatalogForTest(t), map[string]cardEndpoint{
		openai: {name: nodePrefix + openai}, claude: {name: nodePrefix + claude},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if wanted[cardPrefix+"openai"] != nodePrefix+openai || wanted[cardPrefix+"claude"] != nodePrefix+claude {
		t.Fatal("voice cards lost their distinct selected endpoints", wanted)
	}
	rules := namesOf(p.doc["rules"])
	for _, pair := range [][2]string{
		{"RULE-SET," + serviceProviderName(openAIVoiceListID) + "," + cardPrefix + "openai,no-resolve", "RULE-SET," + serviceProviderName(openAIVoiceListID) + "," + serviceGuardName("openai") + ",no-resolve"},
		{"IP-CIDR,34.186.249.240/32," + cardPrefix + "claude,no-resolve", "IP-CIDR,34.186.249.240/32," + serviceGuardName("claude") + ",no-resolve"},
	} {
		at := slices.Index(rules, pair[0])
		if at < 0 || at+1 >= len(rules) || rules[at+1] != pair[1] {
			t.Fatalf("voice predicate has no immediate terminal guard: %v", pair)
		}
	}
	providers := object(p.doc["rule-providers"])
	if object(providers[serviceProviderName(openAIVoiceListID)])["behavior"] != "ipcidr" || object(providers[serviceProviderName("openai")])["behavior"] != "domain" {
		t.Fatal("voice and domain providers have the wrong behavior", providers)
	}
	for _, id := range []string{"openai", "claude"} {
		if wanted[serviceGuardName(id)] != "REJECT" {
			t.Fatal("voice guard permits a direct fallback", id, wanted)
		}
	}
}

func TestVoiceTransitionFindsIPOnlyConnections(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8::/64"), netip.MustParsePrefix("34.186.249.240/32")}
	flow := func(ip, network, port string) connectionTracker {
		var f connectionTracker
		f.Metadata.DestinationIP, f.Metadata.Network, f.Metadata.DestinationPort = ip, network, port
		return f
	}
	for _, tc := range []struct {
		flow connectionTracker
		want bool
	}{
		{flow("198.51.100.7", "udp", "3478"), true},
		{flow("198.51.100.7", "tcp", "443"), true},
		{flow("::ffff:198.51.100.7", "tcp", "443"), true},
		{flow("2001:db8::9", "tcp", "443"), true},
		{flow("34.186.249.240", "tcp", "443"), true},
		{flow("198.51.101.7", "tcp", "443"), false},
		{flow("34.186.249.241", "tcp", "443"), false},
		{flow("192.168.1.1", "tcp", "443"), false},
	} {
		if got := serviceListsFlowAffected(tc.flow, true, map[string]bool{}, prefixes...); got != tc.want {
			t.Errorf("flow=%+v affected=%t want=%t", tc.flow, got, tc.want)
		}
	}
	dedicated := flow("198.51.100.7", "tcp", "443")
	dedicated.Metadata.InboundName = serviceInbound("openai")
	dedicated.Chains = []string{dedicatedGroup("openai")}
	if serviceListsFlowAffected(dedicated, true, map[string]bool{}, prefixes...) {
		t.Fatal("an explicitly tagged whole-application proxy was interrupted")
	}
}

// This snapshot intentionally includes loopback in an isolated synthetic IP
// provider, to make a DIRECT leak observable without any external connection.
// Production JSON normalization rejects loopback, as tested above.
func voiceSnapshotFixture(t *testing.T, dir string) map[string]interface{} {
	t.Helper()
	info := serviceListsCache{Version: serviceListsVersion, Enabled: true, UpdatedAt: "2026-01-01T00:00:00Z", CheckedAt: "2026-01-01T00:00:00Z", Files: map[string]serviceListFile{}}
	for id := range serviceListTags {
		file := geoip.RuleFile{Data: []byte("+." + strings.ReplaceAll(id, "!", "") + ".fixture\n"), Count: 1, Behavior: "domain"}
		if id == openAIVoiceListID {
			file = geoip.RuleFile{Data: []byte("127.0.0.1/32\n198.51.100.10/32\n"), Count: 2, Behavior: "ipcidr"}
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

func TestVoiceRealMihomoCardExitsAndNoDirectFallback(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("set MIHOMO_TEST_BINARY")
	}
	dir := t.TempDir()
	var directHits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits.Add(1)
		w.Header().Set("X-Voice-Exit", "direct")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	newExit := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				w.WriteHeader(http.StatusBadRequest)
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
				_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\nX-Voice-Exit: "+name+"\r\nConnection: close\r\n\r\n")
			}
		}))
	}
	exitA, exitB := newExit("A"), newExit("B")
	defer exitA.Close()
	defer exitB.Close()
	freeAddr := func() string {
		t.Helper()
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := listener.Addr().String()
		listener.Close()
		return addr
	}
	proxyAddr, apiAddr := freeAddr(), freeAddr()
	keyA, keyB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	p := profile{assigned: map[string]string{"openai": keyA, "claude": keyB}, doc: map[string]interface{}{
		"mode": "rule", "mixed-port": mustPort(t, proxyAddr), "bind-address": "127.0.0.1", "allow-lan": false, "ipv6": false,
		"external-controller": apiAddr, "secret": "synthetic-voice",
		"proxies": []interface{}{}, "hosts": map[string]string{"direct-control.fixture": "127.0.0.1"},
		serviceListsKey: voiceSnapshotFixture(t, dir),
		"rules":         []interface{}{"DOMAIN,direct-control.fixture,DIRECT", "MATCH,DIRECT"},
	}}
	path := filepath.Join(dir, "config.yaml")
	writeConfig := func() {
		t.Helper()
		if _, err := render(&p, cardCatalogForTest(t), map[string]cardEndpoint{keyA: {name: nodePrefix + keyA}, keyB: {name: nodePrefix + keyB}}, true); err != nil {
			t.Fatal(err)
		}
		for i, raw := range list(p.doc["proxies"]) {
			name := str(object(raw)["name"])
			var port int
			switch name {
			case nodePrefix + keyA:
				port = mustPort(t, exitA.Listener.Addr().String())
			case nodePrefix + keyB:
				port = mustPort(t, exitB.Listener.Addr().String())
			default:
				continue
			}
			list(p.doc["proxies"])[i] = map[string]interface{}{"name": name, "type": "http", "server": "127.0.0.1", "port": port}
		}
		body, err := json.Marshal(p.doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		// A real transaction rereads the serialized profile before rendering.
		if err := json.Unmarshal(body, &p.doc); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	api := coreAPI{base: "http://" + apiAddr, secret: "synthetic-voice", client: &http.Client{Timeout: time.Second}}
	for !api.ruleMode(ctx) || !api.serviceListsReady(ctx, p.doc) {
		if ctx.Err() != nil {
			t.Fatal("isolated voice core did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}, Timeout: 2 * time.Second}
	check := func(address, expected string) {
		t.Helper()
		response, err := client.Get("http://" + address + "/")
		if response != nil {
			defer response.Body.Close()
		}
		if expected == "blocked" {
			if err == nil && response.StatusCode == http.StatusNoContent {
				t.Fatal("voice request succeeded after its selected exit stopped", address, response.Header)
			}
			return
		}
		if err != nil || response.StatusCode != http.StatusNoContent || response.Header.Get("X-Voice-Exit") != expected {
			t.Fatalf("address=%s expected exit=%s response=%v err=%v", address, expected, response, err)
		}
	}
	check("198.51.100.10:443", "A")
	check("34.186.249.240:443", "B")
	check("direct-control.fixture:"+portOf(destination.Listener.Addr()), "direct")
	p.assigned["openai"], p.assigned["claude"] = keyB, keyA
	writeConfig()
	if err := api.reload(ctx, path); err != nil {
		t.Fatal(err)
	}
	check("198.51.100.10:443", "B")
	check("34.186.249.240:443", "A")
	// The local IP belongs to the synthetic voice provider. A fallback to
	// DIRECT would reach destination and increment directHits.
	check(destination.Listener.Addr().String(), "B")
	exitB.Close()
	check(destination.Listener.Addr().String(), "blocked")
	check("34.186.249.240:443", "A")
	check("direct-control.fixture:"+portOf(destination.Listener.Addr()), "direct")
	got := directHits.Load()
	if got != 2 {
		t.Fatal("voice leaked directly or ordinary DIRECT broke", got)
	}
}
