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
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func protectedModeFixture(t *testing.T) map[string]interface{} {
	t.Helper()
	raw, _ := json.Marshal(protectedRoutingState{Version: 1, DrainToken: time.Now().UTC().Format(time.RFC3339Nano)})
	var result map[string]interface{}
	_ = json.Unmarshal(raw, &result)
	return result
}

func TestProtectedRoutingCanonicalFallbackPrecedesForeignDirectAliases(t *testing.T) {
	key := strings.Repeat("b", 64)
	p := profile{assigned: map[string]string{defaultID: allPoolID, "openai": key, "steam": directTarget}, doc: map[string]interface{}{
		protectedRoutingKey: protectedModeFixture(t),
		"proxies":           []interface{}{map[string]interface{}{"name": "Base", "type": "http", "server": "127.0.0.1", "port": 1}},
		"proxy-groups":      []interface{}{map[string]interface{}{"name": "Bypass", "type": "select", "proxies": []string{"DIRECT"}}, map[string]interface{}{"name": "OwnerBlock", "type": "select", "proxies": []string{"REJECT"}}},
		"rules":             []interface{}{"DOMAIN-REGEX,.+,Bypass", "IP-CIDR,0.0.0.0/0,DIRECT,no-resolve", "DOMAIN-SUFFIX,habr.fixture,DIRECT", "GEOSITE,category-ru,DIRECT", "DOMAIN-SUFFIX,blocked.fixture,OwnerBlock", "MATCH,Bypass"},
	}}
	peers := map[string]cardEndpoint{key: {name: nodePrefix + key}, allPoolID: {name: nodePrefix + allPoolID + "-member"}}
	beforeAssignments, _ := json.Marshal(p.assigned)
	expected, err := render(&p, cardCatalogForTest(t), peers, true)
	if err != nil {
		t.Fatal(err)
	}
	rules := namesOf(p.doc["rules"])
	match := slices.Index(rules, "MATCH,"+cardPrefix+defaultID)
	if match < 0 || rules[match+1] != "MATCH,"+serviceGuardName(defaultID) || expected[serviceGuardName(defaultID)] != "REJECT" {
		t.Fatal("canonical VPN fallback is not followed by its guard")
	}
	for _, preserved := range []string{"DOMAIN-REGEX,.+,Bypass", "IP-CIDR,0.0.0.0/0,DIRECT,no-resolve", "MATCH,Bypass"} {
		if slices.Index(rules, preserved) <= match {
			t.Fatal("a broad foreign bypass survived before the protected fallback", preserved)
		}
	}
	if i := slices.Index(rules, "DOMAIN-SUFFIX,habr.fixture,"+cardPrefix+"direct"); i < 0 || i > match {
		t.Fatal("named DIRECT exemption after the old head was lost")
	}
	if i := slices.Index(rules, "GEOSITE,category-ru,"+cardPrefix+"direct"); i < 0 || i > match {
		t.Fatal("explicit Russian category exemption was lost")
	}
	blocked := false
	for _, rule := range rules[:match] {
		if strings.HasPrefix(rule, "DOMAIN-SUFFIX,blocked.fixture,"+cardPrefix+"protected-owner-") {
			blocked = true
		}
	}
	if !blocked || expected[cardPrefix+"openai"] != nodePrefix+key || expected[cardPrefix+"steam"] != "DIRECT" {
		t.Fatal("explicit card or owner block was changed")
	}
	afterAssignments, _ := json.Marshal(p.assigned)
	if !bytes.Equal(beforeAssignments, afterAssignments) {
		t.Fatal("canonical rendering changed card destinations")
	}
	before, _ := json.Marshal(p.doc)
	if err := json.Unmarshal(before, &p.doc); err != nil {
		t.Fatal(err)
	}
	if _, err := render(&p, cardCatalogForTest(t), peers, true); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(p.doc)
	if !bytes.Equal(before, after) {
		t.Fatal("canonical owner rules multiplied on reconcile")
	}
}

func TestProtectedRoutingRejectsExplicitAllNetworkExclusion(t *testing.T) {
	entry, err := xkeen.NormalizeExclusion("0.0.0.0/0", "explicit all-network bypass")
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]interface{}{exclusionKey: xkeen.Exclusions{Entries: []xkeen.Exclusion{entry}}}
	if err := validateProtectedExclusions(doc); err == nil {
		t.Fatal("an explicit bypass for every address was silently overwritten")
	}
}

func TestRoutingStatusDoesNotCallAnUnverifiedProviderProtected(t *testing.T) {
	p := profile{assigned: map[string]string{defaultID: allPoolID}, doc: map[string]interface{}{
		"proxy-groups": []interface{}{map[string]interface{}{"name": "Bypass", "type": "select", "proxies": []string{"DIRECT"}}},
		"rules":        []interface{}{"DOMAIN-REGEX,.+,Bypass", "MATCH," + cardPrefix + defaultID},
	}}
	if s := routingStatus(p, RefilterStatus{}); s.Mode != "custom" || s.ProtectedFallback {
		t.Fatal("a broad alias bypass was called protected", s)
	}
	for _, rules := range [][]interface{}{{"DOMAIN-SUFFIX,habr.fixture,DIRECT", "MATCH,DIRECT"}, {"DOMAIN-SUFFIX,habr.fixture,DIRECT"}} {
		p.doc["rules"] = rules
		if s := routingStatus(p, RefilterStatus{}); s.Mode != "custom" || s.ProtectedFallback {
			t.Fatal("saved assignments without a managed fallback were called protected", s)
		}
	}
	p.doc["rules"] = []interface{}{"DOMAIN-SUFFIX,habr.fixture,DIRECT", "MATCH," + cardPrefix + defaultID}
	if s := routingStatus(p, RefilterStatus{}); s.Mode != "protected" || !s.ProtectedFallback {
		t.Fatal("an existing managed VPN fallback was not recognized", s)
	}
	p.doc[killSwitchKey] = map[string]interface{}{"enabled": false, "services": map[string]interface{}{}}
	if s := routingStatus(p, RefilterStatus{}); s.Mode != "custom" || s.ProtectedFallback {
		t.Fatal("disabled global protection was reported as a guarded fallback", s)
	}
}

func TestProtectedRoutingDrainKeepsCardsExceptionsAndNewFlows(t *testing.T) {
	dir := t.TempDir()
	var closed []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			closed = append(closed, strings.TrimPrefix(r.URL.Path, "/connections/"))
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/connections" {
			json.NewEncoder(w).Encode(map[string]interface{}{"connections": []map[string]interface{}{
				{"id": "old-unknown", "chains": []string{"DIRECT"}, "rule": "DomainRegex", "rulePayload": ".+", "metadata": map[string]string{"host": "ordinary.fixture", "destinationIP": "192.0.2.5"}},
				{"id": "card", "chains": []string{"DIRECT", cardPrefix + "steam"}, "metadata": map[string]string{"host": "steam.fixture"}},
				{"id": "explicit", "chains": []string{"DIRECT"}, "metadata": map[string]string{"host": "www.habr.fixture"}},
				{"id": "lan", "chains": []string{"DIRECT"}, "metadata": map[string]string{"destinationIP": "192.168.10.1"}},
				{"id": "new", "chains": []string{"DIRECT"}, "start": time.Now().Add(time.Hour)},
				{"id": "vpn", "chains": []string{"ExistingVPN"}, "metadata": map[string]string{"host": "other.fixture"}},
			}})
		}
	}))
	defer server.Close()
	state := protectedRoutingState{Version: 1, DrainToken: time.Now().UTC().Format(time.RFC3339Nano)}
	ack := filepath.Join(dir, "protected-routing-connections.applied")
	if err := os.WriteFile(ack+".pending", []byte(state.DrainToken+"\n"+time.Now().UTC().Format(time.RFC3339Nano)), 0600); err != nil {
		t.Fatal(err)
	}
	p := profile{assigned: map[string]string{"steam": directTarget}, api: coreAPI{base: server.URL, client: server.Client()}, doc: map[string]interface{}{
		"rules": []interface{}{"DOMAIN-SUFFIX,habr.fixture,DIRECT", "MATCH," + cardPrefix + defaultID, "IP-CIDR,0.0.0.0/0,DIRECT,no-resolve"},
	}}
	c := &Controller{stateDir: dir}
	if err := c.finishProtectedDrain(context.Background(), p, state); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(closed, []string{"old-unknown"}) {
		t.Fatal("the transition closed a stable or newly created connection", closed)
	}
	if err := (&Controller{stateDir: dir}).finishProtectedDrain(context.Background(), p, state); err != nil || len(closed) != 1 {
		t.Fatal("an acknowledged transition was repeated after restart", err)
	}
}

func TestProtectedRoutingRealMihomoRejectsUnknownWhenPoolIsEmpty(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("set MIHOMO_TEST_BINARY")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	controller := httptest.NewServer(http.NotFoundHandler())
	controllerAddr := controller.Listener.Addr().String()
	controller.Close()
	proxy := httptest.NewServer(http.NotFoundHandler())
	proxyAddr := proxy.Listener.Addr().String()
	proxy.Close()
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer destination.Close()
	// The documentation IP gives the metadata an external destination. Its
	// old provider transport is synthetic and terminates on loopback, so the
	// test never sends a packet to that IP or to the public internet.
	transport := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	_, port, _ := strings.Cut(destination.Listener.Addr().String(), ":")
	key := strings.Repeat("a", 64)
	base := map[string]interface{}{
		"mode": "rule", "external-controller": controllerAddr, "secret": "synthetic", "mixed-port": mustPort(t, proxyAddr),
		"bind-address": "127.0.0.1", "allow-lan": false, "ipv6": false,
		stateKey:       map[string]string{"openai": key, "claude": key, "steam": directTarget},
		"proxies":      []interface{}{map[string]interface{}{"name": "FixtureTransport", "type": "http", "server": "127.0.0.1", "port": mustPort(t, transport.Listener.Addr().String())}},
		"proxy-groups": []interface{}{map[string]interface{}{"name": "Bypass", "type": "select", "proxies": []string{"FixtureTransport"}}},
		"hosts":        map[string]string{"ordinary.fixture": "192.0.2.10", "habr.fixture": "127.0.0.1"},
		"rules":        []string{"DOMAIN-REGEX,.+,Bypass", "DOMAIN-SUFFIX,habr.fixture,DIRECT", "MATCH,DIRECT"},
	}
	raw, _ := json.Marshal(base)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
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
			t.Logf("isolated core: %s", coreLog.String())
		}
	}()
	c := New(path, dir, xkeen.Runtime{Core: xkeen.CoreMihomo, XrayConfDir: filepath.Join(dir, "configs")}, func() []models.Server { return nil })
	c.validate = func(ctx context.Context, next string) error {
		return exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", next).Run()
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
	// The control API may be ready before the mixed listener is bound.
	for {
		probe, err := net.DialTimeout("tcp4", proxyAddr, 100*time.Millisecond)
		if err == nil {
			probe.Close()
			break
		}
		if ctx.Err() != nil {
			t.Fatal("isolated mixed listener did not start", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}, Timeout: time.Second}
	response, err := client.Get("http://ordinary.fixture:" + port + "/")
	if err != nil || response.StatusCode != 204 {
		t.Fatal("the original foreign bypass was not reached", err)
	}
	response.Body.Close()
	prior := p.assigned
	status, err := c.SetProtectedRouting(ctx)
	if err != nil || status.Enabled || status.Mode != "protected" || !status.ProtectedFallback {
		t.Fatalf("protected mode did not apply: %+v %v", status, err)
	}
	p, err = c.read()
	if err != nil {
		t.Fatal(err)
	}
	for id, target := range prior {
		if p.assigned[id] != target {
			t.Fatal("explicit card assignment changed", id)
		}
	}
	response, err = client.Get("http://ordinary.fixture:" + port + "/")
	if err == nil {
		response.Body.Close()
		if response.StatusCode == 204 {
			t.Fatal("unknown request escaped through a foreign provider bypass")
		}
	}
	response, err = client.Get("http://habr.fixture:" + port + "/")
	if err != nil || response.StatusCode != 204 {
		t.Fatal("named exception no longer opens directly", err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	before, _ := os.ReadFile(path)
	if err := c.FinishRoutingTransition(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("maintenance rewrote a completed protected-mode transition")
	}
}
