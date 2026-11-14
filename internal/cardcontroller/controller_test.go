package cardcontroller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestMihomoReloadExactRouteAndKeepDirect(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("MIHOMO_TEST_BINARY is required for a real core test")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controllerAddr := listener.Addr().String()
	listener.Close()
	base := map[string]interface{}{"external-controller": controllerAddr, "secret": "synthetic-controller-secret", "mode": "rule", "profile": map[string]bool{"store-selected": true}, "proxy-groups": []interface{}{map[string]interface{}{"type": "select", "name": "AI", "proxies": []string{"REJECT", "DIRECT"}}, map[string]interface{}{"name": "ChatGPT", "type": "select", "proxies": []string{"DIRECT", "REJECT"}}}, "rules": []string{"DOMAIN-SUFFIX,test.example,DIRECT", "DOMAIN-SUFFIX,openai.com,ChatGPT", "MATCH,DIRECT"}}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	proc := exec.CommandContext(ctx, core, "-d", dir, "-f", path)
	if err = proc.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); proc.Wait() }()
	item := models.Server{Name: "first", RawURI: "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:9989?type=tcp"}
	servers := []models.Server{item}
	c := New(path, dir, xkeen.Runtime{Core: xkeen.CoreMihomo, XrayConfDir: filepath.Join(dir, "configs")}, func() []models.Server { return servers })
	c.validate = func(ctx context.Context, p string) error {
		return exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", p).Run()
	}
	c.prepare = func(xkeen.Runtime, string, models.Server) (xkeen.CardProxy, error) {
		return xkeen.CardProxy{Port: 59999, UUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", ServerName: "test.invalid", Fingerprint: "ac37b1fd7ada133aa3e6881661add159942aea366767920056ad51be65d6c83a"}, nil
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
	if err = p.api.request(ctx, "PUT", "/proxies/AI", map[string]string{"name": "DIRECT"}, nil); err != nil {
		t.Fatal(err)
	}
	if err = c.CheckCoreInterruption(); err != nil {
		t.Fatal("unmanaged profile should allow ordinary core control", err)
	}
	id := xkeen.ServiceTargetID(item)
	// Seed the format written by an older panel: Claude is pinned, while
	// unassigned services continue to use the original owner's routing.
	view, err := c.apply(ctx, "claude", id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !view.Active || view.GuardReady || view.Services[0].Target != id || view.Services[0].Blocked {
		t.Fatalf("unexpected view active=%t blocked=%t", view.Active, view.Services[0].Blocked)
	}
	if c.CheckCoreInterruption() == nil {
		t.Fatal("managed Claude route allowed the dispatcher to remove interception")
	}
	check := func() {
		live, e := p.api.selectors(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if live["AI"].Now != "DIRECT" || live["ChatGPT"].Now != "DIRECT" {
			t.Fatal("an unrelated selector changed")
		}
		state, e := c.read()
		if e != nil {
			t.Fatal(e)
		}
		rules := list(state.doc["rules"])
		if str(rules[len(rules)-1]) != "MATCH,DIRECT" || !slices.Contains(rules, any("DOMAIN-SUFFIX,test.example,DIRECT")) {
			t.Fatal("direct rules were modified")
		}
	}
	check()
	if _, err := c.Set(ctx, "claude", directTarget); err == nil {
		t.Fatal("accepted DIRECT for Claude")
	}
	if err := p.api.request(ctx, "PUT", "/proxies/ChatGPT", map[string]string{"name": "REJECT"}, nil); err != nil {
		t.Fatal(err)
	}
	explicit, err := c.Set(ctx, "openai", directTarget)
	if err != nil {
		t.Fatal(err)
	}
	var card xkeen.ServiceRouteView
	for _, s := range explicit.Services {
		if s.ID == "openai" {
			card = s
		}
	}
	if !explicit.Active || card.Target != directTarget || card.RouteName != "DIRECT" || card.Blocked {
		t.Fatal("explicit DIRECT wasn't reflected in running state")
	}
	saved, err := c.read()
	if err != nil || saved.assigned["openai"] != directTarget {
		t.Fatal("saved DIRECT assignment not found")
	}
	var claudeIndex, directIndex, openaiIndex int = -1, -1, -1
	for i, v := range list(saved.doc["rules"]) {
		switch str(v) {
		case "DOMAIN-SUFFIX,claude.ai,XKP-card-claude":
			claudeIndex = i
		case "DOMAIN-SUFFIX,test.example,DIRECT":
			directIndex = i
		case "DOMAIN-SUFFIX,openai.com,XKP-card-openai":
			openaiIndex = i
		}
	}
	if !(claudeIndex >= 0 && claudeIndex < directIndex && directIndex < openaiIndex) {
		t.Fatal("wrong Claude/direct exception/ordinary service precedence")
	}
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	explicit, err = c.View(ctx)
	if err != nil || !explicit.Active || explicit.ServiceAutoDefault {
		t.Fatal("reconciliation lost DIRECT")
	}
	// Activation is a single validated reload. A failed pool leaves the
	// installed legacy profile untouched; a successful retry preserves pins.
	legacy, _ := os.ReadFile(path)
	prepare := c.prepare
	c.prepare = func(rt xkeen.Runtime, hash string, target models.Server) (xkeen.CardProxy, error) {
		if target.GeneratedPool {
			return xkeen.CardProxy{}, errors.New("fixture: unavailable pool")
		}
		return prepare(rt, hash, target)
	}
	if _, err := c.EnableServiceAutoDefault(ctx); err == nil {
		t.Fatal("failed pool accepted by migration")
	}
	if raw, _ := os.ReadFile(path); string(raw) != string(legacy) {
		t.Fatal("failed migration changed profile")
	}
	c.prepare = prepare
	validations := 0
	validateCandidate := c.validate
	c.validate = func(ctx context.Context, path string) error {
		validations++
		return validateCandidate(ctx, path)
	}
	for twice := 0; twice < 2; twice++ {
		v, err := c.EnableServiceAutoDefault(ctx)
		if err != nil || !v.Active || !v.ServiceAutoDefault || v.DefaultServiceTarget != allPoolID || v.ActiveConnectionsPending {
			t.Fatal("auto default not confirmed", err)
		}
		for _, card := range v.Services {
			want := allPoolID
			switch card.ID {
			case "claude":
				want = id
			case "openai", "steam":
				want = directTarget
			}
			if card.Target != want || card.Blocked {
				t.Fatal("wrong migrated route", card.ID, card.Target)
			}
		}
	}
	if validations != 1 {
		t.Fatalf("migration/retry validated %d candidate configurations", validations)
	}
	// Simulate a catalog upgrade: a new card has no saved assignment. A
	// restarted panel must give it the same default as the existing cards.
	restart, err := c.read()
	if err != nil {
		t.Fatal(err)
	}
	delete(object(restart.doc[stateKey]), "discord")
	delete(object(restart.doc[stateKey]), "steam")
	if err = c.savePoolMetadata(restart); err != nil {
		t.Fatal(err)
	}
	fresh := New(path, dir, c.rt, c.catalog)
	fresh.prepare, fresh.validate = c.prepare, c.validate
	if err = fresh.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	restart, err = fresh.read()
	if err != nil || restart.assigned["discord"] != allPoolID || restart.assigned["steam"] != directTarget || restart.assigned["openai"] != directTarget {
		t.Fatal("restart did not persist automatic and explicit assignments", err)
	}
	if _, err = c.Set(ctx, "steam", allPoolID); err != nil {
		t.Fatal(err)
	}
	if _, err = c.EnableServiceAutoDefault(ctx); err != nil {
		t.Fatal(err)
	}
	if saved, err := c.read(); err != nil || saved.assigned["steam"] != allPoolID {
		t.Fatal("migration changed a manually selected Steam pool", err)
	}
	if _, err = c.Set(ctx, "steam", ""); err != nil {
		t.Fatal(err)
	}
	auto, err := c.Set(ctx, "openai", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range auto.Services {
		if s.ID == "openai" && (s.Target != allPoolID || s.Blocked) {
			t.Fatal("an empty choice did not restore the automatic VPN pool")
		}
	}
	if err := p.api.request(ctx, "PUT", "/proxies/ChatGPT", map[string]string{"name": "DIRECT"}, nil); err != nil {
		t.Fatal(err)
	}
	firstBackup, err := os.ReadFile(filepath.Join(dir, "before-mihomo-service-routes.yaml"))
	if err != nil || string(raw) != string(firstBackup) {
		t.Fatal("first backup did not preserve original YAML")
	}
	access, err := c.EnableClaudeProxy(ctx, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.EnableClaudeProxy(ctx, "127.0.0.1")
	if err != nil || access != again || access.Username != "claude" || len(access.Password) < 32 {
		t.Fatal("proxy access isn't persistent and explicit")
	}
	if _, err = c.EnableClaudeProxy(ctx, "0.0.0.0"); err == nil {
		t.Fatal("allowed wildcard listener")
	}
	if _, err := c.EnableServiceProxy(ctx, "127.0.0.1", "discord"); err != nil {
		t.Fatal("automatic pool must support the app proxy", err)
	}
	for _, next := range []string{directTarget, ""} {
		if _, err := c.Set(ctx, "openai", id); err != nil {
			t.Fatal(err)
		}
		second, err := c.EnableServiceProxy(ctx, "127.0.0.1", "openai")
		if err != nil || second.Address == access.Address || second.Password == access.Password || second.Username != "openai" {
			t.Fatal("separate service credentials", err)
		}
		live, err := p.api.selectors(ctx)
		if err != nil || live[dedicatedGroup("openai")].Now != nodePrefix+id || live[dedicatedGroup("claude")].Now != nodePrefix+id {
			t.Fatal("private proxy doesn't use an isolated group")
		}
		if _, err = c.Set(ctx, "openai", next); err != nil {
			t.Fatal(err)
		}
		if next == directTarget {
			if conn, err := net.DialTimeout("tcp", second.Address, time.Second); err == nil {
				conn.Close()
				t.Fatal("old service proxy accepted a connection after switching to direct")
			}
			if _, err = c.EnableServiceProxy(ctx, "127.0.0.1", "openai"); err == nil {
				t.Fatal("created proxy for direct card")
			}
		} else {
			again, err := c.EnableServiceProxy(ctx, "127.0.0.1", "openai")
			live, liveErr := p.api.selectors(ctx)
			if err != nil || again != second || liveErr != nil || !strings.HasPrefix(live[dedicatedGroup("openai")].Now, nodePrefix+allPoolID+"-") {
				t.Fatal("changing to auto did not preserve dedicated proxy with new target", err, liveErr)
			}
		}
		if _, err = c.EnableClaudeProxy(ctx, "127.0.0.1"); err != nil {
			t.Fatal("changing another card closed Claude", err)
		}
	}
	// Force a live reload failure *after* validation, then confirm the previous
	// exact target and unchanged direct selector are restored from disk.
	prior, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	validate := c.validate
	c.validate = func(ctx context.Context, p string) error {
		if err := validate(ctx, p); err != nil {
			return err
		}
		return os.WriteFile(p, []byte("mode: [\n"), 0600)
	}
	if _, err = c.Set(ctx, "openai", id); err == nil {
		t.Fatal("broken reload succeeded")
	}
	c.validate = validate
	restored, err := os.ReadFile(path)
	if err != nil || string(prior) != string(restored) {
		t.Fatal("configuration was not restored byte-for-byte")
	}
	short, err := net.DialTimeout("tcp", access.Address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(short, "CONNECT invalid.invalid:443 HTTP/1.1\r\nHost: invalid.invalid\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	short.Close()
	check()
	servers = nil
	if err = c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	view, err = c.View(ctx)
	if err != nil || !view.Active || !view.Services[0].Blocked || view.Services[0].Target != id {
		t.Fatal("missing endpoint was not blocked")
	}
	for _, card := range view.Services {
		if card.ID == "steam" {
			if card.Target != directTarget || card.Blocked || card.RouteName != "DIRECT" {
				t.Fatal("direct Steam route changed when the VPN pool became empty")
			}
		} else if card.ID != "claude" && (card.Target != allPoolID || !card.Blocked) {
			t.Fatal("empty pool did not block the protected service", card.ID)
		}
	}
	check()
	// Changing the default must preserve Claude's assignment and original
	// exceptions, also when the pinned node disappears on a refresh.
	servers = []models.Server{item}
	if err = c.SetDefault(ctx, id); err != nil {
		t.Fatal(err)
	}
	state, err := c.Default(ctx)
	if err != nil || state.Current != id || state.Pinned != id {
		t.Fatal("default is not pinned", err)
	}
	saved, err = c.read()
	if err != nil || saved.assigned["claude"] != id {
		t.Fatal("Claude assignment changed")
	}
	rules := list(saved.doc["rules"])
	if len(rules) < 3 || str(rules[len(rules)-3]) != "MATCH,XKP-card-default" || str(rules[len(rules)-2]) != "MATCH,XKP-card-reject" || str(rules[len(rules)-1]) != "MATCH,DIRECT" {
		t.Fatal("default is not guarded")
	}
	if _, err = c.Set(ctx, defaultID, directTarget); err == nil {
		t.Fatal("default exposed as regular service")
	}
	servers = nil
	if err = c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	state, err = c.Default(ctx)
	if err != nil || state.Name != "REJECT" || state.Pinned != id {
		t.Fatal("lost default did not fail closed")
	}
}
