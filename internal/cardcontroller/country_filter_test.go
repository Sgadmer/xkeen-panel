package cardcontroller

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestMihomoCountryFilterAndProviderRefresh(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("needs local Mihomo")
	}
	dir := t.TempDir()
	socket, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := socket.Addr().String()
	socket.Close()
	const good = "🇸🇪 Sweden ` v2 |+"
	nodes := []string{good, "🇷🇺 Russia", "blocked by owner"}
	writeJSON := func(path string, value any) {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	providerPath := filepath.Join(dir, "provider.json")
	writeProvider := func(names []string) {
		defs := []map[string]any{}
		for _, name := range names {
			defs = append(defs, map[string]any{"type": "socks5", "name": name, "server": "127.0.0.1", "port": 39991})
		}
		writeJSON(providerPath, map[string]any{"proxies": defs})
	}
	writeProvider(nodes)
	policy := map[string]any{"name": "Auto", "type": "url-test", "use": []string{"example"}, "exclude-filter": "blocked by owner", "empty-fallback": "DIRECT", "url": "http://127.0.0.1:39992", "interval": 60}
	path := filepath.Join(dir, "config.yaml")
	writeJSON(path, map[string]any{"mode": "rule", "external-controller": addr, "secret": "example-token", "proxy-providers": map[string]any{"example": map[string]any{"type": "file", "path": "provider.json", "health-check": map[string]any{"enable": false}}}, "proxy-groups": []any{policy, map[string]any{"name": "Manual", "type": "select", "proxies": []string{"Auto"}, "use": []string{"example"}}}, "rules": []string{"MATCH,Manual"}})
	servers := []models.Server{{Name: good, Country: "SE"}, {Name: nodes[1], Country: "RU"}, {Name: nodes[2], Country: "SE"}}
	c := New(path, dir, xkeen.Runtime{}, func() []models.Server { return servers })
	avoid := []string{"RU"}
	c.SetCountryPolicy(func() []string { return avoid }, func(s models.Server) bool { return !slices.Contains(avoid, s.Country) && s.Country != "" })
	c.validate = func(ctx context.Context, path string) error {
		return exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", path).Run()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "-d", dir, "-f", path)
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	p, err := c.read()
	if err != nil {
		t.Fatal(err)
	}
	// The controller can enter rule mode before a file provider finishes
	// registering its members. A selection during that interval returns 400.
	for {
		live, e := p.api.selectors(ctx)
		if e == nil && slices.Contains(live["Manual"].All, nodes[1]) && p.api.ruleMode(ctx) {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err = p.api.request(ctx, "PUT", "/proxies/Manual", map[string]string{"name": nodes[1]}, nil); err != nil {
		t.Fatal(err)
	}
	check := func(want []string) {
		t.Helper()
		live, err := p.api.selectors(ctx)
		if err != nil || !slices.Equal(live["Auto"].All, want) || live["Manual"].Now != nodes[1] {
			t.Fatalf("unexpected state: auto=%v manual=%q %v", live["Auto"].All, live["Manual"].Now, err)
		}
	}
	reconcile := func() {
		t.Helper()
		if err := c.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	check(nodes[:2])
	reconcile()
	check([]string{good})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reconcile()
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("non-idempotent reconciliation", err)
	}
	// Provider refresh can occur before the panel learns the new node's country.
	writeProvider(append(slices.Clone(nodes), "new-node"))
	if err := p.api.request(ctx, "PUT", "/providers/proxies/example", nil, nil); err != nil {
		t.Fatal(err)
	}
	check([]string{good})
	servers = append(servers, models.Server{Name: "new-node", Country: "FI"})
	reconcile()
	check([]string{good, "new-node"})
	avoid = []string{"RU", "SE", "FI"}
	reconcile()
	check([]string{"REJECT"})
	avoid = nil
	reconcile()
	check([]string{good, nodes[1], "new-node"})
	restored, err := c.read()
	if err != nil {
		t.Fatal(err)
	}
	if original := object(list(restored.doc["proxy-groups"])[0]); str(original["exclude-filter"]) != "blocked by owner" || str(original["empty-fallback"]) != "DIRECT" || original[countryFilterKey] != nil {
		t.Fatal("owner group policies lost")
	}
}

func TestCountryGroupReadinessRejectsMissingAllowedMember(t *testing.T) {
	groups := autoCountryGroups{types: map[string]string{"A": "url-test"}, allowed: map[string]map[string]bool{"A": {"FI": true}}}
	before := map[string]selector{"A": {Type: "URLTest", Now: "RU", All: []string{"FI", "RU"}}}
	if groups.ready(map[string]selector{"A": {Type: "URLTest", Now: "REJECT", All: []string{"REJECT"}}}, before) {
		t.Fatal("lost working members")
	}
	input := map[string]interface{}{"type": "url-test", "exclude-filter": "", "empty-fallback": "DIRECT"}
	c := Controller{}
	c.SetCountryPolicy(func() []string { return []string{"RU"} }, func(s models.Server) bool { return s.Country != "RU" })
	p := profile{doc: map[string]interface{}{"proxy-groups": []interface{}{input}}}
	beforeGroup := map[string]interface{}{"type": "url-test", "exclude-filter": "", "empty-fallback": "DIRECT"}
	if _, err := c.renderCountryFilter(&p, []models.Server{{Name: "duplicate", Country: "FI"}, {Name: "duplicate", Country: "RU"}}); err != nil {
		t.Fatal(err)
	}
	if err := removeCountryFilter(input); err != nil || !reflect.DeepEqual(beforeGroup, input) {
		t.Fatal("restore did not preserve group", err)
	}
}
