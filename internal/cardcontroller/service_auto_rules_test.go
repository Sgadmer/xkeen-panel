package cardcontroller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"xkeen-panel/internal/xkeen"
)

func cardCatalogForTest(t *testing.T) []xkeen.ServiceRouteView {
	t.Helper()
	view, err := xkeen.ReadServiceRoutes(xkeen.Runtime{Core: xkeen.CoreMihomo, XrayConfDir: filepath.Join(t.TempDir(), "config")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return view.Services
}

func TestAutoCardsKeepProviderOverridesAheadOfRegistry(t *testing.T) {
	services := cardCatalogForTest(t)
	targets := map[string]string{}
	for _, service := range services {
		targets[service.ID] = allPoolID
	}
	pinned := strings.Repeat("a", 64)
	targets["openai"], targets["claude"], targets["google"], targets["steam"] = pinned, pinned, pinned, directTarget
	hash := strings.Repeat("e", 64)
	p := profile{assigned: targets, doc: map[string]interface{}{
		serviceAutoKey: true,
		refilterKey:    map[string]interface{}{"enabled": true, "domain_behavior": "domain", "site_hash": hash, "ip_hash": hash, "domains": 1, "prefixes": 1},
		"proxies":      []interface{}{map[string]interface{}{"name": "Base", "type": "http", "server": "127.0.0.1", "port": 1}},
		"rules":        []interface{}{"DOMAIN-SUFFIX,habr.com,DIRECT", "SRC-IP-CIDR,192.0.2.5/32,DIRECT", "GEOSITE,google,Google", "GEOSITE,category-ai-!cn,AI", "MATCH,Base"},
	}}
	// There are no pool endpoints. The two pinned cards keep their own
	// endpoint, unlisted service destinations block, and ordinary sites can
	// still reach the direct catch-all. Steam keeps its manual selection.
	groups, err := render(&p, services, map[string]cardEndpoint{pinned: {name: nodePrefix + pinned}}, true)
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{"claude": nodePrefix + pinned, "openai": nodePrefix + pinned, "google": nodePrefix + pinned, "ai": "REJECT", "youtube": "REJECT", "telegram": "REJECT", "steam": "DIRECT"} {
		if groups[cardPrefix+id] != want {
			t.Fatalf("%s target = %q, want %q", id, groups[cardPrefix+id], want)
		}
	}
	rules := namesOf(p.doc["rules"])
	before := func(first, second string) {
		t.Helper()
		i, j := slices.Index(rules, first), slices.Index(rules, second)
		if i < 0 || j < 0 || i >= j {
			t.Fatalf("rule %q at %d must precede %q at %d", first, i, second, j)
		}
	}
	early := "DOMAIN-SUFFIX,gemini.google.com," + cardPrefix + "ai"
	registry := "RULE-SET," + refilterSites + "," + cardPrefix + defaultID
	before("DOMAIN-SUFFIX,claude.ai,"+cardPrefix+"claude", "SRC-IP-CIDR,192.0.2.5/32,DIRECT")
	before("DOMAIN-SUFFIX,habr.com,DIRECT", early)
	before("SRC-IP-CIDR,192.0.2.5/32,DIRECT", early)
	before(early, "DOMAIN-SUFFIX,google.com,"+cardPrefix+"google")
	before("DOMAIN-SUFFIX,youtubei.googleapis.com,"+cardPrefix+"youtube", "GEOSITE,google,"+cardPrefix+"google")
	before("DOMAIN-SUFFIX,chatgpt.com,"+cardPrefix+"openai", "GEOSITE,category-ai-!cn,"+cardPrefix+"ai")
	before("DOMAIN-SUFFIX,discord.com,"+cardPrefix+"discord", registry)
	before("IP-CIDR,149.154.160.0/20,"+cardPrefix+"telegram,no-resolve", registry)
	before(registry, "MATCH,"+cardPrefix+"direct")
}

func TestAutoCardsDrainOnlyDisplacedConnections(t *testing.T) {
	services := cardCatalogForTest(t)
	var gets int
	var closed []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			closed = append(closed, strings.TrimPrefix(r.URL.Path, "/connections/"))
			w.WriteHeader(http.StatusNoContent)
			return
		}
		gets++
		type row = map[string]interface{}
		flow := func(id, host, ip, rule, payload string, chains ...string) row {
			return row{"id": id, "metadata": row{"host": host, "destinationIP": ip}, "rule": rule, "rulePayload": payload, "chains": chains}
		}
		json.NewEncoder(w).Encode(row{"connections": []row{
			flow("old-ai", "gemini.google.com", "", "DomainSuffix", "google.com", "Pinned", cardPrefix+"google"),
			flow("unlisted", "discord.com", "", "DomainRegex", ".+", "DIRECT", cardPrefix+"direct"),
			flow("telegram-ip", "", "149.154.160.17", "Match", "", "DIRECT", cardPrefix+"direct"),
			flow("native-telegram-ip", "", "198.51.100.33", "Match", "", "DIRECT", cardPrefix+"direct"),
			flow("still-youtube", "youtubei.googleapis.com", "", "DomainSuffix", "youtubei.googleapis.com", "Pool", cardPrefix+"youtube"),
			flow("explicit-exempt-device", "discord.com", "", "SrcIPCIDR", "192.0.2.5/32", "DIRECT"),
			flow("ordinary", "habr.com", "", "DomainSuffix", "habr.com", "DIRECT"),
			flow("legacy-default", "store.steampowered.com", "", "Match", "", "Base"),
		}})
	}))
	defer server.Close()
	p := profile{api: coreAPI{base: server.URL, client: server.Client()}, assigned: map[string]string{}, doc: map[string]interface{}{serviceAutoKey: true, "rules": []interface{}{
		"DOMAIN-SUFFIX,habr.com,DIRECT", "SRC-IP-CIDR,192.0.2.5/32,DIRECT", "IP-CIDR,198.51.100.0/24,Telegram,no-resolve", "MATCH,Base",
	}}}
	for _, s := range services {
		p.assigned[s.ID] = allPoolID
	}
	if _, err := render(&p, services, nil, true); err != nil {
		t.Fatal(err)
	}
	failed := (&Controller{}).drainChanged(context.Background(), p, map[string]string{"ai": "Pool", "discord": "Pool", "telegram": "Pool", "google": "Pinned", "youtube": "Pool"}, services)
	if len(failed) != 0 || gets != 1 || !slices.Equal(closed, []string{"old-ai", "unlisted", "telegram-ip", "native-telegram-ip"}) {
		t.Fatalf("closed %v, failed %v, snapshot reads %d", closed, failed, gets)
	}
	// Before migration a service without a pinned route can still use MATCH.
	delete(p.assigned, "steam")
	delete(p.doc, serviceAutoKey)
	closed = nil
	failed = (&Controller{}).drainChanged(context.Background(), p, map[string]string{defaultID: "New base"}, services)
	if len(failed) != 0 || !slices.Equal(closed, []string{"telegram-ip", "legacy-default"}) {
		t.Fatalf("legacy default closed %v, failed %v", closed, failed)
	}
}
