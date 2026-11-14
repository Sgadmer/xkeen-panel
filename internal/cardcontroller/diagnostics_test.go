package cardcontroller

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestConnectionUsesObservedChainAndOnlyPublicFields(t *testing.T) {
	var f connectionTracker
	err := json.Unmarshal([]byte(`{"id":"flow","metadata":{"sourceIP":"::ffff:192.0.2.2","sniffHost":"example.com","destinationIP":"192.0.2.1","destinationPort":"443","network":"tcp","inboundUser":"private"},"chains":["DIRECT","RuleGroup"],"rule":"IPCIDR","rulePayload":"192.0.2.0/24"}`), &f)
	if err != nil {
		t.Fatal(err)
	}
	row := f.project(map[string]string{"DIRECT": "Напрямую"})
	if row.Host != "example.com" || row.Device != "192.0.2.2" || row.Port != "443" || row.Rule != "IPCIDR 192.0.2.0/24" || !reflect.DeepEqual(row.Route, []string{"RuleGroup", "Напрямую"}) {
		t.Fatalf("%+v", row)
	}
	f.Metadata.Host = "https://example.com/path?token=test"
	f.Metadata.SniffHost = ""
	f.Chains = nil
	row = f.project(nil)
	if row.Host != "192.0.2.1" || len(row.Route) != 0 {
		t.Fatalf("%+v", row)
	}
	for tag, id := range map[string]string{"ChatGPT": "openai", cardPrefix + "openai-inherited": "openai", dedicatedGroup("claude"): "claude", "Other": ""} {
		f.Chains = []string{"DIRECT", tag}
		if got := f.project(nil).ServiceID; got != id {
			t.Errorf("tag %q: %q", tag, got)
		}
	}
	f.Chains = []string{"DIRECT"}
	for domain, want := range map[string]string{"API.Anthropic.com.": "claude", "chatgpt.com": "openai", "notchatgpt.com": "", "chatgpt.com.example": ""} {
		f.Metadata.Host = domain
		row = f.project(nil)
		if row.ServiceID != want || !reflect.DeepEqual(row.Route, []string{"DIRECT"}) {
			t.Errorf("incorrect service icon or route for %q", domain)
		}
	}
	f.Chains = []string{"US", cardPrefix + "google"}
	for host, want := range map[string]string{"i.ytimg.com": "youtube", "yt3.googleusercontent.com": "youtube", "youtubei.googleapis.com": "youtube", "play.googleapis.com": "google", "ytimg.com.other.test": "google"} {
		f.Metadata.Host = host
		row := f.project(map[string]string{cardPrefix + "google": "Google"})
		if row.ServiceID != want || !reflect.DeepEqual(row.Route, []string{"Google", "US"}) {
			t.Errorf("wrong service or observed route for %s: %+v", host, row)
		}
	}
}

func TestConnectionRowsKeepWorkerObservationSeparateFromRecordedExit(t *testing.T) {
	de := poolServer("provider-1", "DE", "10001")
	de.Name, de.SourceName = "🇩🇪 Berlin", "⭐ Provider"
	nl := poolServer("provider-2", "NL", "10002")
	nl.CountryOverride = "BE"
	composite := models.Server{Name: "Auto provider", RawProfile: json.RawMessage(`{"outbounds":[{"protocol":"freedom","tag":"direct"}]}`)}
	servers := []models.Server{de, nl, composite}
	c := &Controller{catalog: func() []models.Server { return servers }}
	member := xkeen.ServiceTargetID(de)
	generation := strings.Repeat("a", 64)
	workerTag := nodePrefix + allPoolID + "-" + generation
	oldTag := nodePrefix + allPoolID + "-" + strings.Repeat("b", 64)
	p := profile{doc: map[string]interface{}{"proxies": []interface{}{
		map[string]interface{}{"name": workerTag, "server": "127.0.0.1", "port": 1234, "type": "vless"},
		map[string]interface{}{"name": "🇳🇱 native", "type": "vless"},
	}}}
	flows := []connectionTracker{
		{ID: "a", Chains: []string{workerTag, cardPrefix + defaultID}},
		{ID: "b", Chains: []string{workerTag, cardPrefix + "youtube"}},
		{ID: "c", Chains: []string{oldTag, cardPrefix + defaultID}},
		{ID: "d", Chains: []string{nodePrefix + member}},
		{ID: "e", Chains: []string{"DIRECT", cardPrefix + defaultID}},
		{ID: "f", Chains: []string{"REJECT-DROP"}},
		{ID: "g", Chains: []string{nodePrefix + xkeen.ServiceTargetID(composite)}},
		{ID: "h", Chains: []string{"🇳🇱 native", "auto"}},
	}
	samples := 0
	read := func(ctx context.Context, _ xkeen.Runtime, id string, port int) string {
		samples++
		if id != generation || port != 1234 {
			t.Fatalf("unexpected worker %s, %d", id, port)
		}
		return member
	}
	rows := c.connectionRows(context.Background(), p, flows, read)
	want := ConnectionExit{Kind: "server", Name: de.Name, Source: de.SourceName, Country: "DE"}
	if samples != 1 || rows[0].Exit.Kind != "unresolved" || rows[1].Exit.Kind != "unresolved" ||
		rows[0].PoolCurrent == nil || !reflect.DeepEqual(*rows[0].PoolCurrent, want) || rows[1].PoolCurrent != rows[0].PoolCurrent {
		t.Fatalf("expected one separate sample for the live worker, got %d across %+v", samples, rows[:2])
	}
	if rows[2].Exit.Kind != "unresolved" || rows[2].PoolCurrent != nil || !reflect.DeepEqual(rows[3].Exit, want) || rows[3].PoolCurrent != nil ||
		rows[4].Exit.Kind != "direct" || rows[5].Exit.Kind != "reject" || rows[6].Exit.Kind != "unresolved" ||
		rows[7].Exit.Name != "🇳🇱 native" || rows[7].Exit.Kind != "server" {
		t.Fatalf("unexpected projected exits: %+v", rows[2:])
	}
	member = xkeen.ServiceTargetID(nl)
	changed := c.connectionRows(context.Background(), p, flows[:1], read)[0]
	if changed.Exit.Kind != "unresolved" || changed.PoolCurrent == nil || changed.PoolCurrent.Country != "BE" {
		t.Fatalf("pool changes must never become a per-flow exit: %+v", changed)
	}
	member = ""
	missing := c.connectionRows(context.Background(), p, flows[:1], read)[0]
	if missing.Exit.Kind != "unresolved" || missing.PoolCurrent != nil {
		t.Fatalf("a worker without observations must not fabricate an exit: %+v", missing)
	}
}

func TestDiagnosticCatalogProtectsConflictingAliases(t *testing.T) {
	first := poolServer("A", "DE", "10001")
	first.SourceName = "First"
	alias := first
	alias.SourceName, alias.CountryOverride, alias.Name = "Second", "AU", "Other name"
	a := diagnosticCatalog([]models.Server{first, alias})[xkeen.ServiceTargetID(first)]
	b := diagnosticCatalog([]models.Server{alias, first})[xkeen.ServiceTargetID(first)]
	if !reflect.DeepEqual(a, b) || a.Country != "" || a.Source != "" || a.Name == alias.Name || a.Name == first.Name || a.Kind != "server" {
		t.Fatalf("ambiguous aliases exposed a source or location: %+v, %+v", a, b)
	}
}

func TestDiagnosticCountriesBelongToEachResolvedEndpoint(t *testing.T) {
	a := poolServer("A", "SO", "10001")
	a.Name = "🇷🇺 → 🇸🇪"
	other := poolServer("A", "SO", "10002")
	other.Name = "🇷🇺 → 🇳🇱"
	ordinary := poolServer("A", "FR", "10003")
	forward := diagnosticCatalog([]models.Server{a, other, ordinary})
	if got := forward[xkeen.ServiceTargetID(a)]; got.Country != "SE" || !reflect.DeepEqual(got.DeclaredCountryPath, []string{"RU", "SE"}) {
		t.Fatal(got)
	}
	if got := forward[xkeen.ServiceTargetID(other)]; !reflect.DeepEqual(got.DeclaredCountryPath, []string{"RU", "NL"}) {
		t.Fatal(got)
	}
	if got := forward[xkeen.ServiceTargetID(ordinary)]; got.Country != "FR" || len(got.DeclaredCountryPath) > 0 {
		t.Fatal(got)
	}
	alias := a
	alias.Name = "🇩🇪 → 🇸🇪"
	ambiguous := diagnosticCatalog([]models.Server{a, alias})[xkeen.ServiceTargetID(a)]
	if ambiguous.Country != "SE" || len(ambiguous.DeclaredCountryPath) > 0 {
		t.Fatal(ambiguous)
	}
	if result := nativeConnectionExit("x", "direct"); len(result.DeclaredCountryPath) > 0 || result.Country != "" {
		t.Fatal(result)
	}
}
