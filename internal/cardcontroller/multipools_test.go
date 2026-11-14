package cardcontroller

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func poolServer(source, country, port string) models.Server {
	return models.Server{
		Name: source + country, SourceID: source, Country: country,
		RawURI: "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:" + port + "?type=tcp",
	}
}

func TestMultiPoolSourceCountryComposition(t *testing.T) {
	a := poolServer("A", "DE", "10001")
	b := poolServer("B", "NL", "10002")
	duplicate := a
	duplicate.SourceID = "B"
	overridden := poolServer("B", "RU", "10003")
	overridden.CountryOverride = "NL"
	c := &Controller{}
	c.SetCountryPolicy(func() []string { return []string{"RU"} }, func(s models.Server) bool { return xkeen.ServerCountry(s) != "RU" })
	servers := []models.Server{a, b, duplicate, overridden, poolServer("A", "RU", "10004"), poolServer("B", "", "10005"),
		{SourceID: "B", Country: "NL", RawProfile: json.RawMessage(`{"outbounds":[{"protocol":"freedom","tag":"direct"}]}`)}}
	pool := MultiPool{PoolSpec: PoolSpec{SourceIDs: []string{"B"}, Countries: []string{"NL", "DE"}}}
	members := pool.members(c.poolNodes(servers))
	if len(members) != 3 {
		t.Fatalf("wanted 3 unique allowed nodes after source and country filters, got %d", len(members))
	}
	blockedAlias := duplicate
	blockedAlias.Country = "RU"
	members = pool.members(c.poolNodes(append(servers, blockedAlias)))
	if len(members) != 2 {
		t.Fatal("blocked endpoint alias was reintroduced")
	}
	pool.SourceIDs = []string{"missing"}
	if len(pool.members(c.poolNodes(servers))) != 0 {
		t.Fatal("missing source broadened the pool")
	}
	pool.SourceIDs = []string{}
	pool.Countries = []string{"DE"}
	if len(pool.members(c.poolNodes(append(servers, poolServer("C", "DE", "10006"))))) != 2 {
		t.Fatal("new matching source member not included")
	}
}

func TestNativeDefaultUsesProviderSourceWithMatchingNames(t *testing.T) {
	native := poolServer("legacy", "SE", "10081")
	foreign := poolServer("B", "RU", "10082")
	native.Name, foreign.Name = "Same name", "Same name"
	p := profile{doc: map[string]interface{}{
		"proxy-providers": map[string]interface{}{"p": map[string]interface{}{"type": "http", "url": "https://native.invalid/source"}},
		"proxy-groups":    []interface{}{map[string]interface{}{"name": "Auto", "type": "url-test", "use": []interface{}{"p"}}},
		"rules":           []interface{}{"MATCH,Default"},
	}}
	c := &Controller{catalog: func() []models.Server { return []models.Server{foreign, native} }}
	c.SetSourceProviderURLs(func() map[string]string {
		return map[string]string{"legacy": "https://native.invalid/source", "B": "https://other.invalid/source"}
	})
	c.SetCountryPolicy(func() []string { return []string{"RU"} }, func(s models.Server) bool { return s.Country != "RU" })
	live := map[string]selector{"Default": {Now: "Auto", All: []string{"Auto"}}, "Auto": {Type: "URLTest", Now: "Same name", All: []string{"Same name"}}}
	got := c.defaultRoute(p, live)
	if len(got.Nodes) != 1 || got.Nodes[0].Tag != xkeen.ServiceTargetID(native) || got.Current != xkeen.ServiceTargetID(native) {
		t.Fatalf("wrong native attribution: %+v", got)
	}
	filter, err := c.renderCountryFilter(&p, c.catalog())
	if err != nil || !filter.allowed["Auto"]["Same name"] {
		t.Fatal("unrelated source blocked native provider", err)
	}
	foreign.Name = "New native endpoint"
	native.Name = "Older name"
	c.catalog = func() []models.Server { return []models.Server{foreign, native} }
	filter, err = c.renderCountryFilter(&p, c.catalog())
	if err != nil || filter.allowed["Auto"]["New native endpoint"] {
		t.Fatal("unrelated source classified native provider", err)
	}
}

func TestAutoScopesRankAllSourcesAndKeepExplicitOwnership(t *testing.T) {
	first := poolServer("A", "DE", "10001")
	next := poolServer("B", "DE", "10002")
	other := poolServer("C", "FR", "10003")
	excluded := poolServer("C", "RU", "10004")
	first.Latency, next.Latency, other.Latency, excluded.Latency = 120, 20, 30, 1
	alias := next
	alias.SourceID = "A"
	alias.Latency = 25
	failed := poolServer("B", "US", "10005")
	failed.ProbeKind, failed.Latency = "https", -1
	c := &Controller{}
	c.SetAutoPoolLimit(2)
	c.SetCountryPolicy(func() []string { return []string{"RU"} }, func(s models.Server) bool { return s.Country != "RU" })
	nodes := c.poolNodes([]models.Server{first, next, other, excluded, alias, failed})
	all := builtinPool(allPoolID)
	best := all.members(nodes)
	if len(best) != 2 || best[0].SourceID != "B" || best[1].SourceID != "C" || all.EligibleCount != 3 {
		t.Fatal("global selection lost another source, included failed/avoided or overran limit", best)
	}
	de := builtinPool(scopeHash("country:DE"))
	if got := de.members(nodes); len(got) != 2 || got[0].SourceID != "B" {
		t.Fatal("country did not aggregate sources", got)
	}
	fixed := false
	custom := MultiPool{ID: scopeHash("custom fixture"), PoolSpec: PoolSpec{Name: "Mix", IncludeFiltered: &fixed, Members: []PoolMember{{SourceID: "B", TargetID: xkeen.ServiceTargetID(next)}}}}
	if got := custom.members(c.poolNodes([]models.Server{alias})); len(got) != 0 {
		t.Fatal("explicit reference drifted to a different source")
	}
	filtered := true
	custom.IncludeFiltered = &filtered
	custom.Countries = []string{"FR"}
	if got := custom.members(nodes); len(got) != 2 || got[0].SourceID != "B" || got[1].Country != "FR" {
		t.Fatal("explicit and dynamic sets did not combine", got)
	}
	p := profile{doc: map[string]interface{}{autoScopeKey: de.ID}, assigned: map[string]string{"claude": de.ID}, pools: []MultiPool{custom}}
	got := scopes(p, c.poolNodes([]models.Server{other}))
	if got[0].Kind != "all" || got[len(got)-1].ID != custom.ID {
		t.Fatal("pool order", got)
	}
	for _, s := range got {
		if s.ID == de.ID && s.MemberCount == 0 {
			return
		}
	}
	t.Fatal("missing assigned empty country")
}

func TestDefaultSourceProvenanceAndReplacement(t *testing.T) {
	item := poolServer("A", "SE", "10001")
	item.SourceName = "First"
	twin := item
	twin.SourceID, twin.SourceName, twin.Name = "B", "Second", "Mirror"
	key := xkeen.ServiceTargetID(item)
	p := profile{doc: map[string]interface{}{defaultSourceKey: "B", replacementKey: key}, assigned: map[string]string{defaultID: key}}
	c := &Controller{catalog: func() []models.Server { return []models.Server{item, twin} }}
	state := c.defaultRoute(p, map[string]selector{cardPrefix + defaultID: {Now: nodePrefix + key}})
	if state.Current != key || state.CurrentSource != "B" || state.SourceName != "Second" || state.SelectionName != "Mirror" || state.SelectionKind != "replacement" {
		t.Fatal("incorrect attribution", state)
	}
}

func TestNamedPoolThroughMihomoAndXray(t *testing.T) {
	core, xray := os.Getenv("MIHOMO_TEST_BINARY"), os.Getenv("XRAY_TEST_BINARY")
	if core == "" || xray == "" {
		t.Skip("set MIHOMO_TEST_BINARY and XRAY_TEST_BINARY")
	}
	dir := t.TempDir()
	listen := func() (string, int) {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		return l.Addr().String(), l.Addr().(*net.TCPAddr).Port
	}
	port := func() (string, int) {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().String(), l.Addr().(*net.TCPAddr).Port
	}
	addr, _ := port()
	httpAddr, httpPort := port()
	path := filepath.Join(dir, "config.yaml")
	body, _ := json.Marshal(map[string]interface{}{
		"mode": "rule", "external-controller": addr, "secret": "fixture-controller-secret", "port": httpPort,
		"rules": []string{"MATCH,DIRECT"},
	})
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	proc := exec.CommandContext(ctx, core, "-d", dir, "-f", path)
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); proc.Wait() }()
	// Keep the fake VPN servers loopback-only. They accept no legitimate proxy
	// handshakes so the selected pool cannot accidentally reach a public probe.
	first, _ := listen()
	second, _ := listen()
	_, p1, _ := net.SplitHostPort(first)
	_, p2, _ := net.SplitHostPort(second)
	pinned := poolServer("A", "US", p1)
	member := poolServer("B", "DE", p2)
	servers := []models.Server{pinned, member}
	// The production worker locates xray.exe alongside the core binary.
	rt := xkeen.Runtime{Core: xkeen.CoreMihomo, XrayConfDir: filepath.Join(dir, "configs"), CoreBin: filepath.Join(filepath.Dir(xray), "mihomo.exe")}
	c := New(path, dir, rt, func() []models.Server { return servers })
	c.validate = func(ctx context.Context, candidate string) error {
		return exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", candidate).Run()
	}
	t.Cleanup(func() {
		if e := xkeen.PruneCardProxies(rt, map[string]bool{}); e != nil {
			t.Error(e)
		}
	})
	p, err := c.read()
	if err != nil {
		t.Fatal(err)
	}
	for !p.api.ruleMode(ctx) {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(25 * time.Millisecond)
	}
	sources := []string{"A", "B"}
	spec := PoolSpec{Name: "Европа", SourceIDs: []string{}, Countries: []string{"DE", "NL"}}
	pool, err := c.EditMultiPool(ctx, "", &spec, sources)
	if err != nil || pool.MemberCount != 1 {
		t.Fatal("create pool", pool.MemberCount, err)
	}
	if _, err = c.Set(ctx, "claude", xkeen.ServiceTargetID(pinned)); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Set(ctx, "openai", pool.ID); err != nil {
		t.Fatal(err)
	}
	if err = c.SetDefault(ctx, pool.ID); err != nil {
		t.Fatal(err)
	}
	initial, err := c.Default(ctx)
	if err != nil || initial.Current != pool.ID || initial.Name != spec.Name {
		t.Fatal("default pool", initial, err)
	}
	live, err := p.api.selectors(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old := live[cardPrefix+"openai"].Now
	if old == "" || !strings.HasPrefix(old, nodePrefix+pool.ID+"-") || live[cardPrefix+defaultID].Now != old {
		t.Fatal("pool not shared by assigned routes")
	}
	if _, err = c.EditMultiPool(ctx, pool.ID, nil, nil); err == nil {
		t.Fatal("deleted assigned pool")
	}
	spec.Name = "Моя Европа"
	edited, err := c.EditMultiPool(ctx, pool.ID, &spec, sources)
	if err != nil || edited.ID != pool.ID || edited.Name != spec.Name {
		t.Fatal("rename lost pool", err)
	}
	current, err := c.Default(ctx)
	if err != nil || current.Current != pool.ID || current.Name != spec.Name {
		t.Fatal("active rename lost assignment", err)
	}
	disposable, err := c.EditMultiPool(ctx, "", &PoolSpec{Name: "Только B", SourceIDs: []string{"B"}}, sources)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.EditMultiPool(ctx, disposable.ID, nil, nil); err != nil {
		t.Fatal("delete inactive pool", err)
	}
	saved, err := c.MultiPools()
	if err != nil || len(saved) != 1 || saved[0].ID != pool.ID || saved[0].Name != spec.Name {
		t.Fatal("pool list after delete", err)
	}
	// Adding a matching member changes only the selected worker generation.
	third, _ := listen()
	_, p3, _ := net.SplitHostPort(third)
	servers = append(servers, poolServer("C", "NL", p3))
	if err = c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	live, err = p.api.selectors(ctx)
	if err != nil || live[cardPrefix+defaultID].Now == old || live[cardPrefix+"claude"].Now != nodePrefix+xkeen.ServiceTargetID(pinned) {
		t.Fatal("refresh did not change only the pool worker", err)
	}
	servers = []models.Server{pinned}
	if err = c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	live, err = p.api.selectors(ctx)
	if err != nil || live[cardPrefix+defaultID].Now != "REJECT" || live[cardPrefix+"openai"].Now != "REJECT" {
		t.Fatal("empty pool did not fail closed", err)
	}
	// The original MATCH,DIRECT is still present beneath the guards. Exercise
	// the real HTTP listener against an otherwise reachable local destination.
	var reached atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
	defer destination.Close()
	proxyURL, _ := url.Parse("http://" + httpAddr)
	client := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 2 * time.Second}
	if res, e := client.Get(destination.URL); e == nil {
		res.Body.Close()
	}
	if reached.Load() {
		t.Fatal("traffic from an empty pool escaped via the original direct route")
	}
	view, err := c.View(ctx)
	if err != nil || !view.Active {
		t.Fatal("view not active", err)
	}
	for _, s := range view.Services {
		if s.ID == "openai" && (s.Target != pool.ID || !s.Blocked) || s.ID == "claude" && (s.Target != xkeen.ServiceTargetID(pinned) || s.Blocked) {
			t.Fatal("unexpected active assignment", s.ID)
		}
	}
	// Keep a duplicate endpoint for an unrelated service. Removing the
	// source that supplied the manual default must block only that default.
	alias := pinned
	alias.SourceID = "duplicate"
	servers = []models.Server{pinned, alias}
	if err = c.SetDefaultSource(ctx, xkeen.ServiceTargetID(pinned), pinned.SourceID); err != nil {
		t.Fatal(err)
	}
	servers = []models.Server{alias}
	if err = c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	live, err = p.api.selectors(ctx)
	if err != nil || live[cardPrefix+defaultID].Now != "REJECT" || live[cardPrefix+"claude"].Now != nodePrefix+xkeen.ServiceTargetID(alias) {
		t.Fatal("source removal affected the wrong route", err)
	}
}
