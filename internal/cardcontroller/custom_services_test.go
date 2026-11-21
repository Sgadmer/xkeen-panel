package cardcontroller

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

const customCard, otherCustomCard = "custom-0a1b2c3d", "custom-11223344"

func customService(t *testing.T, id, name string, addresses ...string) xkeen.CustomService {
	t.Helper()
	service, err := xkeen.NormalizeCustomService(id, name, addresses)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func registerCustom(t *testing.T, services ...xkeen.CustomService) {
	t.Helper()
	xkeen.SetCustomServices(services)
	t.Cleanup(func() { xkeen.SetCustomServices(nil) })
}

// An address belongs to one card. The owner's card may not claim what a
// built-in card, its downloaded list or another custom card already has.
func TestCustomServiceCanNotClaimAnotherCardsAddress(t *testing.T) {
	dir := t.TempDir()
	c := New(filepath.Join(dir, "config.yaml"), dir, xkeen.Runtime{}, func() []models.Server { return nil })
	registerCustom(t, customService(t, otherCustomCard, "Форум", "forum.example.org", "full:chat.example.net", "203.0.113.0/24"))
	p := profile{assigned: map[string]string{}, doc: map[string]interface{}{serviceListsKey: analyticsSnapshot(t, dir)}}

	refused := map[string]string{
		"claude.ai":                   "Claude",       // the built-in domain itself
		"full:api.anthropic.com":      "Claude",       // a host inside it
		"anthropic.com":               "Claude",       //
		"160.79.104.10":               "Claude",       // inside a published network
		"160.0.0.0/8":                 "Claude",       // a network that contains one
		"api.openai.com":              "ChatGPT",      //
		"full:api.revenuecat.com":     "ChatGPT",      // a shared dependency routed by the card
		"sub.collector.fixture":       "Аналитика",    // inside the downloaded list of another card
		"youtube.com":                 "YouTube",      // whatever its kill switch says
		"steampowered.com":            "Steam",        // even a card that goes direct
		"com.example.org.youtube.com": "YouTube",      //
		"149.154.167.99":              "Telegram",     // a built-in network of an ordinary card
		"forum.example.org":           "Форум",        // another card of the owner
		"new.forum.example.org":       "Форум",        //
		"example.org":                 "Форум",        // a domain that would contain it
		"full:chat.example.net":       "Форум",        //
		"203.0.113.128/25":            "Форум",        //
		"co.uk":                       "Amazon",       // a zone that contains a card's domain
		"googleapis.com":              "YouTube",      // contains youtubei.googleapis.com
		"gemini.google.com":           "YouTube|Goog", // inside Google; whichever card is met first
	}
	for address, card := range refused {
		err := c.customConflict(p, customService(t, customCard, "Новый", address))
		named := false
		for _, name := range strings.Split(card, "|") {
			named = named || err != nil && strings.Contains(err.Error(), name)
		}
		if !named {
			t.Errorf("%s: got %v, want a refusal naming %q", address, err, card)
		}
	}
	for _, address := range []string{"bank.example.org", "full:pay.example.net", "192.0.2.0/24", "8.8.8.8", "example.com", "chat.example.net.evil.example"} {
		if err := c.customConflict(p, customService(t, customCard, "Новый", address)); err != nil {
			t.Errorf("%s was refused: %v", address, err)
		}
	}
	// Editing a card does not make it collide with its own addresses.
	if err := c.customConflict(p, customService(t, otherCustomCard, "Форум", "forum.example.org", "more.example.org")); err != nil {
		t.Fatalf("a card collided with itself: %v", err)
	}
	// Two cards may not share a name either: it is how the owner tells them apart.
	if err := uniqueCardName(customService(t, customCard, "форум", "x.example.com")); err == nil {
		t.Error("a second card took the name of the first")
	}
	if err := uniqueCardName(customService(t, customCard, "youtube", "x.example.com")); err == nil {
		t.Error("a custom card took the name of a built-in one")
	}
	if err := uniqueCardName(customService(t, otherCustomCard, "Форум 2", "forum.example.org")); err != nil {
		t.Errorf("renaming a card was refused: %v", err)
	}
}

// The owner's rules stand after the rules of every built-in card and are not
// promoted above them, whatever their addresses are.
func TestCustomServiceRulesFollowTheBuiltInCards(t *testing.T) {
	registerCustom(t, customService(t, customCard, "Мой банк", "bank.example.org", "full:pay.example.net", "203.0.113.0/24", "2001:db8::/32"))
	key := strings.Repeat("a", 64)
	doc := map[string]interface{}{
		"mode": "rule", "proxies": []interface{}{}, serviceAutoKey: true,
		"rules": []interface{}{"DOMAIN-SUFFIX,direct.example.org,DIRECT", "MATCH,DIRECT"},
	}
	assigned := map[string]string{customCard: key}
	services := cardCatalogForTest(t)
	for _, service := range services {
		if !service.Custom {
			assigned[service.ID] = key
		}
	}
	assigned["steam"] = directTarget
	p := profile{doc: doc, assigned: assigned}
	if _, err := render(&p, services, map[string]cardEndpoint{key: {name: nodePrefix + key}}, true); err != nil {
		t.Fatal(err)
	}
	rules := namesOf(p.doc["rules"])
	group := cardPrefix + customCard
	first, lastBuiltIn, exclusion := -1, -1, -1
	seen := map[string]bool{}
	for i, rule := range rules {
		fields, end := targetPart(rule)
		switch {
		case fields[end] == group:
			if first < 0 {
				first = i
			}
			seen[strings.Join(fields[:end], ",")] = true
		case strings.HasPrefix(fields[end], cardPrefix) && serviceOfTag(fields[end]) != "" && serviceOfTag(fields[end]) != customCard:
			lastBuiltIn = i
		case rule == "DOMAIN-SUFFIX,direct.example.org,DIRECT":
			exclusion = i
		}
	}
	if first < 0 || lastBuiltIn < 0 || first < lastBuiltIn {
		t.Fatalf("custom rules start at %d, built-in rules end at %d", first, lastBuiltIn)
	}
	if exclusion < 0 || exclusion > first {
		t.Fatalf("the owner's exclusion (%d) must stay above the owner's card (%d)", exclusion, first)
	}
	for _, want := range []string{"DOMAIN-SUFFIX,bank.example.org", "DOMAIN,pay.example.net", "IP-CIDR,203.0.113.0/24", "IP-CIDR,2001:db8::/32"} {
		if !seen[want] {
			t.Errorf("no rule %q for the owner's card: %v", want, seen)
		}
	}
	// The card is protected by default: a second rule ends an unusable route in a block.
	blocked := false
	for _, rule := range rules[first:] {
		if strings.HasPrefix(rule, "DOMAIN-SUFFIX,bank.example.org,") && !strings.HasSuffix(rule, ","+group) {
			blocked = strings.Contains(rule, cardPrefix+"reject")
		}
	}
	if !blocked {
		t.Error("the owner's card has no fail-closed rule behind its route")
	}
	if groups := list(p.doc["proxy-groups"]); len(groups) == 0 {
		t.Fatal("no groups rendered")
	}
}

// The whole life of an owner's card against a real core: created, changed and
// removed through the API, each time accepted and loaded by Mihomo.
func TestLiveCustomServices(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("real Mihomo fixture unavailable")
	}
	t.Cleanup(func() { xkeen.SetCustomServices(nil) })
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	raw, _ := json.Marshal(map[string]interface{}{"external-controller": address, "secret": "synthetic-token", "mode": "rule", "rules": []string{"DOMAIN-SUFFIX,direct.example.org,DIRECT", "MATCH,DIRECT"}})
	if err = os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	proc := exec.CommandContext(ctx, core, "-d", dir, "-f", config)
	if err = proc.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); proc.Wait() }()
	c := New(config, dir, xkeen.Runtime{Core: xkeen.CoreMihomo, XrayConfDir: filepath.Join(dir, "xray")}, func() []models.Server { return nil })
	c.validate = func(ctx context.Context, p string) error {
		return exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", p).Run()
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
	router := chi.NewRouter()
	router.Route("/api", func(r chi.Router) { c.MountCustomServices(r, dir) })
	ask := func(method, path, body string) (int, []customServiceView, string) {
		t.Helper()
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		var answer struct {
			Services []customServiceView `json:"services"`
			Error    string              `json:"error"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &answer)
		return w.Code, answer.Services, answer.Error
	}
	rulesOf := func(id string) []string {
		t.Helper()
		saved, err := c.read()
		if err != nil {
			t.Fatal(err)
		}
		var found []string
		for _, rule := range namesOf(saved.doc["rules"]) {
			if fields, end := targetPart(rule); fields[end] == cardPrefix+id {
				found = append(found, strings.Join(fields[:end], ","))
			}
		}
		return found
	}

	if code, _, problem := ask("POST", "/api/custom-services", `{"name":"Claude 2","addresses":["api.anthropic.com"]}`); code == 200 || !strings.Contains(problem, "Claude") {
		t.Fatalf("an address of Claude was accepted into a custom card: %d %s", code, problem)
	}
	code, services, problem := ask("POST", "/api/custom-services", `{"name":"Мой банк","addresses":["bank.example.org","203.0.113.0/24"]}`)
	if code != 200 || len(services) != 1 || !xkeen.IsCustomService(services[0].ID) {
		t.Fatalf("the card was not created: %d %s", code, problem)
	}
	id := services[0].ID
	if rules := rulesOf(id); !slices.Contains(rules, "DOMAIN-SUFFIX,bank.example.org") || !slices.Contains(rules, "IP-CIDR,203.0.113.0/24") {
		t.Fatalf("the core has no rules of the new card: %v", rules)
	}
	saved, err := c.read()
	if err != nil || saved.assigned[id] != allPoolID {
		t.Fatalf("a new card must start on the automatic pool: %q %v", saved.assigned[id], err)
	}
	if stored, err := xkeen.LoadCustomServices(dir); err != nil || len(stored) != 1 || stored[0].ID != id {
		t.Fatalf("the card was not saved: %v %v", stored, err)
	}
	// The kill switch of the card is its own setting.
	if _, err = c.SetKillSwitch(ctx, nil, id, "off"); err != nil {
		t.Fatalf("the kill switch of a custom card was refused: %v", err)
	}
	if code, _, problem = ask("PUT", "/api/custom-services/"+id, `{"name":"Мой банк","addresses":["pay.example.net"]}`); code != 200 {
		t.Fatalf("the card was not changed: %d %s", code, problem)
	}
	if rules := rulesOf(id); !slices.Contains(rules, "DOMAIN-SUFFIX,pay.example.net") || slices.Contains(rules, "DOMAIN-SUFFIX,bank.example.org") || slices.Contains(rules, "IP-CIDR,203.0.113.0/24") {
		t.Fatalf("the rules do not follow the edited card: %v", rules)
	}
	if code, _, _ = ask("PUT", "/api/custom-services/custom-00000000", `{"name":"x","addresses":["a.example.com"]}`); code != 404 {
		t.Fatalf("changing a missing card answered %d", code)
	}
	if code, services, problem = ask("DELETE", "/api/custom-services/"+id, ""); code != 200 || len(services) != 0 {
		t.Fatalf("the card was not removed: %d %s", code, problem)
	}
	saved, err = c.read()
	if err != nil || saved.assigned[id] != "" || len(rulesOf(id)) != 0 {
		t.Fatalf("a removed card left its route behind: %q %v", saved.assigned[id], err)
	}
	if policy, err := readKillSwitch(saved.doc); err != nil || policy.Services[id] != "" {
		t.Fatalf("a removed card left its kill switch setting behind: %+v %v", policy, err)
	}
	if view, err := c.View(ctx); err != nil || !view.Active {
		t.Fatalf("card routes are not active after the removal: %v", err)
	}
}

func TestCustomServiceHasItsOwnKillSwitchAndSurvivesRemoval(t *testing.T) {
	registerCustom(t, customService(t, customCard, "Мой банк", "bank.example.org"))
	key := strings.Repeat("a", 64)
	doc := map[string]interface{}{
		killSwitchKey: map[string]interface{}{"enabled": true, "services": map[string]interface{}{customCard: "off", otherCustomCard: "off", "youtube": "off"}},
	}
	policy, err := readKillSwitch(doc)
	if err != nil {
		t.Fatalf("a setting of a removed card broke the policy: %v", err)
	}
	if policy.Protects(customCard) || !policy.Protects("claude") || policy.Protects("youtube") {
		t.Fatalf("the owner's card does not follow its own kill switch: %+v", policy)
	}
	if _, kept := policy.Services[otherCustomCard]; kept {
		t.Fatal("the setting of a removed card was kept")
	}
	if !knownCard(customCard) || knownCard(otherCustomCard) || !knownCard("claude") || knownCard("custom-") {
		t.Fatal("cards are told apart wrongly")
	}
	for tag, want := range map[string]string{
		cardPrefix + customCard: customCard, cardPrefix + "guard-" + customCard: customCard, cardPrefix + "claude": "claude",
		cardPrefix + otherCustomCard: "", "DIRECT": "", cardPrefix + customCard + "-x": "",
	} {
		if got := serviceOfTag(tag); got != want {
			t.Errorf("serviceOfTag(%s) = %q, want %q", tag, got, want)
		}
	}
	// With its kill switch on and a VPN route the card guards its addresses
	// against exclusions like any other.
	c := New(filepath.Join(t.TempDir(), "config.yaml"), t.TempDir(), xkeen.Runtime{}, func() []models.Server { return nil })
	guard := c.newExclusionGuard(profile{assigned: map[string]string{customCard: key}, doc: map[string]interface{}{}})
	if id, _, refusal := guard.conflict(exclusion(t, "online.bank.example.org")); id != customCard || refusal == nil {
		t.Fatalf("an exclusion took an address from the owner's protected card: %q %v", id, refusal)
	}
}
