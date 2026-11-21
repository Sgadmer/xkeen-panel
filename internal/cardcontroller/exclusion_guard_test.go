package cardcontroller

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func exclusion(t *testing.T, value string) xkeen.Exclusion {
	t.Helper()
	entry, err := xkeen.NormalizeExclusion(value, "")
	if err != nil {
		t.Fatalf("%s: %v", value, err)
	}
	return entry
}

func TestExclusionCanNotTakeAnAddressFromAProtectedCard(t *testing.T) {
	dir := t.TempDir()
	c := New(filepath.Join(dir, "config.yaml"), dir, xkeen.Runtime{}, func() []models.Server { return nil })
	p := profile{
		assigned: map[string]string{"steam": directTarget},
		doc: map[string]interface{}{
			serviceListsKey: analyticsSnapshot(t, dir),
			killSwitchKey:   map[string]interface{}{"enabled": true, "services": map[string]interface{}{"youtube": "off"}},
		},
	}
	guard := c.newExclusionGuard(p)

	refused := map[string]string{
		"claude.ai":                        "claude",    // the card's own domain
		"full:api.anthropic.com":           "claude",    // a host inside it
		"ai":                               "",          // not a valid exclusion at all, skipped below
		"160.79.104.10":                    "claude",    // inside a published network
		"160.79.0.0/16":                    "claude",    // a network that contains one
		"chatgpt.com":                      "openai",    //
		"full:api.revenuecat.com":          "openai",    // a shared dependency routed by the card
		"198.51.100.1":                     "openai",    // the downloaded voice list
		"full:api3.siftscience.com":        "analytics", // a built-in collector host
		"full:collector.anthropic.fixture": "claude",    // also inside a domain of the Claude list, which comes first
		"sub.collector.fixture":            "analytics", // inside a domain of the downloaded list
		"fixture":                          "",
		"anthropic.fixture":                "claude", // the downloaded list of the card
		"x.com":                            "twitter",
	}
	for value, card := range refused {
		entry, err := xkeen.NormalizeExclusion(value, "")
		if err != nil {
			continue // "ai" and "fixture" are not addresses the panel accepts
		}
		id, name, refusal := guard.conflict(entry)
		if id != card || refusal == nil || name == "" || !strings.Contains(refusal.Error(), name) {
			t.Errorf("%s: got card %q (%v), want a refusal naming %q", value, id, refusal, card)
		}
	}

	allowed := []string{
		"example.org", "full:www.example.org", "8.8.8.8", "203.0.113.0/24",
		"steampowered.com", // the Steam card goes direct anyway
		"youtube.com",      // its kill switch is off: the owner decided
		"www.mydomen.*", "*.cdn.mydomen.com",
	}
	for _, value := range allowed {
		if id, _, refusal := guard.conflict(exclusion(t, value)); refusal != nil {
			t.Errorf("%s was refused because of %q: %v", value, id, refusal)
		}
	}

	// A pattern is refused when it reaches into any card, protected or not:
	// the card decides the route of its own addresses.
	for value, card := range map[string]string{"*claude*": "claude", "*.youtube.*": "youtube", "*steam*": "steam", "api.anthropic.*": "claude"} {
		id, _, refusal := guard.conflict(exclusion(t, value))
		if id != card || refusal == nil {
			t.Errorf("%s: got %q %v, want a refusal for %q", value, id, refusal, card)
		}
	}

	// Entries added before a card was protected are pointed out, not removed.
	view := c.exclusionsView(p, xkeen.Exclusions{Entries: []xkeen.Exclusion{exclusion(t, "example.org"), exclusion(t, "chatgpt.com")}})
	if len(view.Covered) != 1 || view.Covered[exclusion(t, "chatgpt.com").ID] == "" {
		t.Fatalf("covered entries: %v", view.Covered)
	}
}

// The core itself must accept the rule a pattern exclusion becomes.
func TestMihomoAcceptsPatternExclusionRule(t *testing.T) {
	core := os.Getenv("MIHOMO_TEST_BINARY")
	if core == "" {
		t.Skip("requires local Mihomo")
	}
	dir := t.TempDir()
	rules := []string{}
	for _, value := range []string{"www.mydomen.*", "*.cdn.mydomen.com", "*mydomen*", "cdn-*.example.net"} {
		rules = append(rules, exclusionRule(exclusion(t, value)))
	}
	rules = append(rules, "MATCH,DIRECT")
	raw, _ := json.Marshal(map[string]interface{}{"mode": "rule", "rules": rules})
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("the core refused pattern rules: %v\n%s", err, out)
	}
}

func TestPatternExclusionIsARuleBelowTheCards(t *testing.T) {
	pattern := exclusion(t, "www.mydomen.*")
	rule := exclusionRule(pattern)
	if rule != `DOMAIN-REGEX,^www\.mydomen\..*$,DIRECT` {
		t.Fatalf("rule: %s", rule)
	}
	back, ok := directEntry(rule)
	if !ok || back != pattern {
		t.Fatalf("the rule is not recognised as the same exclusion: %+v %v", back, ok)
	}
	fields, target := targetPart(rule)
	if !protectedDirectRule(fields, target) {
		t.Fatal("a pattern exclusion would be dropped in protected routing")
	}
	foreign, end := targetPart(`DOMAIN-REGEX,^.*$,DIRECT`)
	if protectedDirectRule(foreign, end) {
		t.Fatal("an arbitrary expression was accepted as a deliberate exclusion")
	}
	if _, ok := directEntry(`DOMAIN-REGEX,^.*$,DIRECT`); ok {
		t.Fatal("an arbitrary expression was listed as the owner's exclusion")
	}

	key := strings.Repeat("a", 64)
	plain := exclusionRule(exclusion(t, "plain.example.org"))
	doc := map[string]interface{}{
		"mode":    "rule",
		"proxies": []interface{}{},
		// The pattern stands first on disk, as the owner added it first.
		"rules": []interface{}{rule, plain, "MATCH,DIRECT"},
	}
	p := profile{doc: doc, assigned: map[string]string{"claude": key, "youtube": key}}
	services := cardCatalogForTest(t)
	if _, err := render(&p, services, map[string]cardEndpoint{key: {name: nodePrefix + key}}, true); err != nil {
		t.Fatal(err)
	}
	position := func(prefix string) int {
		last := -1
		for i, rule := range namesOf(p.doc["rules"]) {
			if strings.HasPrefix(rule, prefix) {
				last = i
			}
		}
		return last
	}
	patternAt, plainAt := position("DOMAIN-REGEX,"), position("DOMAIN-SUFFIX,plain.example.org,")
	youtubeAt, claudeAt := position("DOMAIN-SUFFIX,youtube.com,"+cardPrefix+"youtube"), position("DOMAIN-SUFFIX,claude.ai,"+cardPrefix+"claude")
	if patternAt < 0 || plainAt < 0 || youtubeAt < 0 || claudeAt < 0 {
		t.Fatalf("rules are missing: pattern %d, plain %d, youtube %d, claude %d", patternAt, plainAt, youtubeAt, claudeAt)
	}
	if !(claudeAt < plainAt && plainAt < youtubeAt && youtubeAt < patternAt) {
		t.Fatalf("order: claude %d, plain exclusion %d, youtube %d, pattern %d — a pattern must come after every card", claudeAt, plainAt, youtubeAt, patternAt)
	}

	// A second pass over its own output, as read back from disk, keeps both
	// exclusions and their order.
	saved, _ := json.Marshal(p.doc)
	if err := json.Unmarshal(saved, &p.doc); err != nil {
		t.Fatal(err)
	}
	if _, err := render(&p, services, map[string]cardEndpoint{key: {name: nodePrefix + key}}, true); err != nil {
		t.Fatal(err)
	}
	if position("DOMAIN-REGEX,") != patternAt || position("DOMAIN-SUFFIX,plain.example.org,") != plainAt {
		t.Fatal("rendering again moved or lost an exclusion")
	}
}
