package xkeen

import (
	"errors"
	"testing"
)

func TestPatternExclusionsAreAcceptedAndBounded(t *testing.T) {
	accepted := map[string]string{
		"*.cdn.mydomen.com":    "pattern:*.cdn.mydomen.com",
		"www.mydomen.*":        "pattern:www.mydomen.*",
		"*mydomen*":            "pattern:*mydomen*",
		"vk.*":                 "pattern:vk.*",
		"CDN-*.Example.net.":   "pattern:cdn-*.example.net",
		"pattern:*.shop.pht.*": "pattern:*.shop.pht.*",
	}
	for input, want := range accepted {
		entry, err := NormalizeExclusion(input, "")
		if err != nil || entry.Type != "pattern" || entry.Value != want {
			t.Errorf("%q: %+v %v, want %s", input, entry, err, want)
			continue
		}
		// What is stored reads back unchanged.
		again, err := NormalizeExclusion(entry.Value, "")
		if err != nil || again != entry {
			t.Errorf("%q does not survive being read back: %+v %v", input, again, err)
		}
	}

	broad := []string{"*", "*.*", "*.com", "*.co.uk", "*.co.jp", "*.shop", "www.*", "*a*", "*h*", "*ru", "*.c*", "*-7.*"}
	for _, input := range broad {
		if _, err := NormalizeExclusion(input, ""); !errors.Is(err, ErrBroadPattern) && !errors.Is(err, ErrBadPattern) {
			t.Errorf("a pattern for unrelated sites was accepted: %q (%v)", input, err)
		}
	}
	malformed := []string{"**.example.com", "*.exa mple.com", "*..example.com", ".*.example.com", "*.example.com/path", "*.*.*.*.*.example.com", "*.-bad.example.com", "*.пример.рф"}
	for _, input := range malformed {
		if _, err := NormalizeExclusion(input, ""); err == nil {
			t.Errorf("a malformed pattern was accepted: %q", input)
		}
	}
}

func TestPatternMatchesWholeNames(t *testing.T) {
	cases := []struct {
		pattern string
		yes, no []string
	}{
		{"*.cdn.mydomen.com", []string{"a.cdn.mydomen.com", "a.b.cdn.mydomen.com"}, []string{"cdn.mydomen.com", "mydomen.com", "a.cdn.mydomen.com.evil.org"}},
		{"www.mydomen.*", []string{"www.mydomen.com", "www.mydomen.co.uk"}, []string{"mydomen.com", "x.www.mydomen.com", "wwwxmydomen.com"}},
		{"*mydomen*", []string{"mydomen.com", "api.mydomen.net", "notmydomen.org"}, []string{"my-domen.com"}},
		{"vk.*", []string{"vk.com", "vk.ru"}, []string{"m.vk.com", "avk.com"}},
	}
	for _, c := range cases {
		match := PatternMatcher(c.pattern)
		for _, host := range c.yes {
			if !match(host) {
				t.Errorf("%s must match %s", c.pattern, host)
			}
		}
		for _, host := range c.no {
			if match(host) {
				t.Errorf("%s must not match %s", c.pattern, host)
			}
		}
	}
}

func TestPatternExpressionIsRecognisedExactly(t *testing.T) {
	for _, pattern := range []string{"*.cdn.mydomen.com", "www.mydomen.*", "*mydomen*", "cdn-*.example.net"} {
		got, ok := PatternFromRegex(PatternRegex(pattern))
		if !ok || got != pattern {
			t.Errorf("%s -> %s -> %q %v", pattern, PatternRegex(pattern), got, ok)
		}
	}
	// Expressions the panel never writes are not exclusions of the owner.
	foreign := []string{"", "^$", "^.*$", `^.*\.com$`, `.*\.mydomen\.com`, `^(a|b)\.mydomen\.com$`, `^.+\.mydomen\.com$`, `^[a-z]+\.mydomen\.com$`, `^.*\.MYDOMEN\.com$`, `^www\.mydomen\..*`}
	for _, expr := range foreign {
		if pattern, ok := PatternFromRegex(expr); ok {
			t.Errorf("a foreign expression was taken for the pattern %q: %s", pattern, expr)
		}
	}
	entry, err := NormalizeExclusion("*.cdn.mydomen.com", "")
	if err != nil || xrayDomain(entry) != `regexp:^.*\.cdn\.mydomen\.com$` {
		t.Fatalf("Xray form: %q %v", xrayDomain(entry), err)
	}
	plain, _ := NormalizeExclusion("mydomen.com", "")
	if xrayDomain(plain) != "domain:mydomen.com" {
		t.Fatalf("a plain domain changed its Xray form: %q", xrayDomain(plain))
	}
}
