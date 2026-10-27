package updater

import "testing"

func TestPrereleaseUpdatePrecedence(t *testing.T) {
	cases := []struct {
		current, release string
		want             bool
	}{
		{"v3.0.0-beta.1", "v3.0.0-beta.2", true},
		{"v3.0.0-beta.9", "v3.0.0-beta.10", true},
		{"v3.0.0-beta.10", "v3.0.0-beta.9", false},
		{"v3.0.0-beta.2", "v3.0.0", true},
		{"v3.0.0", "v3.0.0-beta.2", false},
		{"v3.0.0", "v3.0.1-beta.1", true},
		{"v3.0.0-beta.1+build.1", "v3.0.0-beta.1+build.2", false},
		{"v3.0.0+build.1", "v3.0.0+build.2", false},
		{"v3.0.0-beta.999999999999999999999", "v3.0.0-beta.1000000000000000000000", true},
		{"v3.0.0-4-gabc", "v3.0.0", false},
		{"v3.0.0", "v3.0.0-4-gabc-dirty", false},
		{"v3.0.0-beta.1-4-gabc-dirty", "v3.0.0-beta.1", false},
		{"v3.0.0-beta.1-4-gabc-dirty", "v3.0.0-beta.2", true},
		{"v3.0.0-4-gabc-dirty", "v3.0.1", true},
		{"v3.0.0-dirty", "v3.0.0", false},
		{"v3.0.0", "v3.0.0-dirty", false},
		{"v3.0.0-dirty", "v3.0.1", true},
		{"v3.0.0-beta.1-dirty", "v3.0.0-beta.1", false},
		{"v3.0.0-beta.1", "v3.0.0-beta.1-dirty", false},
		{"v3.0.0-beta.1-dirty", "v3.0.0-beta.2", true},
		{"v3.0.0-beta.1-dirty", "v3.0.0", true},
	}
	for _, c := range cases {
		t.Run(c.current+" to "+c.release, func(t *testing.T) {
			a, okA := parseSemver(c.current)
			b, okB := parseSemver(c.release)
			if !okA || !okB {
				t.Fatal("valid fixture rejected")
			}
			if got := newer(a, b); got != c.want {
				t.Fatalf("newer = %v, want %v", got, c.want)
			}
		})
	}
}

func TestSemverPublishedPrereleaseOrder(t *testing.T) {
	ordered := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"}
	for i, first := range ordered {
		a, ok := parseSemver(first)
		if !ok {
			t.Fatal("valid fixture rejected:", first)
		}
		for j, second := range ordered {
			b, _ := parseSemver(second)
			if got := newer(a, b); got != (j > i) {
				t.Errorf("newer(%s, %s) = %v", first, second, got)
			}
		}
	}
}

func TestParseSemverRejectsMalformedTags(t *testing.T) {
	for _, tag := range []string{"v01.2.3", "v1.02.3", "v1.2.03", "v+1.2.3", "v1.2.3-", "v1.2.3+", "v1.2.3-beta..2", "v1.2.3-beta.01", "v1.2.3-01", "v1.2.3+build..2", "v1.2.3+build+2", "v1.2.3-beta_2", "v1.2.3-бета.2", "v1.2.3-beta.01-2-gabc", "v1.2.3.4"} {
		if _, ok := parseSemver(tag); ok {
			t.Errorf("accepted malformed tag %q", tag)
		}
	}
}

func TestSemverPrereleaseClassification(t *testing.T) {
	for tag, want := range map[string]bool{
		"v3.0.0-beta.1":              true,
		"v3.0.0-rc.2+build.01":       true,
		"v3.0.0-beta.1-3-gabc-dirty": true,
		"v3.0.0-beta.1-dirty":        true,
		"v3.0.0":                     false,
		"v3.0.0-dirty":               false,
		"v3.0.0-dirty+build.01":      false,
		"v3.0.0+build.01":            false,
		"v3.0.0-3-gabc-dirty":        false,
	} {
		v, ok := parseSemver(tag)
		if !ok || v.isPrerelease() != want {
			t.Errorf("classification(%q): parsed=%v, prerelease=%v, want %v", tag, ok, v.isPrerelease(), want)
		}
	}
}
