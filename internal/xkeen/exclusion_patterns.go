package xkeen

import (
	"errors"
	"regexp"
	"strings"
)

// A pattern exclusion is a host name with `*` standing for any run of
// characters, dots included: `www.example.*`, `*.cdn.example.com`, `*example*`.
// It matches the whole name. The same pattern is turned into a regular
// expression for either core, so both treat it identically.

var (
	ErrBadPattern   = errors.New("в шаблоне допустимы латинские буквы, цифры, дефис, точка и до четырёх звёздочек")
	ErrBroadPattern = errors.New("шаблон слишком широкий: под него попадают посторонние сайты. Уточните его, например *.example.com или example.*")
)

const patternPrefix = "pattern:"

// Names that stand for "any site at all" in a few common zones. A pattern
// that matches one of them is not about a particular site.
var patternProbeZones = []string{
	"com", "net", "org", "ru", "io", "co", "info", "app", "dev", "xyz", "de", "fr", "cn", "me", "tv", "ai",
	"su", "online", "site", "top", "pro", "cloud", "link", "co.uk", "com.ru", "com.tr",
}

func normalizePattern(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) < 3 || len(value) > 253 || strings.Contains(value, "**") || strings.Contains(value, "..") ||
		strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return "", ErrBadPattern
	}
	stars, literal := 0, 0
	for _, c := range value {
		switch {
		case c == '*':
			stars++
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			literal++
		case c == '-', c == '.':
		default:
			return "", ErrBadPattern
		}
	}
	if stars < 1 || stars > 4 {
		return "", ErrBadPattern
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) > 63 || !strings.Contains(label, "*") && (label[0] == '-' || label[len(label)-1] == '-') {
			return "", ErrBadPattern
		}
	}
	// Open on both ends, the pattern is a search for a fragment anywhere in a
	// name: a short fragment is found in countless unrelated names.
	need := 2
	if strings.HasPrefix(value, "*") && strings.HasSuffix(value, "*") {
		need = 4
	}
	if literal < need {
		return "", ErrBroadPattern
	}
	// "*.zone" is every site of a zone, and "*.co.jp" of a two-part one. A site
	// with its sub-domains needs no pattern: its plain domain already covers them.
	if rest, ok := strings.CutPrefix(value, "*."); ok && !strings.Contains(rest, "*") {
		labels := strings.Split(rest, ".")
		if len(labels) == 1 || len(labels) == 2 && len(labels[0]) <= 3 && len(labels[1]) <= 3 {
			return "", ErrBroadPattern
		}
	}
	match := regexp.MustCompile(PatternRegex(value)).MatchString
	for _, zone := range patternProbeZones {
		for _, host := range []string{"qzjxkv." + zone, "www.qzjxkv." + zone, "a.b.qzjxkv." + zone, "qzjxkv-7." + zone} {
			if match(host) {
				return "", ErrBroadPattern
			}
		}
	}
	return value, nil
}

// PatternRegex is the anchored regular expression of a pattern. It contains
// no commas or brackets, so it can stand inside a rule of either core.
func PatternRegex(pattern string) string {
	var b strings.Builder
	b.WriteByte('^')
	for _, c := range pattern {
		switch c {
		case '*':
			b.WriteString(".*")
		case '.':
			b.WriteString(`\.`)
		default:
			b.WriteRune(c)
		}
	}
	b.WriteByte('$')
	return b.String()
}

// PatternFromRegex recovers the pattern from an expression PatternRegex made.
// Any other expression is refused: only patterns the panel itself accepts are
// treated as the owner's exclusions.
func PatternFromRegex(expr string) (string, bool) {
	if len(expr) < 2 || expr[0] != '^' || expr[len(expr)-1] != '$' {
		return "", false
	}
	var b strings.Builder
	for body := expr[1 : len(expr)-1]; body != ""; {
		switch {
		case strings.HasPrefix(body, ".*"):
			b.WriteByte('*')
			body = body[2:]
		case strings.HasPrefix(body, `\.`):
			b.WriteByte('.')
			body = body[2:]
		case body[0] >= 'a' && body[0] <= 'z', body[0] >= '0' && body[0] <= '9', body[0] == '-':
			b.WriteByte(body[0])
			body = body[1:]
		default:
			return "", false
		}
	}
	pattern, err := normalizePattern(b.String())
	if err != nil || pattern != b.String() {
		return "", false
	}
	return pattern, true
}

// ExclusionPattern returns the pattern of a pattern exclusion.
func ExclusionPattern(e Exclusion) (string, bool) {
	if e.Type != "pattern" {
		return "", false
	}
	return strings.CutPrefix(e.Value, patternPrefix)
}

// PatternMatcher reports whether host names match the pattern.
func PatternMatcher(pattern string) func(host string) bool {
	return regexp.MustCompile(PatternRegex(pattern)).MatchString
}

// xrayDomain is the value of an exclusion in Xray's domain matcher syntax.
func xrayDomain(e Exclusion) string {
	if pattern, ok := ExclusionPattern(e); ok {
		return "regexp:" + PatternRegex(pattern)
	}
	return e.Value
}
