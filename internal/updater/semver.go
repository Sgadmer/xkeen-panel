package updater

import (
	"regexp"
	"strconv"
	"strings"
)

type semver struct {
	major, minor, patch int
	suffix              string // prerelease/build metadata, or a legacy git describe tail
}

// Keep the old local-build contract without treating every SemVer prerelease
// as a local edit. A describe tail can follow either a stable or beta tag.
var gitDescribeTail = regexp.MustCompile(`^(?:(.*)-)?[0-9]+-g[0-9a-fA-F]+(?:-dirty)?$`)

func parseSemver(s string) (semver, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	version, metadata, hasMetadata := strings.Cut(s, "+")
	if hasMetadata && !validIdentifiers(metadata, false) {
		return semver{}, false
	}
	core, prerelease, hasPrerelease := strings.Cut(version, "-")
	if hasPrerelease && !validIdentifiers(prerelease, true) {
		return semver{}, false
	}

	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semver{}, false
	}

	var nums [3]int
	for i, part := range parts {
		if !numericIdentifier(part) || len(part) > 1 && part[0] == '0' {
			return semver{}, false
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return semver{}, false
		}
		nums[i] = n
	}

	v := semver{major: nums[0], minor: nums[1], patch: nums[2], suffix: s[len(core):]}
	// A legacy describe suffix can hide the original prerelease identifier.
	if pre := v.prerelease(); pre != "" && !validIdentifiers(pre, true) {
		return semver{}, false
	}
	return v, true
}

func numericIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func validIdentifiers(s string, prerelease bool) bool {
	for _, identifier := range strings.Split(s, ".") {
		if identifier == "" || prerelease && numericIdentifier(identifier) && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
		for _, c := range identifier {
			if c != '-' && !(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') {
				return false
			}
		}
	}
	return true
}

func (v semver) prerelease() string {
	pre, _, _ := strings.Cut(v.suffix, "+")
	if !strings.HasPrefix(pre, "-") {
		return ""
	}
	pre = strings.TrimPrefix(pre, "-")
	// `git describe --tags --dirty` has no distance/hash at an exact tag.
	// Reserve its dirty marker just like the longer legacy describe form.
	if pre == "dirty" {
		return ""
	}
	pre = strings.TrimSuffix(pre, "-dirty")
	if local := gitDescribeTail.FindStringSubmatch(pre); local != nil {
		return local[1]
	}
	return pre
}

func (v semver) isPrerelease() bool { return v.prerelease() != "" }

// newer reports whether release b has greater precedence than installed a.
// Build metadata and legacy describe tails do not affect precedence.
func newer(a, b semver) bool {
	if a.major != b.major {
		return b.major > a.major
	}
	if a.minor != b.minor {
		return b.minor > a.minor
	}
	if a.patch != b.patch {
		return b.patch > a.patch
	}
	ap, bp := a.prerelease(), b.prerelease()
	if ap == "" || bp == "" {
		return ap != "" && bp == ""
	}
	aa, bb := strings.Split(ap, "."), strings.Split(bp, ".")
	for i := 0; i < len(aa) && i < len(bb); i++ {
		if aa[i] == bb[i] {
			continue
		}
		an, bn := numericIdentifier(aa[i]), numericIdentifier(bb[i])
		if an != bn {
			return an // numeric identifiers precede nonnumeric identifiers
		}
		if an && len(aa[i]) != len(bb[i]) {
			return len(bb[i]) > len(aa[i])
		}
		return bb[i] > aa[i]
	}
	return len(bb) > len(aa)
}
