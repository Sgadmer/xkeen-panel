package geoip

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// RuleFile contains only the REFILTER section. Domain data that uses a keyword
// or a regex needs the classical matcher to preserve the source semantics.
type RuleFile struct {
	Data     []byte
	Behavior string
	Count    int
}

func ReadRefilter(path string, domains bool) (RuleFile, error) {
	var result RuleFile
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 32<<20 {
		return result, errors.New("файл геобазы Re:filter отсутствует или имеет недопустимый размер")
	}
	data, err := os.ReadFile(path)
	if err != nil || int64(len(data)) != st.Size() {
		return result, errors.New("не удалось прочитать геобазу Re:filter")
	}
	var section []byte
	valid := true
	ok := walk(data, func(field, wire int, _ uint64, entry []byte) bool {
		if field != 1 || wire != 2 {
			valid = false
			return false
		}
		if countryCodeOf(entry) == "REFILTER" {
			if section != nil {
				valid = false
				return false
			}
			section = entry
		}
		return true
	})
	if !ok || !valid || section == nil {
		return result, errors.New("раздел REFILTER отсутствует или повреждён")
	}
	result.Behavior = "ipcidr"
	if domains {
		result.Behavior = "domain"
	}
	write := func(out *bytes.Buffer, classical bool) bool {
		return walk(section, func(field, wire int, n uint64, item []byte) bool {
			if field == 1 && wire == 2 {
				return true
			}
			if !domains && field == 3 && wire == 0 && n == 0 {
				return true
			}
			if field != 2 || wire != 2 {
				valid = false
				return false
			}
			kind, value, ok := refilterEntry(item, domains)
			if !ok {
				valid = false
				return false
			}
			if domains {
				if kind < 2 && !classical {
					result.Behavior = "classical"
					return true
				}
				if classical {
					out.WriteString([]string{"DOMAIN-KEYWORD,", "DOMAIN-REGEX,", "DOMAIN-SUFFIX,", "DOMAIN,"}[kind])
				} else if kind == 2 {
					out.WriteString("+.")
				}
			}
			out.WriteString(value)
			out.WriteByte('\n')
			result.Count++
			if result.Count > 1_000_000 || out.Len() > 32<<20 {
				valid = false
				return false
			}
			return true
		})
	}
	var out bytes.Buffer
	ok = write(&out, false)
	if ok && valid && result.Behavior == "classical" {
		out.Reset()
		result.Count = 0
		ok = write(&out, true)
	}
	if !ok || !valid || result.Count == 0 {
		return RuleFile{}, errors.New("некорректная или неподдерживаемая запись REFILTER")
	}
	result.Data = out.Bytes()
	return result, nil
}

func refilterEntry(data []byte, domains bool) (uint64, string, bool) {
	var kind uint64
	var raw []byte
	valid := true
	seenNumber := false
	ok := walk(data, func(field, wire int, n uint64, b []byte) bool {
		switch {
		case field == 1 && domains && wire == 0, field == 2 && !domains && wire == 0:
			valid = !seenNumber
			seenNumber, kind = true, n
		case field == 2 && domains && wire == 2, field == 1 && !domains && wire == 2:
			valid = raw == nil
			raw = b
		case domains && field == 3 && wire == 2:
			// No attribute selector was requested: tagged entries also match.
		default:
			valid = false
		}
		return valid
	})
	if !ok || !valid || len(raw) == 0 {
		return 0, "", false
	}
	if !domains {
		ip, ok := netip.AddrFromSlice(raw)
		// A /0 in this list would send the entire IP family through the VPN.
		if !ok || kind == 0 || kind > uint64(ip.BitLen()) {
			return 0, "", false
		}
		return kind, netip.PrefixFrom(ip, int(kind)).Masked().String(), true
	}
	s := string(raw)
	if kind > 3 || len(s) > 1024 || !utf8.ValidString(s) || strings.ContainsAny(s, ",\r\n") || strings.IndexFunc(s, unicode.IsSpace) >= 0 || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return 0, "", false
	}
	if kind == 1 {
		if _, err := regexp.Compile(s); err != nil {
			return 0, "", false
		}
	}
	if kind >= 2 {
		if ip, err := netip.ParseAddr(s); err == nil && ip.Zone() == "" {
			// Keep IP literals from GeoSite as DNS patterns. A numeric hostname
			// doesn't implicitly add a network to the independently scoped GeoIP list.
			return kind, s, true
		}
		if len(s) > 253 || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") || strings.ContainsAny(s, "*+/#:@") {
			return 0, "", false
		}
		for _, label := range strings.Split(s, ".") {
			if len(label) > 63 {
				return 0, "", false
			}
			for _, r := range label {
				if !(r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
					return 0, "", false
				}
			}
		}
		if _, err := strconv.Atoi(s); err == nil {
			return 0, "", false
		}
	}
	return kind, s, true
}
