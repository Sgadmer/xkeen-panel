package xkeen

import (
	"strings"

	"xkeen-panel/internal/models"
)

// ISO 3166-1 alpha-2 codes, excluding placeholders such as XX and regional flags.
const providerCountries = " AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ " +
	"BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ " +
	"CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ " +
	"DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR " +
	"GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY " +
	"HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP " +
	"KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY " +
	"MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ " +
	"NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY " +
	"QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ " +
	"TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ " +
	"VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW "

func validProviderCountry(code string) bool {
	return len(code) == 2 && strings.Contains(providerCountries, " "+code+" ")
}

// Accept only a complete country label. A flag and an optional name must agree.
func routeLabelCountry(label string) string {
	label = strings.TrimSpace(label)
	flag := countryFromFlag(label)
	if flag != "" {
		if !validProviderCountry(flag) {
			return ""
		}
		emoji := string([]rune{0x1F1E6 + rune(flag[0]-'A'), 0x1F1E6 + rune(flag[1]-'A')})
		label = strings.TrimSpace(strings.Replace(label, emoji+"\uFE0F", emoji, 1))
		switch {
		case strings.HasPrefix(label, emoji):
			label = strings.TrimSpace(strings.TrimPrefix(label, emoji))
		case strings.HasSuffix(label, emoji):
			label = strings.TrimSpace(strings.TrimSuffix(label, emoji))
		default:
			return ""
		}
		if label == "" {
			return flag
		}
	}
	code := countryTokens[strings.ToLower(label)]
	if validProviderCountry(label) {
		code = label
	}
	if flag != "" && flag != code {
		return ""
	}
	return code
}

func routeParts(name string) []string {
	if !strings.ContainsAny(name, "→>") {
		return nil
	}
	name = strings.ReplaceAll(strings.ReplaceAll(name, "->", "→"), "=>", "→")
	parts := strings.Split(name, "→")
	if len(parts) < 2 {
		return nil
	}
	return parts
}

func providerArrowDestination(name string) (string, bool) {
	parts := routeParts(name)
	if len(parts) == 0 {
		return "", false
	}
	return routeLabelCountry(parts[len(parts)-1]), true
}

// A provider can explicitly name an ordered route "RU → SE → FR".
// Adjacent flags, product names and address geolocation do not establish hops.
func providerChainFromName(name string) []string {
	parts := routeParts(name)
	if len(parts) == 0 {
		return nil
	}
	chain := make([]string, 0, len(parts))
	for _, part := range parts {
		code := routeLabelCountry(part)
		if code == "" {
			return nil
		}
		chain = append(chain, code)
	}
	return chain
}

func ServerCountryPath(server models.Server) []string {
	if server.GeneratedPool || len(server.RawProfile) != 0 || server.Protocol == "xray-profile" {
		return nil
	}
	path := providerChainFromName(server.Name)
	if len(path) == 0 || (server.CountryOverride != "" && !strings.EqualFold(server.CountryOverride, path[len(path)-1])) {
		return nil
	}
	return path
}
