package xkeen

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"xkeen-panel/internal/models"
)

const exitTraceURL = "https://www.cloudflare.com/cdn-cgi/trace"
const ExitCountryTTL = 24 * time.Hour

// ISO 3166-1 alpha-2. Providers also return non-country placeholders such as XX.
const exitCountries = " AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ " +
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

func validExitCountry(code string) bool {
	return len(code) == 2 && strings.Contains(exitCountries, " "+code+" ")
}

// MeasuredExitCountry is the recent country observed by the trace endpoint.
// A composed profile can choose different exits depending on the destination.
func MeasuredExitCountry(s models.Server) string {
	if s.GeneratedPool || len(s.RawProfile) != 0 || s.Protocol == "xray-profile" || !validExitCountry(s.ExitCountry) {
		return ""
	}
	age := time.Since(s.ExitCheckedAt)
	if age < 0 || age >= ExitCountryTTL {
		return ""
	}
	return s.ExitCountry
}

// The caller supplies the verified HTTPS client bound to this node's private
// loopback proxy. Keep the observation's country only, never its IP or body.
func probeExitCountry(ctx context.Context, client *http.Client) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, exitTraceURL, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	const maxTrace = 4096
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTrace+1))
	if err != nil || len(body) > maxTrace {
		return ""
	}
	var hasIP bool
	var country string
	for line := range strings.Lines(string(body)) {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "loc":
			if country != "" || !validExitCountry(value) {
				return ""
			}
			country = value
		case "ip":
			addr, err := netip.ParseAddr(value)
			addr = addr.Unmap()
			if hasIP || err != nil || addr.Zone() != "" || !addr.IsGlobalUnicast() || addr.IsPrivate() {
				return ""
			}
			hasIP = true
		}
	}
	if !hasIP {
		return ""
	}
	return country
}
