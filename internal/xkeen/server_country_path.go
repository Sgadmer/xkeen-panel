package xkeen

import (
	"context"
	"time"

	"xkeen-panel/internal/geoip"
	"xkeen-panel/internal/models"
)

func entryCountries(ctx context.Context, servers []models.Server, datPath string) map[string]string {
	hosts := make([]string, 0, len(servers))
	for _, server := range servers {
		if !server.GeneratedPool && len(server.RawProfile) == 0 && server.Protocol != "xray-profile" {
			hosts = append(hosts, server.Address)
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return geoip.EndpointCountries(ctx, geoip.FindDat(datPath), hosts)
}

func MeasuredEntryCountry(server models.Server) string {
	if server.GeneratedPool || len(server.RawProfile) != 0 || server.Protocol == "xray-profile" || !validExitCountry(server.EntryCountry) {
		return ""
	}
	if age := time.Since(server.ExitCheckedAt); age < 0 || age >= ExitCountryTTL {
		return ""
	}
	return server.EntryCountry
}

// CountryPath includes only known endpoints. A single country means the entry
// and exit both matched it. A partial observation uses the separate fields.
func CountryPath(entry, exit string) []string {
	if entry == "" || exit == "" {
		return nil
	}
	if entry == exit {
		return []string{entry}
	}
	return []string{entry, exit}
}

func ServerCountryPath(server models.Server) []string {
	return CountryPath(MeasuredEntryCountry(server), MeasuredExitCountry(server))
}
