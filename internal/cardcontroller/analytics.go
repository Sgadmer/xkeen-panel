package cardcontroller

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"xkeen-panel/internal/xkeen"
)

// Used only while reconciling a changed route, never for individual packets.
// Existing connections to shared collectors must not keep the former pool's
// exit after the user pins the analytics card to a different server.
func (c *Controller) analyticsMatcher(p profile) (func(string) bool, error) {
	exact, suffixes := map[string]bool{}, map[string]bool{}
	for _, host := range xkeen.AnalyticsHosts() {
		exact[host] = true
	}
	info, err := readServiceLists(p.doc)
	if err != nil {
		return nil, err
	}
	if file, found := info.Files["analytics"]; info.Enabled && found {
		path := filepath.Join(filepath.Dir(c.path), refilterPath(serviceProviderName("analytics"), file.Hash))
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() || st.Size() > serviceListMaxBytes {
			return nil, errors.New("ожидаем рабочий список аналитики")
		}
		raw, err := os.ReadFile(path)
		if err != nil || serviceListDigest(raw) != file.Hash {
			return nil, errors.New("список аналитики не прошёл проверку")
		}
		for line := range strings.Lines(string(raw)) {
			line = strings.TrimSpace(line)
			if host, suffix := strings.CutPrefix(line, "+."); suffix {
				suffixes[host] = true
			} else if line != "" {
				exact[line] = true
			}
		}
	}
	return func(host string) bool {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if exact[host] {
			return true
		}
		for host != "" {
			if suffixes[host] {
				return true
			}
			_, host, _ = strings.Cut(host, ".")
		}
		return false
	}, nil
}
