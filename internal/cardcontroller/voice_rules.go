package cardcontroller

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"xkeen-panel/internal/geoip"
)

// OpenAI publishes a separate maintained list for direct-IP voice transports.
// Keep it in the same immutable daily snapshot as the domain classifiers.
func normalizeOpenAIVoiceList(data []byte) (geoip.RuleFile, error) {
	var source struct {
		CreationTime string              `json:"creationTime"`
		Prefixes     []map[string]string `json:"prefixes"`
	}
	if len(data) == 0 || len(data) > serviceListMaxBytes || json.Unmarshal(data, &source) != nil {
		return geoip.RuleFile{}, errors.New("повреждён список голосовых адресов")
	}
	if _, err := time.Parse(time.RFC3339Nano, source.CreationTime); err != nil || len(source.Prefixes) == 0 || len(source.Prefixes) > 10000 {
		return geoip.RuleFile{}, errors.New("пустой список или неверная дата")
	}
	seen := map[string]bool{}
	for _, entry := range source.Prefixes {
		if len(entry) != 1 {
			return geoip.RuleFile{}, errors.New("неоднозначный адрес голосового сервера")
		}
		for key, value := range entry {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return geoip.RuleFile{}, errors.New("неверная сеть голосового сервера")
			}
			addr := prefix.Addr()
			if key != "ipv4Prefix" && key != "ipv6Prefix" || (key == "ipv4Prefix") != addr.Is4() || addr.Is4In6() ||
				!addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || prefix.Bits() < 8 || addr.Is6() && prefix.Bits() < 16 {
				return geoip.RuleFile{}, errors.New("неподдерживаемая сеть голосового сервера")
			}
			seen[prefix.Masked().String()] = true
		}
	}
	lines := make([]string, 0, len(seen))
	for line := range seen {
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return geoip.RuleFile{Data: []byte(strings.Join(lines, "\n") + "\n"), Count: len(lines), Behavior: "ipcidr"}, nil
}

// Only used when reconciling connections, never on the packet forwarding path.
func (c *Controller) openAIVoicePrefixes(p profile) ([]netip.Prefix, error) {
	info, err := readServiceLists(p.doc)
	if err != nil {
		return nil, err
	}
	file, found := info.Files[openAIVoiceListID]
	if !info.Enabled || !found {
		return nil, nil
	}
	path := filepath.Join(filepath.Dir(c.path), refilterPath(serviceProviderName(openAIVoiceListID), file.Hash))
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > serviceListMaxBytes {
		return nil, errors.New("ожидаем рабочий список голосовых адресов ChatGPT")
	}
	raw, err := os.ReadFile(path)
	if err != nil || serviceListDigest(raw) != file.Hash {
		return nil, errors.New("список голосовых адресов ChatGPT не прошёл проверку")
	}
	var prefixes []netip.Prefix
	for line := range strings.Lines(string(raw)) {
		if line = strings.TrimSpace(line); line != "" {
			prefix, err := netip.ParsePrefix(line)
			if err != nil {
				return nil, errors.New("повреждена сохранённая сеть голосового сервера")
			}
			prefixes = append(prefixes, prefix)
		}
	}
	if len(prefixes) != file.Count {
		return nil, errors.New("не совпадает число голосовых сетей ChatGPT")
	}
	return prefixes, nil
}
