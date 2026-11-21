package cardcontroller

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"xkeen-panel/internal/xkeen"
)

// An exclusion sends its address past the VPN. It must not quietly take an
// address away from a service card whose kill switch is on:
//
//   - a domain, a host or a network that overlaps such a card is refused;
//   - a pattern is refused when it reaches into the addresses of any card.
//     Patterns are also placed below the card rules, so one that slips through
//     this check still can not pull a card's address out of its route.
//
// A card whose route is "direct", or whose kill switch is off, is not guarded.

type cardAddresses struct {
	id, name  string
	protected bool
	// host -> true when the names below it belong to the card too
	hosts    map[string]bool
	networks []netip.Prefix
}

type exclusionGuard struct{ cards []cardAddresses }

func (c *Controller) newExclusionGuard(p profile) exclusionGuard {
	policy, err := readKillSwitch(p.doc)
	if err != nil {
		return exclusionGuard{}
	}
	lists, _ := readServiceLists(p.doc)
	dir := filepath.Dir(c.path)
	var guard exclusionGuard
	for _, service := range xkeen.ServiceNames() {
		id := service.ID
		card := cardAddresses{id: id, name: service.Name, hosts: map[string]bool{},
			protected: policy.Protects(id) && p.assigned[id] != directTarget}
		for _, suffix := range xkeen.ServiceSuffixes(id) {
			card.hosts[suffix] = true
		}
		if id == "analytics" {
			for _, host := range xkeen.AnalyticsHosts() {
				card.hosts[host] = card.hosts[host]
			}
		}
		for _, raw := range xkeen.ServiceNetworks(id) {
			if prefix, err := netip.ParsePrefix(raw); err == nil {
				card.networks = append(card.networks, prefix.Masked())
			}
		}
		if lists.Enabled {
			if file, ok := lists.Files[id]; ok {
				readServiceHosts(filepath.Join(dir, refilterPath(serviceProviderName(id), file.Hash)), card.hosts)
			}
			if id == "openai" {
				for _, host := range openAISharedDomains {
					card.hosts[host] = card.hosts[host]
				}
				if file, ok := lists.Files[openAIVoiceListID]; ok {
					card.networks = append(card.networks, readServiceNetworks(filepath.Join(dir, refilterPath(serviceProviderName(openAIVoiceListID), file.Hash)))...)
				}
			}
		}
		guard.cards = append(guard.cards, card)
	}
	return guard
}

// Lines are "+.example.com" for a domain with everything below it, or a bare
// host name. A missing or unreadable file only narrows the check to the
// built-in addresses; the refusal itself never depends on it.
func readServiceHosts(path string, into map[string]bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > serviceListMaxBytes {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if host, ok := strings.CutPrefix(line, "+."); ok {
			into[host] = true
		} else if line != "" && !strings.HasPrefix(line, "#") {
			into[line] = into[line]
		}
	}
}

func readServiceNetworks(path string) []netip.Prefix {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > serviceListMaxBytes {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var result []netip.Prefix
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if prefix, err := netip.ParsePrefix(strings.TrimSpace(scanner.Text())); err == nil {
			result = append(result, prefix.Masked())
		}
	}
	return result
}

// touches reports whether the exclusion and the card share an address.
func (card cardAddresses) touches(e xkeen.Exclusion) bool {
	switch e.Type {
	case "ip":
		prefix, err := netip.ParsePrefix(e.Value)
		if err != nil {
			addr, err := netip.ParseAddr(e.Value)
			if err != nil {
				return false
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		for _, network := range card.networks {
			if network.Overlaps(prefix) {
				return true
			}
		}
	case "domain":
		host := strings.TrimPrefix(e.Value, "domain:")
		// The exclusion covers the card's host, or lies inside one of its domains.
		for known := range card.hosts {
			if known == host || strings.HasSuffix(known, "."+host) {
				return true
			}
		}
		return card.owns(host)
	case "full":
		return card.owns(strings.TrimPrefix(e.Value, "full:"))
	case "pattern":
		pattern, _ := xkeen.ExclusionPattern(e)
		match := xkeen.PatternMatcher(pattern)
		for known, below := range card.hosts {
			if match(known) || below && (match("www."+known) || match("a.b."+known)) {
				return true
			}
			// "api.example.*" names no host of the card literally. Fill the
			// stars with pieces of the card's own name and see whether the
			// result is one of its addresses.
			for _, piece := range namePieces(known) {
				if candidate := strings.ReplaceAll(pattern, "*", piece); card.owns(candidate) {
					return true
				}
			}
		}
	}
	return false
}

// namePieces gives the first and the last label of a name: "api.example.com"
// gives "api" and "com". Longer pieces would themselves be whole domains, and
// "www.mysite.*" filled with one would look like a host of that domain.
func namePieces(host string) []string {
	first, _, found := strings.Cut(host, ".")
	if !found {
		return nil
	}
	return []string{first, host[strings.LastIndexByte(host, '.')+1:]}
}

// owns reports whether a host name is one of the card's addresses.
func (card cardAddresses) owns(host string) bool {
	if _, exact := card.hosts[host]; exact {
		return true
	}
	for _, parent, found := strings.Cut(host, "."); found; _, parent, found = strings.Cut(parent, ".") {
		if card.hosts[parent] {
			return true
		}
	}
	return false
}

// conflict names the first card the exclusion overlaps, in catalogue order
// (specific services before the categories that contain them). The error is
// set when the exclusion must not be added.
func (g exclusionGuard) conflict(e xkeen.Exclusion) (id, name string, refusal error) {
	for _, card := range g.cards {
		if e.Type != "pattern" && !card.protected || !card.touches(e) {
			continue
		}
		if e.Type == "pattern" {
			return card.id, card.name, fmt.Errorf("шаблон задевает адреса карточки «%s». Маршрут этих адресов выбирается в самой карточке; уточните шаблон", card.name)
		}
		return card.id, card.name, fmt.Errorf("адрес относится к карточке «%s», у которой включён kill switch. Исключение увело бы его мимо VPN. Выберите маршрут в карточке или сначала выключите её kill switch", card.name)
	}
	return "", "", nil
}
