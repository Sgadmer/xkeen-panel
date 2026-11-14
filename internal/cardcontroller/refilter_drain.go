package cardcontroller

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type refilterFlow struct {
	ID                string
	Chains            []string
	Rule, RulePayload string
	Start             time.Time
	Metadata          struct{ Host, SniffHost, DestinationIP string }
}

func stableRefilterFlow(flow refilterFlow, p profile) bool {
	for _, name := range flow.Chains {
		for id, target := range p.assigned {
			if id != defaultID && target != "" && (name == cardPrefix+id || name == dedicatedGroup(id)) {
				return true
			}
		}
	}
	host := flow.Metadata.SniffHost
	if host == "" {
		host = flow.Metadata.Host
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ip, _ := netip.ParseAddr(flow.Metadata.DestinationIP)
	// Only skip an explicit direct route when it was already direct. Keep
	// named exceptions such as Habr even when the new list includes them.
	direct := false
	for _, name := range flow.Chains {
		if name == "DIRECT" {
			direct = true
			break
		}
	}
	if direct {
		for _, raw := range list(p.doc["rules"]) {
			fields, end := targetPart(str(raw))
			if end < 2 || fields[end] != "DIRECT" {
				continue
			}
			if strings.EqualFold(fields[0], "DOMAIN") && strings.EqualFold(host, fields[1]) {
				return true
			}
			if strings.EqualFold(fields[0], "DOMAIN-SUFFIX") && (strings.EqualFold(host, fields[1]) || strings.HasSuffix(host, "."+strings.ToLower(fields[1]))) {
				return true
			}
			if fields[0] == "IP-CIDR" || fields[0] == "IP-CIDR6" {
				cidr, err := netip.ParsePrefix(fields[1])
				if err == nil && cidr.Contains(ip) {
					return true
				}
			}
		}
	}
	// On regular refresh, an unchanged classification keeps its connection.
	// First activation / profile restores can change arbitrary owner rules.
	return false
}

// The desired token is stored in the same atomic profile as the new rules.
// An acknowledgement exists only after pre-transition connections have been
// drained. A failed callback or router/panel restart retries automatically.
func (c *Controller) finishRefilterDrain(ctx context.Context, p profile, state refilterCache) error {
	if state.DrainToken == "" {
		return nil
	}
	ack := filepath.Join(c.stateDir, "refilter-connections.applied")
	previous, err := os.ReadFile(ack)
	if err != nil && !os.IsNotExist(err) {
		return errors.New("не удалось прочитать состояние переподключения Re:filter")
	}
	if string(previous) == state.DrainToken {
		return nil
	}
	_, err = time.Parse(time.RFC3339Nano, state.DrainToken)
	if err != nil {
		return errors.New("повреждено состояние переподключения Re:filter")
	}
	// A failure may have happened between on-disk publication and live
	// verification. Establish a cutoff only after verifying the new rules.
	pending := ack + ".pending"
	persist := func(path, data string) error {
		tmp, err := stage(c.stateDir, []byte(data))
		if err != nil {
			return err
		}
		defer os.Remove(tmp)
		return os.Rename(tmp, path)
	}
	body, err := os.ReadFile(pending)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	token, at, _ := strings.Cut(string(body), "\n")
	cutoff, parsed := time.Parse(time.RFC3339Nano, at)
	if token != state.DrainToken || parsed != nil {
		if !p.api.ruleMode(ctx) || !p.api.rulesReady(ctx, p.doc) {
			return errors.New("ожидаем подтверждения новых правил Re:filter работающим ядром")
		}
		cutoff = time.Now().UTC()
		if err := persist(pending, state.DrainToken+"\n"+cutoff.Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	var snapshot struct{ Connections []refilterFlow }
	if err = p.api.request(ctx, "GET", "/connections", nil, &snapshot); err != nil {
		return errors.New("правила Re:filter применены, проверка прежних соединений будет повторена")
	}
	var byName map[string]bool
	if state.Enabled && state.DomainBehavior == "domain" && len(snapshot.Connections) > 0 {
		raw, err := os.ReadFile(filepath.Join(filepath.Dir(c.path), refilterPath(refilterSites, state.SiteHash)))
		if err != nil {
			return errors.New("ожидаем рабочую копию доменных правил Re:filter")
		}
		byName = make(map[string]bool, state.Domains)
		for line := range strings.Lines(string(raw)) {
			byName[strings.ToLower(strings.TrimSpace(line))] = true
		}
	}
	for _, flow := range snapshot.Connections {
		if !flow.Start.IsZero() && flow.Start.After(cutoff) {
			continue
		}
		if stableRefilterFlow(flow, p) {
			continue
		}
		host := flow.Metadata.SniffHost
		if host == "" {
			host = flow.Metadata.Host
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if byName != nil && host != "" {
			blocked := byName[host]
			for suffix := host; suffix != ""; {
				if byName["+."+suffix] {
					blocked = true
					break
				}
				_, rest, ok := strings.Cut(suffix, ".")
				if !ok {
					break
				}
				suffix = rest
			}
			direct, viaDefault := false, false
			for _, name := range flow.Chains {
				if name == "DIRECT" {
					direct = true
				}
				if name == cardPrefix+defaultID {
					viaDefault = true
				}
			}
			// Explicit cards and exceptions were handled above. Only cached
			// decisions made by the old list are known to have the same role.
			if !blocked && direct || blocked && viaDefault && !direct {
				continue
			}
		}
		if flow.ID == "" || strings.ContainsAny(flow.ID, "/?#") {
			return errors.New("нет идентификатора соединения Re:filter")
		}
		err = p.api.request(ctx, "DELETE", "/connections/"+url.PathEscape(flow.ID), nil, nil)
		if err != nil && !errors.Is(err, apiResponseError(404)) {
			return errors.New("правила Re:filter применены, переподключение прежних потоков будет повторено")
		}
	}
	if err := persist(ack, state.DrainToken); err != nil {
		return err
	}
	_ = os.Remove(pending)
	return nil
}
