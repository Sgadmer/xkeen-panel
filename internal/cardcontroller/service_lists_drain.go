package cardcontroller

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"xkeen-panel/internal/xkeen"
)

// A reload cannot retroactively reclassify an already open QUIC session. Keep
// the transition token in the atomic config, and acknowledge only after older
// affected connections are closed. Maintenance retries interrupted transitions.
func (c *Controller) finishServiceListsDrain(ctx context.Context, p profile, state serviceListsCache) error {
	if state.DrainToken == "" {
		return nil
	}
	ack := filepath.Join(c.stateDir, "service-lists-connections.applied")
	previous, err := os.ReadFile(ack)
	if err != nil && !os.IsNotExist(err) {
		return errors.New("не удалось прочитать состояние переподключения сервисов")
	}
	if string(previous) == state.DrainToken {
		return nil
	}
	if err := os.MkdirAll(c.stateDir, 0700); err != nil {
		return err
	}
	persist := func(path, data string) error {
		tmp, err := stage(c.stateDir, []byte(data))
		if err != nil {
			return err
		}
		defer os.Remove(tmp)
		return os.Rename(tmp, path)
	}
	pending := ack + ".pending"
	body, err := os.ReadFile(pending)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	token, at, _ := strings.Cut(string(body), "\n")
	cutoff, parsed := time.Parse(time.RFC3339Nano, at)
	if token != state.DrainToken || parsed != nil {
		if !p.api.ruleMode(ctx) || !p.api.rulesReady(ctx, p.doc) {
			return errors.New("ожидаем подтверждения новых правил сервисов работающим ядром")
		}
		cutoff = time.Now().UTC()
		if err := persist(pending, state.DrainToken+"\n"+cutoff.Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	var snapshot struct{ Connections []connectionTracker }
	if err := p.api.request(ctx, "GET", "/connections", nil, &snapshot); err != nil {
		return errors.New("правила сервисов применены; проверка прежних соединений будет повторена")
	}
	known := map[string]bool{}
	if len(snapshot.Connections) > 0 {
		for id, file := range state.Files {
			path := filepath.Join(filepath.Dir(c.path), refilterPath(serviceProviderName(id), file.Hash))
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Size() > serviceListMaxBytes {
				return errors.New("ожидаем рабочую копию списков сервисов")
			}
			raw, err := os.ReadFile(path)
			if err != nil || serviceListDigest(raw) != file.Hash {
				return errors.New("сохранённая копия списка сервиса не прошла проверку")
			}
			for line := range strings.Lines(string(raw)) {
				known[strings.TrimSpace(line)] = true
			}
		}
		for _, host := range openAISharedDomains {
			known[host] = true
		}
	}
	for _, flow := range snapshot.Connections {
		if !flow.Start.IsZero() && flow.Start.After(cutoff) || !serviceListsFlowAffected(flow, state.Enabled, known) {
			continue
		}
		if flow.ID == "" {
			return errors.New("прежнее соединение сервиса ещё не подтверждено закрытым")
		}
		if err := p.api.request(ctx, "DELETE", "/connections/"+url.PathEscape(flow.ID), nil, nil); err != nil && !errors.Is(err, apiResponseError(404)) {
			return errors.New("правила сервисов применены; переподключение прежних запросов будет повторено")
		}
	}
	if err := persist(ack, state.DrainToken); err != nil {
		return err
	}
	_ = os.Remove(pending)
	return nil
}

func serviceListsFlowAffected(flow connectionTracker, enabled bool, known map[string]bool) bool {
	// Dataset changes cannot change the route of a correctly tagged private
	// application proxy. Keep an active call on that explicit whole-app path.
	for id := range groupNames {
		if flow.Metadata.InboundName == serviceInbound(id) && slices.Contains(flow.Chains, dedicatedGroup(id)) {
			return false
		}
	}
	if ip, err := netip.ParseAddr(flow.Metadata.DestinationIP); err == nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast()) {
		return false
	}
	if enabled && strings.EqualFold(flow.Metadata.Network, "udp") && (flow.Metadata.DestinationPort == "443" || flow.Metadata.DestinationPort == "8443") {
		return true
	}
	for _, name := range []string{flow.Metadata.SniffHost, flow.Metadata.Host} {
		host := strings.ToLower(strings.TrimSuffix(name, "."))
		if known[host] || xkeen.ServiceForHost(host) != "" {
			return true
		}
		for suffix := host; suffix != ""; {
			if known["+."+suffix] {
				return true
			}
			_, suffix, _ = strings.Cut(suffix, ".")
		}
	}
	return false
}
