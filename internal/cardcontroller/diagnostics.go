package cardcontroller

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"time"

	"xkeen-panel/internal/xkeen"
)

// Connection contains only the metadata needed by the local diagnostics view.
// The core can also return process paths, proxy credentials and process names.
type Connection struct {
	ServiceID string    `json:"service_id,omitempty"`
	ID        string    `json:"id"`
	Device    string    `json:"device"`
	Host      string    `json:"host"`
	Port      string    `json:"port,omitempty"`
	Network   string    `json:"network,omitempty"`
	Rule      string    `json:"rule,omitempty"`
	Route     []string  `json:"route"`
	Start     time.Time `json:"start"`
}

type connectionTracker struct {
	ID                string
	Start             time.Time
	Chains            []string
	Rule, RulePayload string
	Metadata          struct {
		SourceIP, DestinationIP, Host, SniffHost, DestinationPort, Network string
	}
}

func hostOnly(value string) string {
	value = strings.TrimSuffix(strings.TrimSpace(value), ".")
	if len(value) > 253 || strings.ContainsAny(value, "/?#@\\ \t\n\r") {
		return ""
	}
	return value
}

func (f connectionTracker) project(names map[string]string) Connection {
	device := ""
	if ip, err := netip.ParseAddr(f.Metadata.SourceIP); err == nil {
		device = ip.Unmap().String()
	}
	host := hostOnly(f.Metadata.Host)
	if host == "" {
		host = hostOnly(f.Metadata.SniffHost)
	}
	if host == "" {
		host = hostOnly(f.Metadata.DestinationIP)
	}
	row := Connection{ID: f.ID, Device: device, Host: host, Port: f.Metadata.DestinationPort, Network: strings.ToUpper(f.Metadata.Network), Rule: f.Rule, Start: f.Start, Route: []string{}}
	payload := hostOnly(f.RulePayload)
	if cidr, err := netip.ParsePrefix(f.RulePayload); err == nil {
		payload = cidr.String()
	}
	if payload != "" {
		row.Rule = strings.TrimSpace(row.Rule + " " + payload)
	}
	// Mihomo records the final outbound first. Show the order seen by the packet.
	for i := len(f.Chains) - 1; i >= 0; i-- {
		tag := f.Chains[i]
		if row.ServiceID == "" {
			row.ServiceID = diagnosticServiceTags[tag]
		}
		if pretty := names[tag]; pretty != "" {
			tag = pretty
		} else if strings.HasPrefix(tag, nodePrefix) {
			tag = "Выход панели"
		}
		if tag != "" {
			row.Route = append(row.Route, tag)
		}
	}
	if service := xkeen.ServiceForHost(host); service != "" &&
		(row.ServiceID == "" || row.ServiceID == "ai" || row.ServiceID == "google" && service == "youtube") {
		row.ServiceID = service
	}
	return row
}

var diagnosticServiceTags = func() map[string]string {
	tags := map[string]string{}
	for id, name := range groupNames {
		for _, tag := range []string{name, cardPrefix + id, cardPrefix + id + "-inherited", dedicatedGroup(id)} {
			tags[tag] = id
		}
	}
	return tags
}()

func (c *Controller) Connections(ctx context.Context) ([]Connection, error) {
	// Config changes use atomic renames. Read one coherent snapshot without
	// making a route change wait for this observational controller request.
	p, err := c.read()
	if err != nil {
		return nil, err
	}
	var snapshot struct{ Connections []connectionTracker }
	if err := p.api.request(ctx, "GET", "/connections", nil, &snapshot); err != nil {
		return nil, err
	}
	names := map[string]string{"DIRECT": "Напрямую", "REJECT": "Блокировка", "REJECT-DROP": "Блокировка", cardPrefix + defaultID: "Общий маршрут"}
	for id, display := range groupNames {
		names[cardPrefix+id] = display
		names[cardPrefix+id+"-inherited"] = display + " (по правилам)"
		names[dedicatedGroup(id)] = display + " (прокси устройства)"
	}
	rows := make([]Connection, 0, len(snapshot.Connections))
	needNames := map[string]bool{}
	for _, f := range snapshot.Connections {
		for _, tag := range f.Chains {
			if _, ok := names[tag]; ok {
				continue
			}
			if rest, ok := strings.CutPrefix(tag, nodePrefix); ok {
				id, _, _ := strings.Cut(rest, "-")
				if pool := p.pool(id); pool != nil {
					names[tag] = pool.Name + " (мультипул Xray)"
				} else {
					needNames[tag] = true
				}
			}
		}
	}
	if len(needNames) > 0 {
		for _, s := range c.catalog() {
			tag := nodePrefix + xkeen.ServiceTargetID(s)
			if !needNames[tag] {
				continue
			}
			names[tag] = s.Name
			if len(s.RawProfile) > 0 {
				names[tag] += " (профиль Xray)"
			}
			delete(needNames, tag)
			if len(needNames) == 0 {
				break
			}
		}
	}
	for _, f := range snapshot.Connections {
		rows = append(rows, f.project(names))
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Start.After(rows[j].Start) })
	return rows, nil
}
