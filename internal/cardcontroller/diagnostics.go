package cardcontroller

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

type ConnectionExit struct {
	Kind    string `json:"kind,omitempty"`
	Name    string `json:"name,omitempty"`
	Country string `json:"country,omitempty"`
	Source  string `json:"source,omitempty"`
}

// Connection contains only the metadata needed by the local diagnostics view.
// The core can also return process paths, proxy credentials and process names.
type Connection struct {
	ServiceID   string          `json:"service_id,omitempty"`
	ID          string          `json:"id"`
	Device      string          `json:"device"`
	Host        string          `json:"host"`
	Port        string          `json:"port,omitempty"`
	Network     string          `json:"network,omitempty"`
	Rule        string          `json:"rule,omitempty"`
	Route       []string        `json:"route"`
	Exit        ConnectionExit  `json:"exit"`
	PoolCurrent *ConnectionExit `json:"pool_current,omitempty"`
	Start       time.Time       `json:"start"`
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
		} else if tag != "" && publicRouteName(tag, nil) == "" {
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
	return c.connectionRows(ctx, p, snapshot.Connections, xkeen.CardPoolMember), nil
}

// Mihomo records the terminal adapter for this flow. A panel-generated Xray
// pool is itself one adapter: its current observatory result is a separate
// sample and may have changed since this connection started.
func (c *Controller) connectionRows(ctx context.Context, p profile, flows []connectionTracker, readMember func(context.Context, xkeen.Runtime, string, int) string) []Connection {
	names := map[string]string{"DIRECT": "Напрямую", "REJECT": "Блокировка", "REJECT-DROP": "Блокировка", cardPrefix + defaultID: "Общий маршрут"}
	for id, display := range groupNames {
		names[cardPrefix+id] = display
		names[cardPrefix+id+"-inherited"] = display + " (по правилам)"
		names[dedicatedGroup(id)] = display + " (прокси устройства)"
	}
	metricsCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	workers := newWorkerSnapshot(metricsCtx, c.rt, p, c.catalog, readMember)
	leaves := map[string]bool{}
	for _, f := range flows {
		if len(f.Chains) > 0 {
			leaves[f.Chains[0]] = true
		}
	}

	unresolved := ConnectionExit{Kind: "unresolved"}
	exits := map[string]ConnectionExit{}
	poolNow := map[string]*ConnectionExit{}
	var providers map[string]selector
	for tag := range leaves {
		if !strings.HasPrefix(tag, nodePrefix) {
			if tag == "DIRECT" || tag == "REJECT" || tag == "REJECT-DROP" {
				exits[tag] = nativeConnectionExit(tag, tag)
				continue
			}
			if publicRouteName(tag, nil) == "" {
				continue
			}
			typ := str(workers.proxies[tag]["type"])
			if typ == "" && len(object(p.doc["proxy-providers"])) > 0 {
				if providers == nil {
					providers = p.api.providerNodes(ctx)
				}
				typ = providers[tag].Type
			}
			exits[tag] = nativeConnectionExit(tag, typ)
			continue
		}

		worker := workers.resolve(tag)
		if worker.pool {
			names[tag] = worker.label
			if worker.exit.Kind == "server" {
				poolNow[tag] = &worker.exit
			}
		} else if worker.exit.Kind == "server" {
			names[tag], exits[tag] = worker.exit.Name, worker.exit
		} else if worker.label != "" {
			names[tag] = worker.label + " (профиль Xray)"
		}
	}
	rows := make([]Connection, 0, len(flows))
	for _, f := range flows {
		row := f.project(names)
		row.Exit = unresolved
		if len(f.Chains) > 0 {
			tag := f.Chains[0]
			if exit, ok := exits[tag]; ok {
				row.Exit = exit
			}
			row.PoolCurrent = poolNow[tag]
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Start.After(rows[j].Start) })
	return rows
}

func nativeConnectionExit(tag, typ string) ConnectionExit {
	switch strings.ToLower(typ) {
	case "direct":
		return ConnectionExit{Kind: "direct"}
	case "reject", "rejectdrop", "reject-drop":
		return ConnectionExit{Kind: "reject"}
	case "http", "socks5", "ss", "shadowsocks", "ssr", "shadowsocksr", "snell", "vmess", "vless", "trojan", "hysteria", "hysteria2",
		"wireguard", "tuic", "ssh", "anytls", "mieru", "sudoku", "trusttunnel", "masque", "openvpn":
		return ConnectionExit{Kind: "server", Name: tag}
	}
	return ConnectionExit{Kind: "unresolved"}
}

// Worker tags identify the complete outbound. Catalog entries sharing that
// identity may have different user-defined labels or subscription names.
func diagnosticCatalog(servers []models.Server) map[string]ConnectionExit {
	index := map[string]ConnectionExit{}
	for _, s := range servers {
		id := xkeen.ServiceTargetID(s)
		if id == "" {
			continue
		}
		exit := ConnectionExit{Kind: "server", Name: publicRouteName(s.Name, nil), Country: xkeen.ServerCountry(s), Source: publicRouteName(s.SourceName, nil)}
		if len(s.RawProfile) > 0 {
			exit.Kind = "unresolved"
		}
		if prior, exists := index[id]; exists {
			if prior.Source != exit.Source {
				exit.Source = ""
			}
			if prior.Country != exit.Country {
				exit.Country = ""
			}
			if prior.Name != exit.Name {
				exit.Name = "Сервер с несколькими названиями"
			}
		}
		if exit.Name == "" {
			exit.Name = "Выход панели"
		}
		index[id] = exit
	}
	return index
}
