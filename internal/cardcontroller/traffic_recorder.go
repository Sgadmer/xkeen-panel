package cardcontroller

import (
	"context"
	"regexp"
	"strings"
	"time"

	"xkeen-panel/internal/trafficlog"
	"xkeen-panel/internal/xkeen"
)

type trafficRecorder struct {
	active func() bool
	record func(trafficlog.Entry)
	raw    []byte
	names  map[string]string
	exits  map[string]ConnectionExit
}

// SetTrafficRecorder is set once before starting the observer. Disabled
// installations do not parse ordinary traffic or allocate an archive queue.
func (c *Controller) SetTrafficRecorder(active func() bool, record func(trafficlog.Entry)) {
	c.traffic = &trafficRecorder{active: active, record: record}
}

func (c *Controller) recordTraffic(level, payload string, p profile, guard *GuardEvent) {
	r := c.traffic
	if r == nil || r.active == nil || !r.active() || r.record == nil {
		return
	}
	if r.names == nil || len(p.raw) == 0 || len(r.raw) == 0 || &p.raw[0] != &r.raw[0] {
		r.project(c, p)
	}
	if entry, ok := r.parse(level, payload, guard); ok {
		r.record(entry)
	}
}

func (r *trafficRecorder) project(c *Controller, p profile) {
	r.raw = p.raw
	r.names = map[string]string{"DIRECT": "Напрямую", "REJECT": "Блокировка", "REJECT-DROP": "Блокировка", cardPrefix + defaultID: "Общий маршрут", serviceGuardName("quic"): "Блокировка QUIC"}
	r.exits = map[string]ConnectionExit{"DIRECT": {Kind: "direct"}, "REJECT": {Kind: "reject"}, "REJECT-DROP": {Kind: "reject"}}
	for id, name := range groupNames {
		r.names[cardPrefix+id], r.names[cardPrefix+id+"-inherited"], r.names[dedicatedGroup(id)] = name, name, name
		r.names[serviceGuardName(id)] = "Kill switch"
	}
	for _, custom := range xkeen.CustomServices() {
		r.names[cardPrefix+custom.ID] = custom.Name
		r.names[serviceGuardName(custom.ID)] = "Kill switch"
	}
	r.names[serviceGuardName(defaultID)] = "Kill switch"
	catalog := map[string]ConnectionExit{}
	if c.catalog != nil {
		catalog = diagnosticCatalog(c.catalog())
	}
	for _, raw := range list(p.doc["proxies"]) {
		proxy := object(raw)
		tag := str(proxy["name"])
		exit := nativeConnectionExit(tag, str(proxy["type"]))
		if strings.HasPrefix(tag, nodePrefix) {
			key := strings.TrimPrefix(tag, nodePrefix)
			if len(key) >= 64 {
				key = key[:64]
				if value, ok := catalog[key]; ok {
					exit = value
				} else if pool := p.pool(key); pool != nil {
					exit = ConnectionExit{Kind: "unresolved", Name: publicRouteName(pool.Name, nil)}
				}
			}
		}
		r.exits[tag] = exit
		if exit.Name != "" {
			r.names[tag] = exit.Name
		} else if name := publicRouteName(tag, nil); name != "" {
			r.names[tag] = name
		}
	}
}

var historyDialLog = regexp.MustCompile(`^\[(TCP|UDP)\] dial (.+?) \(match ([^\r\n]*)\) ([^ ]+) --> ([^ ]+) error: `)

func (r *trafficRecorder) parse(level, payload string, guard *GuardEvent) (trafficlog.Entry, bool) {
	entry := trafficlog.Entry{At: time.Now().UTC(), Kind: "connection", Count: 1, Route: []string{}}
	var source, destination, used string
	if guard != nil {
		entry.Device, entry.Host, entry.Port, entry.Network, entry.ServiceID = guard.Device, guard.Host, guard.Port, guard.Network, guard.ServiceID
		entry.At = guard.At
		entry.Kind = "kill_switch"
		if guard.Reason == "protocol_guard" {
			entry.Kind = "quic"
		}
		entry.Exit = &trafficlog.Exit{Kind: "reject"}
	} else if level == "info" {
		parts := guardFlowLog.FindStringSubmatch(payload)
		if len(parts) == 0 {
			return entry, false
		}
		entry.Network, source, destination, used = parts[1], parts[2], parts[3], parts[4]
	} else if level == "warning" || level == "warn" || level == "error" {
		parts := historyDialLog.FindStringSubmatch(payload)
		if len(parts) == 0 {
			return entry, false
		}
		entry.Kind, entry.Network, used, entry.Rule, source, destination = "error", parts[1], parts[2], parts[3], parts[4], parts[5]
	} else {
		return entry, false
	}
	if guard == nil {
		var ok bool
		entry.Device, _, ok = guardAddress(source, true)
		if !ok {
			return entry, false
		}
		entry.Host, entry.Port, ok = guardAddress(destination, false)
		if !ok {
			return entry, false
		}
	} else if parts := guardFlowLog.FindStringSubmatch(payload); len(parts) > 0 {
		used = parts[4]
	} else if parts := historyDialLog.FindStringSubmatch(payload); len(parts) > 0 {
		used = parts[2]
		entry.Rule = parts[3]
	}
	if entry.Rule == "" {
		if start := strings.Index(payload, " match "); start >= 0 {
			if end := strings.Index(payload[start+7:], " using "); end >= 0 {
				entry.Rule = payload[start+7 : start+7+end]
			}
		}
	}
	group, leaf := used, used
	if start := strings.Index(used, "["); start >= 0 && strings.HasSuffix(used, "]") {
		group, leaf = used[:start], used[start+1:len(used)-1]
	}
	if entry.ServiceID == "" {
		entry.ServiceID = serviceOfTag(group)
	}
	if entry.ServiceID == "" {
		entry.ServiceID = xkeen.ServiceForHost(entry.Host)
	}
	for _, tag := range []string{group, leaf} {
		name := r.names[tag]
		if name == "" {
			name = publicRouteName(tag, nil)
		}
		if name != "" && (len(entry.Route) == 0 || entry.Route[len(entry.Route)-1] != name) {
			entry.Route = append(entry.Route, name)
		}
	}
	if entry.Exit == nil {
		if exit, ok := r.exits[leaf]; ok {
			entry.Exit = &trafficlog.Exit{Kind: exit.Kind, Name: exit.Name, Country: exit.Country, Source: exit.Source}
		} else {
			entry.Exit = &trafficlog.Exit{Kind: "unresolved"}
		}
	}
	return entry, true
}

// EnsureTrafficLogging changes log verbosity only. It does not enable a
// routing mode or reset any selected server when disk history is requested.
func (c *Controller) EnsureTrafficLogging(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return err
	}
	level := str(p.doc["log-level"])
	if level == "info" || level == "debug" {
		return nil
	}
	_, err = c.apply(ctx, "", "", func(p *profile) error { p.doc["log-level"] = "info"; return nil })
	return err
}
