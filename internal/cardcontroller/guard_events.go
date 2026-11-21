package cardcontroller

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"xkeen-panel/internal/xkeen"
)

const guardEventTTL = 30 * time.Minute

// GuardEvent describes an observed attempt, rather than a failed health probe.
// Raw core logs and their (potentially credential-bearing) errors are discarded.
type GuardEvent struct {
	ID        string    `json:"id"`
	At        time.Time `json:"at"`
	ServiceID string    `json:"service_id,omitempty"`
	Device    string    `json:"device,omitempty"`
	Host      string    `json:"host,omitempty"`
	Port      string    `json:"port,omitempty"`
	Network   string    `json:"network"`
	Reason    string    `json:"reason"`
	Count     int       `json:"count"`
}

type GuardObservation struct {
	Running  bool         `json:"running"`
	Complete bool         `json:"complete"`
	Events   []GuardEvent `json:"events"`
	Error    string       `json:"error,omitempty"`
}

type guardJournal struct {
	sync.Mutex
	running, complete bool
	err               string
	events            []GuardEvent
	session           string
	next              uint64

	// The log level of the profile as last read, with the file it was read from.
	levelSize     int64
	levelTime     time.Time
	levelComplete bool
}

func (g *guardJournal) trim(now time.Time) {
	g.events = slices.DeleteFunc(g.events, func(e GuardEvent) bool { return now.Sub(e.At) > guardEventTTL })
}

func (g *guardJournal) add(event GuardEvent) {
	g.Lock()
	defer g.Unlock()
	g.trim(event.At)
	for i := len(g.events) - 1; i >= 0; i-- {
		prior := &g.events[i]
		if event.At.Sub(prior.At) > 15*time.Second {
			break
		}
		if prior.ServiceID == event.ServiceID && prior.Device == event.Device && prior.Host == event.Host && prior.Port == event.Port && prior.Network == event.Network && prior.Reason == event.Reason {
			prior.Count++
			return
		}
	}
	if g.session == "" {
		var b [8]byte
		_, _ = rand.Read(b[:])
		g.session = hex.EncodeToString(b[:])
	}
	g.next++
	event.ID = fmt.Sprintf("%s-%d", g.session, g.next)
	event.Count = 1
	g.events = append(g.events, event)
	if len(g.events) > 128 {
		g.events = g.events[len(g.events)-128:]
	}
}

// logsComplete reports whether the core writes a line for every connection.
// Pages ask this every few seconds; the profile is parsed again only after the
// file on disk has changed.
func (c *Controller) logsComplete() bool {
	info, err := os.Stat(c.path)
	if err != nil {
		return false
	}
	c.guard.Lock()
	if c.guard.levelSize == info.Size() && c.guard.levelTime.Equal(info.ModTime()) {
		complete := c.guard.levelComplete
		c.guard.Unlock()
		return complete
	}
	c.guard.Unlock()
	p, err := c.read()
	complete := err == nil && (str(p.doc["log-level"]) == "info" || str(p.doc["log-level"]) == "debug")
	if err == nil {
		c.guard.Lock()
		c.guard.levelSize, c.guard.levelTime, c.guard.levelComplete = info.Size(), info.ModTime(), complete
		c.guard.Unlock()
	}
	return complete
}

func (c *Controller) GuardEvents() GuardObservation {
	complete := c.logsComplete()
	c.guard.Lock()
	defer c.guard.Unlock()
	c.guard.trim(time.Now())
	events := append([]GuardEvent{}, c.guard.events...)
	slices.Reverse(events)
	return GuardObservation{Running: c.guard.running, Complete: complete, Error: c.guard.err, Events: events}
}

func (c *Controller) LatestGuardEvent() (string, time.Time) {
	c.guard.Lock()
	defer c.guard.Unlock()
	if len(c.guard.events) == 0 {
		return "", time.Time{}
	}
	for i := len(c.guard.events) - 1; i >= 0; i-- {
		e := c.guard.events[i]
		if time.Since(e.At) > 2*time.Minute {
			break
		}
		if e.Reason != "protocol_guard" {
			return e.ID, e.At
		}
	}
	return "", time.Time{}
}

func (c *Controller) guardState(running, complete bool, err string) {
	c.guard.Lock()
	c.guard.running, c.guard.complete, c.guard.err = running, complete, err
	c.guard.Unlock()
}

// RunGuardObserver reads the authenticated loopback log stream. It never changes
// the core log level, routes or retry policy; configuration remains panel-owned.
func (c *Controller) RunGuardObserver(ctx context.Context) {
	defer c.guardState(false, false, "Наблюдение остановлено.")
	for ctx.Err() == nil {
		p, err := c.read()
		if err == nil {
			complete := str(p.doc["log-level"]) == "info" || str(p.doc["log-level"]) == "debug"
			c.guardState(true, complete, "")
			c.readGuardStream(ctx, p)
		}
		if ctx.Err() != nil {
			return
		}
		c.guardState(false, false, "Поток событий Mihomo переподключается.")
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (c *Controller) readGuardStream(ctx context.Context, p profile) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.api.base+"/logs?level=info", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.api.secret)
	client := *p.api.client
	client.Timeout = 0 // The stream has its own bounded context and closes on shutdown.
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 4096), 32<<10)
	lastCheck := time.Time{}
	fileInfo, _ := os.Stat(c.path)
	for scanner.Scan() && ctx.Err() == nil {
		var line struct {
			Type    string `json:"type"`
			Payload string `json:"payload"`
		}
		if json.Unmarshal(scanner.Bytes(), &line) != nil || len(line.Payload) > 8192 {
			continue
		}
		// Reparse YAML only after publication of a changed configuration,
		// rather than for every QUIC packet or archived connection.
		if time.Since(lastCheck) > 500*time.Millisecond {
			if info, err := os.Stat(c.path); err == nil && (fileInfo == nil || info.ModTime() != fileInfo.ModTime() || info.Size() != fileInfo.Size()) {
				if fresh, err := c.read(); err == nil {
					p, fileInfo = fresh, info
				}
			}
			lastCheck = time.Now()
		}
		if !strings.Contains(line.Payload, cardPrefix) || line.Type == "info" &&
			(!strings.Contains(line.Payload, "[REJECT]") || !guardRejectTag.MatchString(line.Payload) && !guardCardTag.MatchString(line.Payload)) ||
			(line.Type == "warning" || line.Type == "warn" || line.Type == "error") && !guardDialLog.MatchString(line.Payload) {
			c.recordTraffic(line.Type, line.Payload, p, nil)
			continue
		}
		// Re-read after a candidate event: a preference or route can change
		// while the long-lived core stream remains connected.
		if event, ok := parseGuardLog(line.Type, line.Payload, p); ok {
			event.At = time.Now()
			c.guard.add(event)
			c.recordTraffic(line.Type, line.Payload, p, &event)
		} else {
			c.recordTraffic(line.Type, line.Payload, p, nil)
		}
	}
}

var guardRejectTag = regexp.MustCompile(`(?:^|[\s,\[])XKP-card-guard-([a-z]+)(?:\[|[\s,\]]|$)`)
var guardCardTag = regexp.MustCompile(`(?:^|[\s,\[])XKP-card-([a-z]+)(?:\[|[\s,\]]|$)`)
var guardDialLog = regexp.MustCompile(`^\[(TCP|UDP)\] dial (XKP-card-[a-z-]+) \(match [^\r\n]*\) ([^ ]+) --> ([^ ]+) error: `)
var guardFlowLog = regexp.MustCompile(`^\[(TCP|UDP)\] ([^ ]+) --> ([^ ]+) (?:match .* )?using (.+)$`)

func guardService(p profile, tag, id string) bool {
	if _, owned := p.doc[stateKey]; !owned || id != defaultID && id != "quic" && groupNames[id] == "" || p.assigned[id] == directTarget {
		return false
	}
	policy, err := readKillSwitch(p.doc)
	if err != nil || id != "quic" && !policy.Protects(id) {
		return false
	}
	for _, item := range list(p.doc["proxy-groups"]) {
		group := object(item)
		if str(group["name"]) != tag || str(group["type"]) != "select" {
			continue
		}
		members := namesOf(group["proxies"])
		if len(members) != 1 || members[0] == "DIRECT" || strings.HasPrefix(members[0], failoverPrefix) {
			return false
		}
		if strings.HasPrefix(tag, cardPrefix+"guard-") {
			return members[0] == "REJECT"
		}
		// Intentional manual REJECT is not an outage event. A failed VPN
		// connection has an actual proxy destination, not a rejection adapter.
		return guardVPNRoute(p.doc, members[0], map[string]bool{})
	}
	return false
}

// A missing selected worker makes its owned card selector itself REJECT. This
// is a generated fail-closed state, distinct from a user's native REJECT group.
func guardMissingWorker(p profile, id string) bool {
	if _, owned := p.doc[stateKey]; !owned || id != defaultID && groupNames[id] == "" || p.assigned[id] == directTarget || p.assigned[id] == "" && id != "claude" {
		return false
	}
	policy, err := readKillSwitch(p.doc)
	if err != nil || !policy.Protects(id) {
		return false
	}
	for _, raw := range list(p.doc["proxy-groups"]) {
		group := object(raw)
		if str(group["name"]) != cardPrefix+id || str(group["type"]) != "select" {
			continue
		}
		members := namesOf(group["proxies"])
		return len(members) == 1 && members[0] == "REJECT"
	}
	return false
}

// A warning can also describe a deliberate user-selected rejection adapter.
// Report an outage only when every configured choice is an actual VPN adapter.
func guardVPNRoute(doc map[string]interface{}, name string, seen map[string]bool) bool {
	if seen[name] {
		return false
	}
	seen[name] = true
	defer delete(seen, name)
	for _, raw := range list(doc["proxies"]) {
		node := object(raw)
		if str(node["name"]) == name {
			return nativeConnectionExit(name, str(node["type"])).Kind == "server"
		}
	}
	for _, raw := range list(doc["proxy-groups"]) {
		group := object(raw)
		if str(group["name"]) != name {
			continue
		}
		members := namesOf(group["proxies"])
		if len(members) == 0 || len(namesOf(group["use"])) > 0 || group["include-all"] == true {
			return false
		}
		for _, member := range members {
			if !guardVPNRoute(doc, member, seen) {
				return false
			}
		}
		return true
	}
	return false
}

func guardAddress(raw string, source bool) (string, string, bool) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", "", false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	} else if source || hostOnly(host) == "" || strings.ContainsAny(host, "[]<>%\"'") {
		return "", "", false
	}
	return host, port, true
}

func parseGuardLog(level, payload string, p profile) (GuardEvent, bool) {
	var event GuardEvent
	var source, dest string
	if level == "warning" || level == "warn" || level == "error" {
		parts := guardDialLog.FindStringSubmatch(payload)
		if len(parts) == 0 {
			return event, false
		}
		tag := parts[2]
		id := diagnosticServiceTags[tag]
		if tag == cardPrefix+defaultID {
			id = defaultID
		}
		if id == "" || !guardService(p, tag, id) {
			return event, false
		}
		event.Network, event.ServiceID, event.Reason = parts[1], id, "vpn_unavailable"
		source, dest = parts[3], parts[4]
	} else if level == "info" {
		parts := guardFlowLog.FindStringSubmatch(payload)
		if len(parts) == 0 || !strings.Contains(parts[4], "[REJECT]") {
			return event, false
		}
		tag := guardRejectTag.FindStringSubmatch(parts[4])
		id := ""
		if len(tag) > 0 && guardService(p, cardPrefix+"guard-"+tag[1], tag[1]) {
			id = tag[1]
		} else if card := guardCardTag.FindStringSubmatch(parts[4]); len(card) > 0 && guardMissingWorker(p, card[1]) {
			id = card[1]
		}
		if id == "" {
			return event, false
		}
		event.Network, event.ServiceID, event.Reason = parts[1], id, "guard_reject"
		if id == "quic" {
			if event.Network != "UDP" {
				return GuardEvent{}, false
			}
			event.ServiceID, event.Reason = "", "protocol_guard"
		}
		source, dest = parts[2], parts[3]
	} else {
		return event, false
	}
	var ok bool
	event.Device, _, ok = guardAddress(source, true)
	if !ok {
		return GuardEvent{}, false
	}
	event.Host, event.Port, ok = guardAddress(dest, false)
	if !ok {
		return GuardEvent{}, false
	}
	if event.Reason == "protocol_guard" {
		event.ServiceID = xkeen.ServiceForHost(event.Host)
	}
	return event, true
}
