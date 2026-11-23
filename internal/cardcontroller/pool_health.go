package cardcontroller

import (
	"bytes"
	"context"
	"errors"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

// silentFor is how long a server the router could not reach stays out of
// «Все локации». The panel's own check may still find it working: the router's
// verdict wins, because the router is the one that carries the traffic.
const silentFor = 30 * time.Minute

// pinRefresh re-applies a pool's choice now and then: a worker that restarted
// by itself has forgotten it.
const pinRefresh = 5 * time.Minute

type silentMembers struct {
	mu    sync.Mutex
	until map[string]time.Time
}

func (s *silentMembers) has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Now().Before(s.until[id])
}

// mark records the servers and reports which of them are new.
func (s *silentMembers) mark(ids []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.until == nil {
		s.until = map[string]time.Time{}
	}
	for id, until := range s.until {
		if !now.Before(until) {
			delete(s.until, id)
		}
	}
	var fresh []string
	for _, id := range ids {
		if _, known := s.until[id]; !known {
			fresh = append(fresh, id)
		}
		s.until[id] = now.Add(silentFor)
	}
	return fresh
}

func (s *silentMembers) forget(ids []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		delete(s.until, id)
	}
}

// poolWorker is a running pool worker as Mihomo reaches it.
type poolWorker struct {
	pool, id string
	port     int
}

func (w poolWorker) key() string { return w.id + "/" + strconv.Itoa(w.port) }

type poolPin struct {
	member string
	at     time.Time
}

// SetPingRecorder sets where the router's measurements are stored. full marks
// a full check, which also renews the page-loading verdict.
func (c *Controller) SetPingRecorder(record func(samples []models.Server, full bool)) {
	c.recordPings = record
}

// MaintainPools runs every few seconds from one goroutine. What the pool
// workers measured goes into the servers' ping history (see xkeen/ping.go), a
// member of «Все локации» that did not answer twice in a row is replaced, and
// every pool carries traffic through the member with the best number. It
// returns how many members were replaced.
//
// The swap is soft, like a subscription reissue: new connections go to the
// new worker at once, while connections already open keep running through the
// previous one until they end. Closing them used to break every download and
// call through the pool on each replacement.
func (c *Controller) MaintainPools(ctx context.Context) (int, error) {
	workers, err := c.runningPoolWorkers()
	if err != nil || len(workers) == 0 {
		return 0, err
	}
	members := map[poolWorker][]string{}
	tried := map[string]time.Time{}
	observe, pin := c.observePool, c.pinMember
	if observe == nil {
		observe = xkeen.CardPoolObservations
	}
	if pin == nil {
		pin = xkeen.PinPoolMember
	}
	// Identities are computed once per round: on a router they cost.
	targets := c.targetServers()
	for _, w := range workers {
		_, observed := observe(ctx, c.rt, w.id, w.port)
		members[w] = c.storePoolPings(w, observed, tried, targets.lookup(c.catalog()))
	}
	c.poolTried = tried
	// The numbers as just stored.
	lookup := targets.lookup(c.catalog())
	replaced, err := c.replaceSilentMembers(ctx, workers, members, lookup)
	if replaced == 0 && err == nil {
		c.pinBestMembers(ctx, workers, members, lookup, pin)
	}
	return replaced, err
}

// targetIDs maps the endpoint identity of a pool member to its servers' IDs.
type targetIDs map[string][]int

func (c *Controller) targetServers() targetIDs {
	targets := targetIDs{}
	for _, s := range c.catalog() {
		if id := xkeen.ServiceTargetID(s); id != "" {
			targets[id] = append(targets[id], s.ID)
		}
	}
	return targets
}

// lookup finds the servers of a member in the given catalogue by ID.
func (t targetIDs) lookup(catalog []models.Server) func(string) []models.Server {
	byID := make(map[int]models.Server, len(catalog))
	for _, s := range catalog {
		byID[s.ID] = s
	}
	return func(target string) []models.Server {
		var out []models.Server
		for _, id := range t[target] {
			if s, ok := byID[id]; ok {
				out = append(out, s)
			}
		}
		return out
	}
}

func (c *Controller) runningPoolWorkers() ([]poolWorker, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return nil, err
	}
	used := map[string]bool{}
	for _, id := range p.assigned {
		if p.pool(id) != nil {
			used[id] = true
		}
	}
	var workers []poolWorker
	for _, raw := range list(p.doc["proxies"]) {
		proxy := object(raw)
		name := str(proxy["name"])
		for pool := range used {
			if prefix := nodePrefix + pool + "-"; strings.HasPrefix(name, prefix) {
				port, _ := proxy["port"].(int)
				workers = append(workers, poolWorker{pool: pool, id: strings.TrimPrefix(name, prefix), port: port})
			}
		}
	}
	return workers, nil
}

// storePoolPings hands the worker's new answers to the ping history and
// returns its members.
func (c *Controller) storePoolPings(w poolWorker, observed map[string]xkeen.PoolObservation, tried map[string]time.Time, servers func(string) []models.Server) []string {
	var ids []string
	var samples []models.Server
	for member, o := range observed {
		ids = append(ids, member)
		key := w.key() + "/" + member
		tried[key] = c.poolTried[key]
		if o.Tried.IsZero() || !o.Tried.After(c.poolTried[key]) {
			continue
		}
		tried[key] = o.Tried
		for _, s := range servers(member) {
			s.Latency, s.ProbeKind, s.CheckError, s.LastChecked = o.Delay, "https", "", o.Tried
			samples = append(samples, s)
		}
	}
	if len(samples) > 0 && c.recordPings != nil {
		c.recordPings(samples, false)
	}
	sort.Strings(ids)
	return ids
}

// shownLatency is the number the servers of a target show: the best of them.
func shownLatency(servers []models.Server) int {
	best := -1
	for _, s := range servers {
		if s.Latency > 0 && (best < 0 || s.Latency < best) {
			best = s.Latency
		}
	}
	return best
}

// replaceSilentMembers takes the members of «Все локации» the router got no
// answer from twice in a row, or that cannot load a page, out of the pool, so
// the next fastest servers take their places. Nothing changes while no member
// answers: then the trouble is the internet or the probe, not the servers.
func (c *Controller) replaceSilentMembers(ctx context.Context, workers []poolWorker, members map[poolWorker][]string, lookup func(string) []models.Server) (int, error) {
	current := map[string]int{}
	var silent []string
	alive := 0
	for _, w := range workers {
		if w.pool != allPoolID {
			continue
		}
		for _, id := range members[w] {
			servers := lookup(id)
			current[id] = shownLatency(servers)
			switch {
			case len(servers) == 0:
			case current[id] > 0:
				alive++
			case xkeen.PingSilent(servers[0]) || servers[0].LoadError != "":
				silent = append(silent, id)
			}
		}
	}
	if alive == 0 || len(silent) == 0 {
		return 0, nil
	}
	fresh := c.silent.mark(silent)
	if len(fresh) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	p, err := c.read()
	c.mu.Unlock()
	if err != nil || p.pool(allPoolID) == nil {
		c.silent.forget(fresh)
		return 0, err
	}
	// The check of the newcomers takes seconds; the rest of the panel must not
	// wait for it.
	c.vetNewcomers(ctx, *p.pool(allPoolID), current)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.soft = true
	defer func() { c.soft = false }()
	_, err = c.apply(ctx, "", allPoolID, func(next *profile) error {
		if !bytes.Equal(next.raw, p.raw) {
			return errors.New("конфигурация изменилась параллельно")
		}
		return nil
	})
	if err != nil {
		c.silent.forget(fresh)
		return 0, err
	}
	return len(fresh), nil
}

// pinBestMembers points every pool at its member with the best number: the
// number every screen shows. A member whose last check failed has no number
// and is skipped; without any, the worker chooses by itself again.
func (c *Controller) pinBestMembers(ctx context.Context, workers []poolWorker, members map[poolWorker][]string, lookup func(string) []models.Server, pin func(context.Context, xkeen.Runtime, string, int, string) error) {
	pinned := map[string]poolPin{}
	for _, w := range workers {
		key := w.key()
		previous := c.poolPinned[key]
		best, bestMs := "", 0
		for _, id := range members[w] {
			ms := shownLatency(lookup(id))
			if ms > 0 && (best == "" || ms < bestMs || ms == bestMs && id == previous.member) {
				best, bestMs = id, ms
			}
		}
		if !previous.at.IsZero() && best == previous.member && time.Since(previous.at) < pinRefresh {
			pinned[key] = previous
			continue
		}
		err := pin(ctx, c.rt, w.id, w.port, best)
		switch {
		case errors.Is(err, xkeen.ErrPoolNoAPI):
			c.upgradePoolWorkers(ctx)
		case err != nil:
			log.Printf("Не удалось выбрать сервер пула: %v", err)
		}
		// A failed attempt waits like a successful one: the worker's API is
		// asked again in pinRefresh or when the best member changes.
		pinned[key] = poolPin{member: best, at: time.Now()}
	}
	c.poolPinned = pinned
}

// upgradePoolWorkers rebuilds the pools once, softly, when their workers were
// started without the routing API by an older panel.
func (c *Controller) upgradePoolWorkers(ctx context.Context) {
	if c.pinUpgrade {
		return
	}
	c.pinUpgrade = true
	c.mu.Lock()
	defer c.mu.Unlock()
	c.soft = true
	defer func() { c.soft = false }()
	if _, err := c.apply(ctx, "", "", nil); err != nil {
		log.Printf("Не удалось перезапустить ядра пулов с каналом управления: %v", err)
	}
}

// The servers that would come into the pool may have been measured hours ago,
// and many are dead by the time they are needed: every one of them used to
// cost another rebuild of the pool, eight in two minutes on our router. So the
// newcomers are checked first, by the router's check like every server, and
// those that fail go to the back of the pool as well. A few rounds at most;
// whatever is left unchecked the router will judge itself.
const vetRounds = 3

func (c *Controller) vetNewcomers(ctx context.Context, pool MultiPool, current map[string]int) {
	passed := map[string]bool{}
	for round := 0; round < vetRounds && ctx.Err() == nil; round++ {
		var newcomers []models.Server
		for _, s := range pool.members(c.poolNodes(c.catalog())) {
			id := xkeen.ServiceTargetID(s)
			if _, inPool := current[id]; !inPool && !passed[id] && !c.silent.has(id) {
				newcomers = append(newcomers, s)
			}
		}
		if len(newcomers) == 0 {
			return
		}
		checked, err := c.CheckServers(newcomers, xkeen.ProbeOptions{Context: ctx, Timeout: 5 * time.Second, Concurrency: 4, StateDir: c.stateDir})
		if err != nil {
			return
		}
		if c.recordPings != nil {
			c.recordPings(checked, true)
		}
		var failed []string
		for _, s := range checked {
			if id := xkeen.ServiceTargetID(s); s.ProbeKind == "https" && s.Latency > 0 && s.LoadError == "" {
				passed[id] = true
			} else {
				failed = append(failed, id)
			}
		}
		if len(failed) == 0 {
			return
		}
		c.silent.mark(failed)
	}
}
