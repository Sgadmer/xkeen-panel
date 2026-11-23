package cardcontroller

import (
	"bytes"
	"context"
	"errors"
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

// ReplaceSilentPoolMembers takes the servers the pool worker got no answer
// from out of «Все локации», so the next fastest servers take their places.
// Nothing changes while every member is silent: then the trouble is the
// internet or the probe, not the servers. It returns how many were replaced.
//
// The swap is soft, like a subscription reissue: new connections go to the
// new worker at once, while connections already open keep running through the
// previous one until they end. Closing them used to break every download and
// call through the pool on each replacement.
func (c *Controller) ReplaceSilentPoolMembers(ctx context.Context) (int, error) {
	p, delays, err := c.allPoolState(ctx)
	if err != nil || delays == nil {
		return 0, err
	}
	var silent []string
	alive := 0
	for tag, ms := range delays {
		if ms > 0 {
			alive++
		} else {
			silent = append(silent, tag)
		}
	}
	if alive == 0 || len(silent) == 0 {
		return 0, nil
	}
	fresh := c.silent.mark(silent)
	if len(fresh) == 0 {
		return 0, nil
	}
	// The check of the newcomers takes seconds; the rest of the panel must not
	// wait for it.
	c.vetNewcomers(ctx, *p.pool(allPoolID), delays)
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

// allPoolState reads what the «Все локации» worker measured for each member.
// No delays means no pool in use, or a worker that cannot tell yet.
func (c *Controller) allPoolState(ctx context.Context) (profile, map[string]int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.read()
	if err != nil {
		return p, nil, err
	}
	used := false
	for _, id := range p.assigned {
		used = used || id == allPoolID
	}
	if !used || p.pool(allPoolID) == nil {
		return p, nil, nil
	}
	prefix := nodePrefix + allPoolID + "-"
	for _, raw := range list(p.doc["proxies"]) {
		proxy := object(raw)
		name := str(proxy["name"])
		if strings.HasPrefix(name, prefix) {
			port, _ := proxy["port"].(int)
			_, delays := xkeen.CardPoolState(ctx, c.rt, strings.TrimPrefix(name, prefix), port)
			return p, delays, nil
		}
	}
	return p, nil, nil
}

// The servers that would come into the pool were measured by the panel up to
// six hours ago, and many are dead by the time they are needed: every one of
// them used to cost another rebuild of the pool, eight in two minutes on our
// router. So the newcomers are checked first, the way the panel checks every
// server, and those that fail go to the back of the pool as well. A few rounds
// at most; whatever is left unchecked the router will judge itself.
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
		var failed []string
		for _, s := range checked {
			if id := xkeen.ServiceTargetID(s); s.ProbeKind == "https" && s.Latency >= 0 {
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
