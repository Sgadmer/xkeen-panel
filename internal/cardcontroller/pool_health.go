package cardcontroller

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"time"

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
	c.mu.Lock()
	defer c.mu.Unlock()
	c.soft = true
	defer func() { c.soft = false }()
	p, err := c.read()
	if err != nil {
		return 0, err
	}
	used := false
	for _, id := range p.assigned {
		used = used || id == allPoolID
	}
	if !used || p.pool(allPoolID) == nil {
		return 0, nil
	}
	prefix := nodePrefix + allPoolID + "-"
	var silent []string
	alive := 0
	for _, raw := range list(p.doc["proxies"]) {
		proxy := object(raw)
		name := str(proxy["name"])
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		port, _ := proxy["port"].(int)
		_, delays := xkeen.CardPoolState(ctx, c.rt, strings.TrimPrefix(name, prefix), port)
		for tag, ms := range delays {
			if ms > 0 {
				alive++
			} else {
				silent = append(silent, tag)
			}
		}
		break
	}
	if alive == 0 || len(silent) == 0 {
		return 0, nil
	}
	fresh := c.silent.mark(silent)
	if len(fresh) == 0 {
		return 0, nil
	}
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
