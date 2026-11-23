package server

import (
	"context"
	"time"

	"xkeen-panel/internal/models"
)

// The panel re-checks the servers the router may switch to on its own, so a
// server that started to freeze leaves the pool and every screen shows a
// recent number. Between these runs the pool's own probes keep its choice
// fresh; these runs catch what an empty answer cannot.
const (
	poolCheckEvery    = 30 * time.Minute
	catalogCheckEvery = 6 * time.Hour
	firstCheckDelay   = 3 * time.Minute
	busyRetry         = 2 * time.Minute
)

type backgroundProber interface {
	StartBackground(ids []int) bool
}

func runBackgroundChecks(ctx context.Context, jobs backgroundProber, poolIDs func() []int, servers func() []models.Server) {
	timer := time.NewTimer(firstCheckDelay)
	defer timer.Stop()
	var lastCatalog time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		now := time.Now()
		catalog := now.Sub(lastCatalog) >= catalogCheckEvery
		ids := backgroundCheckIDs(servers(), poolIDs(), catalog, now)
		next := poolCheckEvery
		if len(ids) > 0 {
			if jobs.StartBackground(ids) {
				if catalog {
					lastCatalog = now
				}
			} else {
				// The owner's own check is running; come back soon.
				next = busyRetry
			}
		} else if catalog {
			lastCatalog = now
		}
		timer.Reset(next)
	}
}

// backgroundCheckIDs picks the pool members, every server without a result
// yet and, when the catalogue sweep is due, every server whose result is
// older than the sweep period. Complete provider profiles need a core each
// and are measured only by the sweep.
func backgroundCheckIDs(all []models.Server, pool []int, catalog bool, now time.Time) []int {
	inPool := make(map[int]bool, len(pool))
	for _, id := range pool {
		inPool[id] = true
	}
	stale := now.Add(-catalogCheckEvery + poolCheckEvery)
	ids := []int{}
	for _, s := range all {
		profile := len(s.RawProfile) != 0
		switch {
		case inPool[s.ID] && !profile:
		case s.ProbeKind != "https" && !profile:
		case catalog && s.LastChecked.Before(stale):
		default:
			continue
		}
		ids = append(ids, s.ID)
	}
	return ids
}
