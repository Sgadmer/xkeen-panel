package cardcontroller

import (
	"context"
	"slices"
	"sort"
	"strings"
	"time"

	"xkeen-panel/internal/xkeen"
)

// A subscription refresh can replace the keys of a server, or of the members
// of a pool, while the owner's choice stays the same. The route then gets a
// new worker. Connections that are already open still run through the previous
// worker and leave through the same provider, so they are left alone: closing
// them would interrupt every download and call each time a provider reissues
// its keys. The previous worker is kept until those connections finish, or
// until retireFor passes; a worker can only reach its own VPN servers, so a
// connection whose keys were revoked simply ends.
//
// Anything the owner changes — another server, another pool, a country
// excluded — is not a reissue and closes the affected connections as before.

const (
	retireFor  = 30 * time.Minute
	retireStep = time.Minute
	maxRetired = 4
)

type retiredWorker struct {
	endpoint string // the proxy name open connections still carry in their chain
	until    time.Time
}

// replacedWorker names the worker behind a route whose endpoint changed only
// because its keys were reissued. It returns "" for a real change of route.
//
// before and after are the saved choice of the card around the refresh,
// previous and want the proxies its group pointed at. A pool keeps its
// identifier and gets a new worker for its members; a single server is found
// again under its new fingerprint.
func replacedWorker(before, after, previous, want string, pool bool) string {
	if before == "" || after == "" || previous == want ||
		!strings.HasPrefix(previous, nodePrefix) || !strings.HasPrefix(want, nodePrefix) {
		return ""
	}
	if pool {
		prefix := nodePrefix + after + "-"
		worker, found := strings.CutPrefix(previous, prefix)
		if before != after || !found || !strings.HasPrefix(want, prefix) || !validHash(worker) {
			return ""
		}
		return worker
	}
	if before == after || !validHash(before) || !validHash(after) ||
		previous != nodePrefix+before || want != nodePrefix+after {
		return ""
	}
	return before
}

// retire keeps a replaced worker for the connections still using it.
// The caller holds c.mu.
func (c *Controller) retire(worker, endpoint string) {
	if c.retired == nil {
		c.retired = map[string]retiredWorker{}
	}
	c.retired[worker] = retiredWorker{endpoint: endpoint, until: time.Now().Add(retireFor)}
	// A router with little memory must not collect idle workers: the oldest go first.
	for len(c.retired) > maxRetired {
		oldest := ""
		for id, item := range c.retired {
			if oldest == "" || item.until.Before(c.retired[oldest].until) {
				oldest = id
			}
		}
		delete(c.retired, oldest)
	}
	if !c.retireSweep {
		c.retireSweep = true
		time.AfterFunc(retireStep, c.sweepRetired)
	}
}

// stillUsed drops the retired workers that no open connection needs any more
// and returns the rest. The caller holds c.mu.
func (c *Controller) stillUsed(chains [][]string, known bool, now time.Time) []string {
	var kept []string
	for id, item := range c.retired {
		used := !known // without the list of connections nothing is given up early
		for _, chain := range chains {
			if slices.Contains(chain, item.endpoint) {
				used = true
				break
			}
		}
		if !used || !now.Before(item.until) {
			delete(c.retired, id)
			continue
		}
		kept = append(kept, id)
	}
	sort.Strings(kept)
	return kept
}

func (c *Controller) openChains(ctx context.Context, api coreAPI) ([][]string, bool) {
	var snapshot struct{ Connections []connectionTracker }
	if err := api.request(ctx, "GET", "/connections", nil, &snapshot); err != nil {
		return nil, false
	}
	chains := make([][]string, 0, len(snapshot.Connections))
	for _, flow := range snapshot.Connections {
		chains = append(chains, flow.Chains)
	}
	return chains, true
}

// sweepRetired stops the retired workers nobody uses, once a minute while any remain.
func (c *Controller) sweepRetired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.retireSweep = false
	if len(c.retired) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	before := len(c.retired)
	if p, err := c.read(); err == nil {
		chains, known := c.openChains(ctx, p.api)
		kept := c.stillUsed(chains, known, time.Now())
		// The live set is known only after a completed reload; until then
		// nothing is stopped.
		if len(kept) != before && c.liveWorkers != nil && len(c.pending) == 0 {
			keep := map[string]bool{}
			for id := range c.liveWorkers {
				keep[id] = true
			}
			for _, id := range kept {
				keep[id] = true
			}
			_ = xkeen.PruneCardProxies(c.rt, keep)
		}
	}
	if len(c.retired) > 0 {
		c.retireSweep = true
		time.AfterFunc(retireStep, c.sweepRetired)
	}
}
