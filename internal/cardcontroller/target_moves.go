package cardcontroller

import (
	"context"

	"xkeen-panel/internal/xkeen"
)

// A subscription refresh can reissue the parameters behind an unchanged server
// name. Saved selections store the parameter fingerprint, so without this step
// the card would lose its server and stay blocked until chosen again.
//
// A service card stores no source. It follows a move only once its old
// fingerprint has left the whole catalogue: another subscription may still
// offer exactly the server that was chosen. The common route and the explicit
// members of a multipool name their source and follow that source alone.
func rebindTargets(p *profile, moves []xkeen.TargetMove, present map[string]bool) int {
	replacement := xkeen.FollowableTargets(moves, present)
	scoped := func(source, target string) string {
		for _, move := range moves {
			if move.SourceID == source && move.From == target && move.From != move.To && present[move.To] {
				return move.To
			}
		}
		return ""
	}
	changed := 0
	defaultSource := str(p.doc[defaultSourceKey])
	for service, target := range p.assigned {
		to := ""
		switch {
		case service == defaultID && defaultSource != "":
			to = scoped(defaultSource, target)
		case !present[target]:
			to = replacement[target]
		}
		if to == "" {
			continue
		}
		p.assigned[service] = to
		if service == defaultID && str(p.doc[replacementKey]) == target {
			p.doc[replacementKey] = to
		}
		changed++
	}
	rewritten := false
	for i := range p.pools {
		var members []PoolMember
		seen := map[PoolMember]bool{}
		moved := false
		for _, ref := range p.pools[i].Members {
			if to := scoped(ref.SourceID, ref.TargetID); to != "" {
				ref.TargetID, moved = to, true
				changed++
			}
			if !seen[ref] {
				members = append(members, ref)
				seen[ref] = true
			}
		}
		if moved {
			p.pools[i].Members, rewritten = members, true
		}
	}
	if rewritten {
		p.doc[poolsKey] = p.pools
	}
	return changed
}

// ReconcileMoves is Reconcile for a refreshed subscription. Selections follow
// the reported identity changes in the same validated reload that replaces the
// affected routes, so a card never passes through a state without its server.
func (c *Controller) ReconcileMoves(ctx context.Context, moves []xkeen.TargetMove) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rebound := 0
	var follow func(*profile) error
	if len(moves) > 0 {
		follow = func(next *profile) error {
			present := map[string]bool{}
			for _, s := range c.catalog() {
				if id := xkeen.ServiceTargetID(s); id != "" {
					present[id] = true
				}
			}
			rebound = rebindTargets(next, moves, present)
			return nil
		}
	}
	return rebound, c.reconcile(ctx, follow)
}
