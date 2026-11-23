package cardcontroller

import (
	"context"
	"testing"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func TestSilentServerLeavesAllLocations(t *testing.T) {
	var silent silentMembers
	if fresh := silent.mark([]string{"b"}); len(fresh) != 1 {
		t.Fatalf("first verdict must be new: %v", fresh)
	}
	if fresh := silent.mark([]string{"b"}); len(fresh) != 0 {
		t.Fatalf("a repeated verdict must not rebuild the pool again: %v", fresh)
	}
	nodes := []poolNode{
		{id: "a", server: models.Server{ID: 1, Latency: 100, ProbeKind: "https"}, allowed: true},
		{id: "b", server: models.Server{ID: 2, Latency: 120, ProbeKind: "https"}, allowed: true, silent: silent.has("b")},
		{id: "c", server: models.Server{ID: 3, Latency: 150, ProbeKind: "https"}, allowed: true},
	}
	pool := MultiPool{ID: allPoolID, limit: 2}
	got := pool.members(nodes)
	if len(got) != 2 || got[0].ID != 1 || got[1].ID != 3 {
		t.Fatalf("the next fastest server must take the silent one's place: %+v", got)
	}
	pool = MultiPool{ID: allPoolID, limit: 3}
	got = pool.members(nodes)
	if len(got) != 3 || got[2].ID != 2 || pool.EligibleCount != 3 {
		t.Fatalf("a silent server must fill the pool rather than leave it short: %+v", got)
	}
	everyone := MultiPool{ID: "custom"}
	if got := everyone.members(nodes); len(got) != 3 || got[1].ID != 2 {
		t.Fatalf("only «Все локации» reorders silent servers: %+v", got)
	}
	silent.forget([]string{"b"})
	if silent.has("b") {
		t.Fatal("a failed rebuild must not keep the server out")
	}
}

// Servers measured hours ago are checked before they enter the pool, so one
// rebuild replaces a silent member instead of a chain of them.
func TestNewcomersAreCheckedBeforeTheyEnterThePool(t *testing.T) {
	servers := []models.Server{}
	for i, port := range []string{"10001", "10002", "10003", "10004", "10005"} {
		s := poolServer("A", "DE", port)
		s.ID, s.Latency, s.ProbeKind = i+1, 100+i, "https"
		servers = append(servers, s)
	}
	id := func(i int) string { return xkeen.ServiceTargetID(servers[i]) }
	dead := map[string]bool{id(2): true, id(3): true}
	checked := 0
	c := &Controller{catalog: func() []models.Server { return servers }}
	c.probe = func(_ xkeen.Runtime, batch []models.Server, _ xkeen.ProbeOptions) ([]models.Server, error) {
		out := []models.Server{}
		for _, s := range batch {
			checked++
			if dead[xkeen.ServiceTargetID(s)] {
				s.Latency = -1
			}
			out = append(out, s)
		}
		return out, nil
	}
	// Two members in the pool; the second went silent.
	c.silent.mark([]string{id(1)})
	pool := MultiPool{ID: allPoolID, limit: 2}
	c.vetNewcomers(context.Background(), pool, map[string]int{id(0): 120, id(1): -1})
	got := pool.members(c.poolNodes(servers))
	if len(got) != 2 || got[0].ID != 1 || got[1].ID != 5 {
		t.Fatalf("the first newcomer that passes the check must take the place: %+v", got)
	}
	if checked != 3 || !c.silent.has(id(2)) || !c.silent.has(id(3)) {
		t.Fatalf("checked %d servers; the dead newcomers must go to the back", checked)
	}
}
