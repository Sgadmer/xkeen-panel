package cardcontroller

import (
	"testing"

	"xkeen-panel/internal/models"
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
