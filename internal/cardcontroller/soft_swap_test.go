package cardcontroller

import (
	"strings"
	"testing"
	"time"
)

func TestReplacedWorkerRecognisesOnlyAReissue(t *testing.T) {
	a, b, pool := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	w1, w2 := strings.Repeat("1", 64), strings.Repeat("2", 64)
	cases := []struct {
		name                          string
		before, after, previous, want string
		pool                          bool
		worker                        string
	}{
		{"server found again under new keys", a, b, nodePrefix + a, nodePrefix + b, false, a},
		{"pool with a new worker for its members", pool, pool, nodePrefix + pool + "-" + w1, nodePrefix + pool + "-" + w2, true, w1},
		{"nothing changed", a, a, nodePrefix + a, nodePrefix + a, false, ""},
		{"the card was blocked before", a, b, "REJECT", nodePrefix + b, false, ""},
		{"the new server is not available", a, b, nodePrefix + a, "REJECT", false, ""},
		{"direct route", a, directTarget, nodePrefix + a, "DIRECT", false, ""},
		{"the group pointed at another server", a, b, nodePrefix + w1, nodePrefix + b, false, ""},
		{"another pool was chosen", a, pool, nodePrefix + a, nodePrefix + pool + "-" + w2, true, ""},
		{"a pool endpoint of another pool", pool, pool, nodePrefix + a + "-" + w1, nodePrefix + pool + "-" + w2, true, ""},
		{"an unprotected route behind a fallback group", a, b, failoverPrefix + "x", failoverPrefix + "y", false, ""},
		{"no saved choice", "", b, nodePrefix + a, nodePrefix + b, false, ""},
	}
	for _, tc := range cases {
		if got := replacedWorker(tc.before, tc.after, tc.previous, tc.want, tc.pool); got != tc.worker {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.worker)
		}
	}
}

func TestRetiredWorkerLivesWhileItsConnectionsDo(t *testing.T) {
	c := &Controller{retireSweep: true} // no timer in the test
	c.retire("busy", "XKP-endpoint-busy")
	c.retire("idle", "XKP-endpoint-idle")
	now := time.Now()
	chains := [][]string{{"XKP-endpoint-busy", "XKP-card-youtube"}, {"DIRECT"}}

	// The list of connections could not be read: nothing is given up early.
	if kept := c.stillUsed(nil, false, now); len(kept) != 2 {
		t.Fatalf("a worker was dropped without knowing its connections: %v", kept)
	}
	if kept := c.stillUsed(chains, true, now); len(kept) != 1 || kept[0] != "busy" {
		t.Fatalf("kept %v, want only the worker with an open connection", kept)
	}
	if _, left := c.retired["idle"]; left {
		t.Fatal("an unused worker stayed retired")
	}
	// The time limit ends the wait even for a connection that never closes.
	if kept := c.stillUsed(chains, true, now.Add(retireFor+time.Second)); len(kept) != 0 || len(c.retired) != 0 {
		t.Fatalf("a worker outlived the limit: %v", kept)
	}
}

func TestRetiredWorkersAreCapped(t *testing.T) {
	c := &Controller{retireSweep: true}
	for i := 0; i < maxRetired+3; i++ {
		c.retire(strings.Repeat(string(rune('a'+i)), 4), "endpoint")
		time.Sleep(time.Millisecond)
	}
	if len(c.retired) != maxRetired {
		t.Fatalf("%d retired workers kept, the limit is %d", len(c.retired), maxRetired)
	}
	if _, kept := c.retired["aaaa"]; kept {
		t.Fatal("the oldest worker was not the one given up")
	}
}
