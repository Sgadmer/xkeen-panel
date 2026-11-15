package notifications

import (
	"encoding/json"
	"testing"
	"time"
)

func TestKillSwitchNotificationsRequireEventAndThrottle(t *testing.T) {
	var s transitions
	now := time.Now()
	if got := s.changes(Snapshot{}); len(got) != 0 {
		t.Fatal("empty observer created an event")
	}
	changes := s.changes(Snapshot{GuardEventID: "first", GuardAt: now})
	if len(changes) != 1 || changes[0].Kind != "kill_switch" {
		t.Fatal("missing observed guard event")
	}
	if len(s.changes(Snapshot{GuardEventID: "first", GuardAt: now})) != 0 {
		t.Fatal("same attempt notified twice")
	}
	if len(s.changes(Snapshot{GuardEventID: "second", GuardAt: now.Add(time.Second)})) != 0 {
		t.Fatal("packet burst not throttled")
	}
	if len(s.changes(Snapshot{GuardEventID: "third", GuardAt: now.Add(time.Minute)})) != 1 {
		t.Fatal("later failure episode not notified")
	}
	if (Preferences{Health: true}).allows("kill_switch") || !(Preferences{KillSwitch: true}).allows("kill_switch") {
		t.Fatal("kill-switch preference is not independent")
	}
	raw, err := json.Marshal(changes[0])
	if err != nil || string(raw) != `{"kind":"kill_switch"}` {
		t.Fatalf("notification contains sensitive event metadata: %s", raw)
	}
}
