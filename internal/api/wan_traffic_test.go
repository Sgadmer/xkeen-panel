package api

import (
	"testing"
	"time"

	"xkeen-panel/internal/keenetic"
)

func TestWANIntervalsKeepCounterResetsSeparate(t *testing.T) {
	old := map[string]keenetic.TrafficCounters{"fiber": {Received: 1 << 55, Sent: 10}, "mobile": {Received: 200, Sent: 150}}
	now := map[string]keenetic.TrafficCounters{"fiber": {Received: 1<<55 + 90, Sent: 20}, "mobile": {Received: 100, Sent: 300}, "vpn": {}}
	result := wanIntervals(old, now, 4500*time.Millisecond)
	if len(result) != 3 || result[0] != (wanInterval{Interface: "fiber", Seconds: 4.5, Received: 90, Sent: 10}) {
		t.Fatalf("invalid measured interval: %+v", result)
	}
	if result[1].Seconds != 0 || result[2].Seconds != 0 {
		t.Fatalf("unexpected reading after reset or first sample: %+v", result)
	}
	for _, span := range []time.Duration{0, -time.Second, 30 * time.Second} {
		if got := wanIntervals(old, now, span); got[0].Seconds != 0 {
			t.Errorf("invalid interval %v produced %+v", span, got)
		}
	}
	idle := wanIntervals(now, now, 5*time.Second)
	if idle[0].Seconds != 5 || idle[0].Received != 0 || idle[0].Sent != 0 {
		t.Fatal("zero traffic mistaken for unavailable measurement")
	}
}
