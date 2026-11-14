package api

import (
	"sort"
	"time"

	"xkeen-panel/internal/keenetic"
)

// Keep byte deltas as well as their actual duration: the chart displays both
// speed and volume without integrating rounded rates on the client.
type wanInterval struct {
	Interface string  `json:"interface"`
	Seconds   float64 `json:"seconds,omitempty"`
	Received  uint64  `json:"rx_bytes"`
	Sent      uint64  `json:"tx_bytes"`
}

func wanIntervals(previous, current map[string]keenetic.TrafficCounters, elapsed time.Duration) []wanInterval {
	result := make([]wanInterval, 0, len(current))
	for id, next := range current {
		point := wanInterval{Interface: id}
		old, ok := previous[id]
		if ok && elapsed > 0 && elapsed <= 12*time.Second && next.Received >= old.Received && next.Sent >= old.Sent {
			point.Seconds = elapsed.Seconds()
			point.Received = next.Received - old.Received
			point.Sent = next.Sent - old.Sent
		}
		result = append(result, point)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Interface < result[j].Interface })
	return result
}
