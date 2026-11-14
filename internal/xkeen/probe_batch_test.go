package xkeen

import (
	"errors"
	"testing"

	"xkeen-panel/internal/models"
)

func TestProbeIndependentNodesIsolatesInvalidOutbound(t *testing.T) {
	nodes := []models.Server{{ID: 11}, {ID: 12}, {ID: 13}}
	var reported []int
	options := ProbeOptions{OnResult: func(s models.Server) { reported = append(reported, s.ID) }}
	var calls int
	batch := func(rt Runtime, servers []models.Server, o ProbeOptions) ([]models.Server, error) {
		calls++
		for _, s := range servers {
			if s.ID == 12 {
				return nil, errProbeConfig
			}
		}
		results := append([]models.Server(nil), servers...)
		for i := range results {
			results[i].Latency = 50
			o.report(results[i])
		}
		return results, nil
	}
	got, err := probeIndependentNodes(Runtime{}, nodes, options, batch)
	if err != nil || len(got) != 3 || got[0].Latency != 50 || got[1].Latency != -1 || got[2].Latency != 50 || len(reported) != 3 || calls != 5 {
		t.Fatalf("unexpected result: calls=%d reported=%v err=%v", calls, reported, err)
	}
	broken := errors.New("core unavailable")
	calls = 0
	_, err = probeIndependentNodes(Runtime{}, nodes, options, func(Runtime, []models.Server, ProbeOptions) ([]models.Server, error) { calls++; return nil, broken })
	if !errors.Is(err, broken) || calls != 1 {
		t.Fatal("infrastructure failure was treated as an invalid outbound")
	}
}
