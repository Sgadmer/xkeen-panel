package xkeen

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"xkeen-panel/internal/models"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A provider's mode is measured with the request of the router's own check:
// a plain GET of the pools' probe file, timed to the answer.
func TestModeIsMeasuredWithTheRoutersRequest(t *testing.T) {
	answer := func(fail bool) int {
		client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet || r.URL.String() != defaultProbeURL || r.Header.Get("Range") != "" {
				t.Fatalf("not the router's request: %s %s range %q", r.Method, r.URL, r.Header.Get("Range"))
			}
			if fail {
				return nil, errors.New("silent")
			}
			time.Sleep(15 * time.Millisecond)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}"))}, nil
		})}
		return probeLikeRouter(context.Background(), client)
	}
	if ms := answer(false); ms < 15 {
		t.Fatalf("an answer took %d ms", ms)
	}
	if ms := answer(true); ms != -1 {
		t.Fatalf("no answer is -1, got %d", ms)
	}
}

// The settings of the old TCP ping must not slow the server check down: a
// router installed long ago kept 3 at a time and 8 s per try.
func TestServerCheckIgnoresTheOldPingSettings(t *testing.T) {
	got := nodeProbeOptions(ProbeOptions{Concurrency: 3, Timeout: 8 * time.Second, StateDir: "kept"})
	if got.Concurrency != MaxProbeConcurrency || got.Timeout != probeAttempt || got.StateDir != "kept" {
		t.Fatalf("server check runs at %d nodes, %v per try", got.Concurrency, got.Timeout)
	}
}

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
