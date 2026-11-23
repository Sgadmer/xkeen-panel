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

// The first phase asks for one byte and falls back to the second CDN.
func TestReachAsksForOneByteAndTriesTheSecondCDN(t *testing.T) {
	answer := func(firstCDN, secondCDN int) bool {
		client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			if r.Header.Get("Range") != "bytes=0-0" {
				t.Fatalf("reach must ask for a single byte, asked %q", r.Header.Get("Range"))
			}
			code := secondCDN
			if r.URL.String() == probeTargets[0] {
				code = firstCDN
			}
			if code == 0 {
				return nil, errors.New("silent")
			}
			return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("x"))}, nil
		})}
		return probeReach(context.Background(), client, time.Second)
	}
	if !answer(http.StatusPartialContent, 0) || !answer(0, http.StatusOK) || !answer(http.StatusForbidden, http.StatusPartialContent) {
		t.Fatal("a node that returned the byte through either CDN is reachable")
	}
	if answer(0, 0) || answer(http.StatusForbidden, http.StatusBadGateway) {
		t.Fatal("a node with no good answer is not reachable")
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
