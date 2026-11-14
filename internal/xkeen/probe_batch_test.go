package xkeen

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

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

type connectivityTransport func(*http.Request) (*http.Response, error)

func (fn connectivityTransport) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func TestHTTPSLatencyUsesOnlyConnectivityEndpoints(t *testing.T) {
	endpoints := []string{"https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"}
	for _, tc := range []struct {
		name     string
		statuses []int
		works    bool
	}{
		{"first endpoint available", []int{204}, true},
		{"fallback available", []int{403, 204}, true},
		{"both unavailable", []int{403, 500}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Timeout: time.Second, Transport: connectivityTransport(func(req *http.Request) (*http.Response, error) {
				if calls >= len(tc.statuses) || req.URL.String() != endpoints[calls] || req.Method != http.MethodGet {
					t.Fatalf("unexpected request %s %s", req.Method, req.URL)
				}
				status := tc.statuses[calls]
				calls++
				return &http.Response{StatusCode: status, Body: http.NoBody}, nil
			})}
			if got := measureHTTPSLatency(context.Background(), client); (got > 0) != tc.works || calls != len(tc.statuses) {
				t.Fatalf("latency=%d, requests=%d", got, calls)
			}
		})
	}
}
