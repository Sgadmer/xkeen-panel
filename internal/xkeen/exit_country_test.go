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

type traceTransport func(*http.Request) (*http.Response, error)

func (fn traceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func TestTraceExitCountry(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		status           int
	}{
		{"country not datacenter", "colo=AMS\nip=1.1.1.1\nloc=SO\n", "SO", 200},
		{"ipv6", "loc=NL\r\nip=2606:4700:4700::1111\r\n", "NL", 200},
		{"missing observed IP", "colo=SO\nloc=SO", "", 200},
		{"no country", "ip=1.1.1.1\ncolo=AMS", "", 200},
		{"unknown country", "ip=1.1.1.1\nloc=XX", "", 200},
		{"Tor placeholder", "ip=1.1.1.1\nloc=T1", "", 200},
		{"unassigned code", "ip=1.1.1.1\nloc=AA", "", 200},
		{"conflicting", "loc=SO\nip=1.1.1.1\nloc=RU", "", 200},
		{"local address", "loc=SO\nip=::ffff:192.168.0.1", "", 200},
		{"oversized", "loc=SO\nip=1.1.1.1\n" + strings.Repeat("x", 4096), "", 200},
		{"redirect", "loc=SO\nip=1.1.1.1", "", http.StatusFound},
		{"HTTP error", "loc=SO\nip=1.1.1.1", "", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: traceTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != exitTraceURL || len(r.Header) > 0 {
					t.Fatal("unexpected destination or identifying request headers")
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			if got := probeExitCountry(context.Background(), client); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	calls := 0
	client := &http.Client{Transport: traceTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("VPN unavailable")
	})}
	if probeExitCountry(context.Background(), client) != "" || calls != 1 {
		t.Fatal("failed proxy request must not retry through another transport")
	}
}

func TestMeasuredExitCountryExpires(t *testing.T) {
	s := models.Server{RawURI: uriA, ExitCountry: "SE", ExitCheckedAt: time.Now().Add(-time.Hour)}
	if got := MeasuredExitCountry(s); got != "SE" {
		t.Fatalf("recent measurement = %q", got)
	}
	for _, at := range []time.Time{time.Now().Add(-ExitCountryTTL), {}, time.Now().Add(time.Hour)} {
		s.ExitCheckedAt = at
		if MeasuredExitCountry(s) != "" {
			t.Fatal("accepted expired or invalid timestamp")
		}
	}
	s.Protocol, s.ExitCheckedAt = "xray-profile", time.Now()
	if MeasuredExitCountry(s) != "" {
		t.Fatal("a composed provider route cannot establish one exit")
	}
}

func TestExitCountryTracksProbedConfiguration(t *testing.T) {
	sm := NewSubscriptionManager(t.TempDir())
	nodes, err := sm.ImportContent(uriA, "server")
	if err != nil {
		t.Fatal(err)
	}
	checked := nodes[0]
	checked.ExitCountry, checked.ExitCheckedAt = "SE", time.Now().Add(-time.Minute)
	checked.ProbeKind, checked.LastChecked, checked.Latency = "https", checked.ExitCheckedAt, 10
	save := func(s models.Server) {
		t.Helper()
		if err := sm.UpdateLatencies([]models.Server{s}); err != nil {
			t.Fatal(err)
		}
	}
	save(checked)
	// Same outbound and source, even if the provider renamed the location.
	renamed := strings.Split(uriA, "#")[0] + "#new"
	if _, err := sm.ImportContent(renamed, "server"); err != nil {
		t.Fatal(err)
	}
	if err := sm.Load(); err != nil || sm.GetServers()[0].ExitCountry != "SE" {
		t.Fatal("refresh or reload lost the observation for the same config")
	}
	failed := checked
	failed.ExitCountry, failed.ExitCheckedAt = "", time.Now()
	failed.LastChecked = failed.ExitCheckedAt
	save(failed)
	save(checked)
	got := sm.GetServers()[0]
	if got.ExitCountry != "" || got.ExitCheckedAt != failed.ExitCheckedAt || got.Latency != 10 {
		t.Fatal("a failure must revoke the previous exit without changing the independent HTTPS result")
	}
	if _, err := sm.ImportContent(uriB, "server"); err != nil {
		t.Fatal(err)
	}
	save(checked)
	if !sm.GetServers()[0].ExitCheckedAt.IsZero() {
		t.Fatal("late measurement attached to a different config")
	}
}
