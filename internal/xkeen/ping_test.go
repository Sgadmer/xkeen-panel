package xkeen

import (
	"testing"
	"time"

	"xkeen-panel/internal/models"
)

func TestOneNumberIsTheMedianOfTheLastThreeChecks(t *testing.T) {
	s := models.Server{}
	at := time.Date(2026, 11, 24, 1, 0, 0, 0, time.UTC)
	step := func(ms int) {
		at = at.Add(time.Minute)
		if !ApplyPing(&s, ms, "", at) {
			t.Fatal("a newer check was refused")
		}
	}
	step(400)
	if s.Latency != 400 || s.CheckError != "" || s.ProbeKind != "https" || !s.LastChecked.Equal(at) {
		t.Fatalf("first check: %+v", s)
	}
	step(132)
	if s.Latency != 266 {
		t.Fatalf("two answers give their mean, got %d", s.Latency)
	}
	step(300)
	if s.Latency != 300 {
		t.Fatalf("three answers give their median, got %d", s.Latency)
	}
	step(900) // 132, 300, 900: one slow answer moves nothing
	if s.Latency != 300 || len(s.PingSamples) != 3 {
		t.Fatalf("a slow answer moved the number to %d (%d samples)", s.Latency, len(s.PingSamples))
	}
	if ApplyPing(&s, 50, "", at) {
		t.Fatal("a check not newer than the last one was stored")
	}
}

func TestNoAnswerHidesTheNumberAndTwoMakeTheServerSilent(t *testing.T) {
	s := models.Server{}
	at := time.Now()
	ApplyPing(&s, 200, "", at)
	ApplyPing(&s, -1, "", at.Add(time.Minute))
	if s.Latency != -1 || s.CheckError != PingNoAnswer || PingSilent(s) {
		t.Fatalf("one failed check: %+v silent=%v", s, PingSilent(s))
	}
	ApplyPing(&s, 0, "", at.Add(2*time.Minute))
	if !PingSilent(s) {
		t.Fatal("two failed checks in a row make a server silent")
	}
	ApplyPing(&s, 250, "", at.Add(3*time.Minute)) // the last three: none, none, 250
	if s.Latency != 250 || s.CheckError != "" || PingSilent(s) {
		t.Fatalf("an answer brings the number back: %+v", s)
	}
}

func TestAPageThatDoesNotLoadOutweighsAnswers(t *testing.T) {
	s := models.Server{LoadError: ProbeStalledError}
	ApplyPing(&s, 180, "", time.Now())
	if s.Latency != -1 || s.CheckError != ProbeStalledError {
		t.Fatalf("a server that cannot load a page has no number: %+v", s)
	}
}

func TestStaleSamplesDoNotCount(t *testing.T) {
	now := time.Now()
	samples := []models.PingSample{{Ms: 50, At: now.Add(-48 * time.Hour)}, {Ms: 300, At: now}}
	if got := PingMedian(samples); got != 300 {
		t.Fatalf("a sample of two days ago still counted: %d", got)
	}
}

func TestPoolSamplesAndFullChecksShareTheHistory(t *testing.T) {
	sm := NewSubscriptionManager(t.TempDir())
	server := models.Server{ID: 1, SourceID: "s", Name: "a", RawURI: "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.10:443?type=tcp"}
	sm.data.Servers = []models.Server{server}
	at := time.Now().Add(-time.Hour)
	full := server
	full.Latency, full.ProbeKind, full.LastChecked = 400, "https", at
	if err := sm.UpdateLatencies([]models.Server{full}); err != nil {
		t.Fatal(err)
	}
	pool := server
	pool.Latency, pool.ProbeKind, pool.LastChecked = 200, "https", at.Add(time.Minute)
	if err := sm.RecordPings([]models.Server{pool}); err != nil {
		t.Fatal(err)
	}
	got := sm.GetServers()[0]
	if got.Latency != 300 || len(got.PingSamples) != 2 {
		t.Fatalf("pool and full checks are one history: %+v", got)
	}
	next := server
	next.Latency, next.ProbeKind, next.LastChecked = 260, "https", at.Add(2*time.Minute)
	if preview := sm.PreviewPing(next); preview.Latency != 260 {
		t.Fatalf("the screen shows the stored number, got %d", preview.Latency)
	}
}
