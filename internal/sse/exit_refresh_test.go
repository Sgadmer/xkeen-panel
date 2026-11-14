package sse

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

func exitTestNode(id int, exit string, age time.Duration) models.Server {
	at := time.Now().Add(-age)
	return models.Server{ID: id, SourceID: "test", Protocol: "vless", ExitCountry: exit, ExitCheckedAt: at,
		RawURI: "vless://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa@vpn.invalid:" + strconv.Itoa(10000+id)}
}

func exitTestCatalogue(t *testing.T, servers []models.Server) *xkeen.SubscriptionManager {
	t.Helper()
	sub := xkeen.NewSubscriptionManager(t.TempDir())
	if err := sub.RestoreData(models.SubscriptionData{CatalogVersion: 1, Sources: []models.SubscriptionSource{{ID: "test", Kind: "file", Name: "Test"}}, Servers: servers}); err != nil {
		t.Fatal(err)
	}
	return sub
}

func TestBackgroundExitRefreshOnlyChecksDueNodes(t *testing.T) {
	never := exitTestNode(1, "", 0)
	never.ExitCheckedAt = time.Time{}
	sub := exitTestCatalogue(t, []models.Server{never, exitTestNode(2, "SE", time.Hour), exitTestNode(3, "NL", 23*time.Hour),
		exitTestNode(4, "", 2*time.Hour), exitTestNode(5, "", 4*time.Hour),
		{ID: 6, Protocol: "xray-profile"}, {ID: 7, RawURI: "unsupported://test"}})
	calls := 0
	jobs := NewProbeJobs(sub, xkeen.ProbeOptions{Concurrency: 6}, func(nodes []models.Server, opts xkeen.ProbeOptions) ([]models.Server, error) {
		calls++
		if opts.Concurrency != 2 || len(nodes) != 3 || nodes[0].ID != 1 || nodes[1].ID != 3 || nodes[2].ID != 5 {
			t.Fatalf("wrong scheduled set: %+v", nodes)
		}
		for i := range nodes {
			nodes[i].LastChecked, nodes[i].ExitCheckedAt = time.Now(), time.Now()
			nodes[i].ExitCountry, nodes[i].ProbeKind = "SE", "https"
		}
		return nodes, nil
	}, nil)
	jobs.refreshExitCountries(context.Background())
	jobs.refreshExitCountries(context.Background())
	if calls != 1 || jobs.Snapshot().Run != 0 {
		t.Fatal("repeated an already fresh batch or replaced the manual job")
	}
}

func TestManualProbePreemptsScheduledSubset(t *testing.T) {
	sub := exitTestCatalogue(t, []models.Server{exitTestNode(1, "", 5*time.Hour), exitTestNode(2, "SE", time.Hour)})
	started, stopped := make(chan struct{}), make(chan struct{})
	var saves atomic.Int32
	jobs := NewProbeJobs(sub, xkeen.ProbeOptions{Concurrency: 3}, func(nodes []models.Server, opts xkeen.ProbeOptions) ([]models.Server, error) {
		if len(nodes) == 1 {
			close(started)
			<-opts.Context.Done()
			return nodes, nil // Even a successful-looking result from a cancelled job must be discarded.
		}
		return nodes, nil
	}, func(_ context.Context, nodes []models.Server) error {
		if len(nodes) != 2 {
			t.Error("background subset replaced the full job")
		}
		saves.Add(1)
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		jobs.refreshExitCountries(ctx)
		close(stopped)
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("background probe did not start")
	}
	if nodes, message := jobs.Wait(ctx); len(nodes) != 2 || message != "" {
		t.Fatal("manual client did not receive full catalogue")
	}
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("manual probe failed to cancel scheduled work")
	}
	if saves.Load() != 1 {
		t.Fatal("cancelled probe committed a second result")
	}
}
