package trafficjournal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"xkeen-panel/internal/trafficlog"
)

func flow(device, host, service, exit string, at time.Time) trafficlog.Entry {
	e := trafficlog.Entry{At: at, Kind: "connection", Device: device, DeviceID: "ip:" + device, Host: host, Port: "443", Network: "TCP", ServiceID: service, Route: []string{"Общий маршрут"}, Count: 1}
	if exit != "" {
		e.Exit = &trafficlog.Exit{Kind: exit, Name: "Server " + exit}
	}
	return e
}

func TestRecentJournalKeepsClosedConnections(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	log := newRecentLog(5, "s")
	log.now = func() time.Time { return now }
	for i := 0; i < 6; i++ {
		log.add(flow("192.168.1.10", fmt.Sprintf("host%d.example", i), "", "server", now.Add(time.Duration(i)*time.Second)))
	}
	// Bounded: the oldest record made room for the newest.
	page := log.query(trafficlog.Query{Limit: 10})
	if len(page.Events) != 5 || page.Events[0].Host != "host5.example" || page.Events[4].Host != "host1.example" || page.HasMore {
		t.Fatalf("newest first, five kept: %+v", page.Events)
	}
	// Pages do not shift when new records arrive.
	first := log.query(trafficlog.Query{Limit: 2})
	if len(first.Events) != 2 || !first.HasMore || first.NextCursor == "" {
		t.Fatalf("first page: %+v", first)
	}
	log.add(flow("192.168.1.10", "later.example", "", "server", now.Add(10*time.Second)))
	second := log.query(trafficlog.Query{Limit: 2, Cursor: first.NextCursor})
	if len(second.Events) != 2 || second.Events[0].Host != "host3.example" || second.Events[1].Host != "host2.example" {
		t.Fatalf("second page moved: %+v", second.Events)
	}
	// Records older than the keep time are not shown even before they are overwritten.
	now = now.Add(recentKeep + time.Minute)
	if page := log.query(trafficlog.Query{}); len(page.Events) != 0 {
		t.Fatalf("expired records are still shown: %d", len(page.Events))
	}
	if count, capacity, _ := log.size(); count != 0 || capacity != 5 {
		t.Fatalf("size: %d of %d", count, capacity)
	}
}

func TestRecentJournalFiltersAndGroups(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	log := newRecentLog(100, "s")
	log.now = func() time.Time { return now.Add(time.Minute) }
	pc, phone := "192.168.1.10", "192.168.1.20"
	log.add(flow(pc, "claude.ai", "claude", "server", now))
	log.add(flow(pc, "claude.ai", "claude", "server", now.Add(time.Second)))
	log.add(flow(pc, "lenta.com", "", "direct", now.Add(2*time.Second)))
	log.add(flow(phone, "youtube.com", "youtube", "server", now.Add(3*time.Second)))
	blocked := flow(phone, "api.anthropic.com", "claude", "reject", now.Add(4*time.Second))
	blocked.Kind, blocked.ID, blocked.Count = "kill_switch", "repeat-s-1", 1
	log.add(blocked)
	blocked.Count = 5 // the same blocked attempt, repeated
	log.add(blocked)

	count := func(q trafficlog.Query) int { return len(log.query(q).Events) }
	if count(trafficlog.Query{}) != 5 {
		t.Fatalf("a repeated block must stay one row: %d", count(trafficlog.Query{}))
	}
	if rows := log.query(trafficlog.Query{Kind: "kill_switch"}).Events; len(rows) != 1 || rows[0].Count != 5 {
		t.Fatalf("repeat count: %+v", rows)
	}
	checks := map[string]struct {
		q    trafficlog.Query
		want int
	}{
		"device by id":       {trafficlog.Query{Device: "ip:" + pc}, 3},
		"device by address":  {trafficlog.Query{Device: phone}, 2},
		"service":            {trafficlog.Query{Service: "claude"}, 3},
		"service and device": {trafficlog.Query{Service: "claude", Device: pc}, 2},
		"search host":        {trafficlog.Query{Search: "LENTA"}, 1},
		"search exit":        {trafficlog.Query{Search: "server direct"}, 1},
		"service and search": {trafficlog.Query{Service: "claude", Search: "anthropic"}, 1},
		"since":              {trafficlog.Query{Since: now.Add(3 * time.Second)}, 2},
		"before":             {trafficlog.Query{Before: now.Add(2 * time.Second)}, 2},
		"window":             {trafficlog.Query{Since: now.Add(time.Second), Before: now.Add(3 * time.Second)}, 2},
	}
	for name, check := range checks {
		if got := count(check.q); got != check.want {
			t.Errorf("%s: %d records, want %d", name, got, check.want)
		}
	}

	sites := log.sites(trafficlog.Query{})
	if len(sites) != 4 || sites[0].Host != "api.anthropic.com" || sites[0].Blocked != 5 || sites[0].Count != 5 {
		t.Fatalf("busiest site first, a repeated block counted by attempts: %+v", sites)
	}
	bySite := map[string]Site{}
	for _, site := range sites {
		bySite[site.Host] = site
	}
	if s := bySite["claude.ai"]; s.Count != 2 || s.VPN != 2 || s.Direct != 0 || s.ServiceID != "claude" || s.Devices != 1 || s.Exit == "" {
		t.Fatalf("claude.ai: %+v", s)
	}
	if s := bySite["lenta.com"]; s.Direct != 1 || s.VPN != 0 {
		t.Fatalf("lenta.com: %+v", s)
	}
	if only := log.sites(trafficlog.Query{Device: phone}); len(only) != 2 {
		t.Fatalf("sites of one device: %+v", only)
	}
	devices := log.devices()
	if len(devices) != 2 || devices[0].IP != phone {
		t.Fatalf("devices, most recent first: %+v", devices)
	}
}

func TestManagerKeepsRecentJournalWithoutDisk(t *testing.T) {
	dir := t.TempDir()
	m := New(context.Background(), dir)
	m.memory = func() (int64, int64) { return 1 << 30, 512 << 20 }
	m.applyRecent(m.config)
	if !m.Active() {
		t.Fatal("the short journal must be on without any disk")
	}
	m.Record(flow("192.168.1.10", "example.org", "", "server", time.Now()))
	page, devices := m.QueryRecent(trafficlog.Query{})
	if len(page.Events) != 1 || page.Events[0].DeviceID != "ip:192.168.1.10" || len(devices) != 1 {
		t.Fatalf("recent records: %+v %+v", page.Events, devices)
	}
	status := m.Status()
	if !status.RecentEnabled || status.RecentCount != 1 || status.RecentEvents != DefaultRecentEvents || status.Enabled {
		t.Fatalf("status: %+v", status)
	}

	// Switching it off drops the records and stops the observer's parsing.
	off := true
	if _, err := m.Apply(context.Background(), Patch{RecentOff: &off}); err != nil {
		t.Fatal(err)
	}
	if m.Active() || m.Status().RecentEnabled {
		t.Fatal("the short journal stayed on")
	}
	if page, _ := m.QueryRecent(trafficlog.Query{}); len(page.Events) != 0 {
		t.Fatal("records survived switching the journal off")
	}
	// The choice is saved.
	if again := New(context.Background(), dir); again.Active() {
		t.Fatal("a restart switched the short journal back on")
	}
	on, size := false, 800
	if _, err := m.Apply(context.Background(), Patch{RecentOff: &on, RecentEvents: &size}); err != nil {
		t.Fatal(err)
	}
	if status := m.Status(); !status.RecentEnabled || status.RecentEvents != 800 {
		t.Fatalf("resized journal: %+v", status)
	}
	for _, bad := range []int{10, 1_000_000} {
		if _, err := m.Apply(context.Background(), Patch{RecentEvents: &bad}); err == nil {
			t.Fatalf("a journal of %d records was accepted", bad)
		}
	}
	// A small router gets a smaller default.
	small := New(context.Background(), t.TempDir())
	small.memory = func() (int64, int64) { return 128 << 20, 64 << 20 }
	small.recent.Store(nil)
	small.applyRecent(small.config)
	if small.Status().RecentEvents != 1000 {
		t.Fatalf("default on a small router: %d", small.Status().RecentEvents)
	}
}

func TestPresetsAreValidatedAndSaved(t *testing.T) {
	dir := t.TempDir()
	presets := NewPresets(dir)
	if len(presets.List()) != 0 {
		t.Fatal("presets appeared from nowhere")
	}
	saved, err := presets.Replace([]Preset{
		{Name: " Claude на ПК ", Source: "recent", View: "sites", Device: "mac:aa:bb:cc:dd:ee:ff", Service: "claude"},
		{ID: "blocks", Name: "Блокировки", Source: "history", View: "list", Kind: "kill_switch"},
	})
	if err != nil || len(saved) != 2 || saved[0].Name != "Claude на ПК" || saved[0].ID == "" || saved[1].ID != "blocks" {
		t.Fatalf("saved: %+v %v", saved, err)
	}
	if again := NewPresets(dir).List(); len(again) != 2 || again[0] != saved[0] || again[1] != saved[1] {
		t.Fatalf("presets were not read back: %+v", again)
	}
	bad := [][]Preset{
		{{Name: "", Source: "recent", View: "list"}},
		{{Name: "x", Source: "disk", View: "list"}},
		{{Name: "x", Source: "recent", View: "table"}},
		{{Name: "x", Source: "recent", View: "list", Kind: "everything"}},
		{{Name: "line\nbreak", Source: "recent", View: "list"}},
		make([]Preset, maxPresets+1),
	}
	for i, list := range bad {
		if _, err := presets.Replace(list); err == nil {
			t.Errorf("invalid preset list %d was saved", i)
		}
	}
	if len(presets.List()) != 2 {
		t.Fatal("a refused list replaced the saved presets")
	}
	// A damaged file is an empty list, not an error for the journal.
	if err := os.WriteFile(filepath.Join(dir, "journal-presets.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if len(NewPresets(dir).List()) != 0 {
		t.Fatal("a damaged file produced presets")
	}
}
