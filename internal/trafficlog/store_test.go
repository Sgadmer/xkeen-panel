//go:build (linux && (amd64 || arm64)) || (windows && amd64)

package trafficlog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct{ at atomic.Int64 }

func (c *clock) Now() time.Time { return time.Unix(0, c.at.Load()).UTC() }
func newClock() *clock {
	c := &clock{}
	c.at.Store(time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC).UnixNano())
	return c
}
func fixture(t *testing.T, l Limits, c *clock, validate func(string) error) *Store {
	t.Helper()
	if validate == nil {
		validate = func(string) error { return nil }
	}
	path := filepath.Join(t.TempDir(), "history", "traffic.sqlite")
	s, err := Open(context.Background(), path, Options{Limits: l, Validate: validate, Now: c.Now, FlushInterval: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func entry(at time.Time, id string) Entry {
	return Entry{At: at, Kind: "connection", DeviceID: "mac:" + id, Device: "192.0.2.5", DeviceName: "Test device", Host: "api.example.com", Network: "TCP", Port: "443", Route: []string{"ChatGPT", "Test VPN"}, Exit: &Exit{Kind: "server", Name: "Test server", Country: "US", Source: "Example"}}
}
func flush(t *testing.T, s *Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
}
func all(t *testing.T, s *Store) Page {
	t.Helper()
	p, err := s.Query(context.Background(), Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHistoryExpiresEachRecordAndPersists(t *testing.T) {
	c := newClock()
	s := fixture(t, DefaultLimits(), c, nil)
	old := entry(c.Now().Add(-24*time.Hour+time.Minute), "a")
	old.ID = "old"
	newer := entry(c.Now().Add(-time.Hour), "a")
	newer.ID = "new"
	if !s.Submit(old) || !s.Submit(newer) {
		t.Fatal("valid entries not accepted")
	}
	flush(t, s)
	if len(all(t, s).Events) != 2 {
		t.Fatal("initial history")
	}
	c.at.Add(int64(2 * time.Minute))
	p := all(t, s)
	if len(p.Events) != 1 || p.Events[0].ID != "new" {
		t.Fatal("query rolling expiry failed")
	}
	flush(t, s)
	var count int
	if err := s.writer.QueryRow(`SELECT count(*) FROM events`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("expired disk row retained: %d %v", count, err)
	}
	path := s.path
	_ = s.Close()
	r, err := Open(context.Background(), path, Options{Validate: func(string) error { return nil }, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	p = all(t, r)
	if len(p.Events) != 1 || p.Events[0].ID != "new" || p.Events[0].Exit.Source != "Example" {
		t.Fatal("reopen changed frozen history")
	}
}

func TestHistoryFIFODeviceAndGlobalLimits(t *testing.T) {
	l := DefaultLimits()
	l.MaxEvents = 5
	l.MaxDeviceEvents = 3
	c := newClock()
	s := fixture(t, l, c, nil)
	for i := 0; i < 8; i++ {
		id := "a"
		if i >= 4 {
			id = "b"
		}
		e := entry(c.Now().Add(time.Duration(i)*time.Millisecond), id)
		e.ID = fmt.Sprint(i)
		if !s.Submit(e) {
			t.Fatal("submit")
		}
	}
	flush(t, s)
	p := all(t, s)
	if len(p.Events) != 5 || p.Events[0].ID != "7" || p.Events[4].ID != "2" || p.Status.Evicted != 3 {
		t.Fatalf("FIFO result %+v %+v", p.Events, p.Status)
	}
	devices, err := s.Devices(context.Background())
	if err != nil || len(devices) != 2 {
		t.Fatal("device directory", err)
	}
}

func TestHistoryStableCursorFiltersAndDuplicateCount(t *testing.T) {
	c := newClock()
	s := fixture(t, DefaultLimits(), c, nil)
	for i := 0; i < 7; i++ {
		e := entry(c.Now().Add(time.Duration(i)*time.Millisecond), "a")
		e.ID = fmt.Sprint(i)
		e.ServiceID = "openai"
		s.Submit(e)
	}
	flush(t, s)
	p, err := s.Query(context.Background(), Query{Service: "openai", Search: "example", Limit: 3})
	if err != nil || !p.HasMore || len(p.Events) != 3 {
		t.Fatal("first page", err)
	}
	e := entry(c.Now().Add(time.Second), "a")
	e.ID = "late"
	e.ServiceID = "openai"
	s.Submit(e)
	flush(t, s)
	p2, err := s.Query(context.Background(), Query{Service: "openai", Search: "example", Cursor: p.NextCursor, Limit: 3})
	if err != nil || len(p2.Events) != 3 || p2.Events[0].ID != "3" {
		t.Fatal("cursor replay/gap", err)
	}
	if _, err = s.Query(context.Background(), Query{Service: "claude", Search: "example", Cursor: p.NextCursor, Limit: 3}); err == nil {
		t.Fatal("cursor accepted different filter")
	}
	e = entry(c.Now().Add(2*time.Second), "a")
	e.ID = "late"
	e.Count = 17
	e.Route = []string{"Changed VPN"}
	s.Submit(e)
	flush(t, s)
	p = all(t, s)
	if len(p.Events) != 8 || p.Events[0].Count != 17 || p.Events[0].Route[1] != "Test VPN" {
		t.Fatal("duplicate changed historic route")
	}
	p, err = s.Query(context.Background(), Query{Device: "192.0.2.5", Limit: 100})
	if err != nil || len(p.Events) != 8 {
		t.Fatal("historical IP filter", err)
	}
}

func TestHistoryQueueBoundedAndOfflineRecovery(t *testing.T) {
	c := newClock()
	var online atomic.Bool
	online.Store(true)
	s := fixture(t, DefaultLimits(), c, func(string) error {
		if !online.Load() {
			return errors.New("offline")
		}
		return nil
	})
	online.Store(false)
	start := time.Now()
	accepted := 0
	for range 1100 {
		if s.Submit(entry(c.Now(), "a")) {
			accepted++
		}
	}
	if accepted != 1024 || time.Since(start) > time.Second {
		t.Fatalf("producer accepted=%d took=%v", accepted, time.Since(start))
	}
	if s.Flush(context.Background()) == nil {
		t.Fatal("offline flush accepted")
	}
	st := s.Status()
	if st.StorageAvailable || st.Queued != 0 || st.Dropped != 1100 {
		t.Fatalf("offline status %+v", st)
	}
	online.Store(true)
	s.Submit(entry(c.Now(), "a"))
	flush(t, s)
	st = s.Status()
	if !st.StorageAvailable || st.Events != 1 || st.Error != "" {
		t.Fatalf("recovery %+v", st)
	}
}

func TestHistoryRefusesMissingMountAndForeignFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-mounted", "journal")
	path := filepath.Join(dir, "traffic.sqlite")
	if _, err := Open(context.Background(), path, Options{Validate: func(string) error { return errors.New("not mounted") }}); err == nil {
		t.Fatal("missing volume accepted")
	}
	if _, err := os.Stat(filepath.Dir(dir)); !os.IsNotExist(err) {
		t.Fatal("mount hierarchy recreated")
	}
	path = filepath.Join(t.TempDir(), "traffic.sqlite")
	original := []byte("not a traffic database")
	_ = os.WriteFile(path, original, 0644)
	if _, err := Open(context.Background(), path, Options{Validate: func(string) error { return nil }}); err == nil {
		t.Fatal("foreign file accepted")
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(original) {
		t.Fatal("foreign file modified")
	}
	if _, err := Open(context.Background(), path, Options{}); err == nil {
		t.Fatal("missing validator accepted")
	}
	foreign := filepath.Join(t.TempDir(), "foreign.sqlite")
	db, err := sql.Open("sqlite", foreign)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE keep(value TEXT)`)
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Open(context.Background(), foreign, Options{Validate: func(string) error { return nil }}); err == nil {
		t.Fatal("unowned SQLite accepted")
	}
}

func TestHistoryPhysicalBudgetAndFIFOReuse(t *testing.T) {
	c := newClock()
	l := DefaultLimits()
	l.MaxBytes = 4 << 20
	s := fixture(t, l, c, nil)
	for batch := 0; batch < 24; batch++ {
		for i := 0; i < 128; i++ {
			e := entry(c.Now().Add(time.Duration(batch*128+i)*time.Microsecond), "a")
			e.ID = fmt.Sprintf("%d-%d", batch, i)
			e.Rule = strings.Repeat("r", 380)
			e.DeviceName = strings.Repeat("d", 120)
			e.Route = []string{strings.Repeat("a", 150), strings.Repeat("b", 150), strings.Repeat("c", 150), strings.Repeat("d", 150), strings.Repeat("e", 150), strings.Repeat("f", 150), strings.Repeat("g", 150), strings.Repeat("h", 150)}
			if !s.Submit(e) {
				t.Fatal("bounded payload rejected")
			}
		}
		flush(t, s)
		size, err := s.physicalBytes()
		if err != nil || size > l.MaxBytes {
			t.Fatalf("disk quota exceeded %d %v", size, err)
		}
	}
	p := all(t, s)
	if p.Status.Evicted == 0 || p.Events[0].ID != "23-127" {
		t.Fatal("byte-budget FIFO did not retain latest")
	}
	if runtime.GOOS != "windows" {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			st, err := os.Stat(s.path + suffix)
			if err == nil && st.Mode().Perm() != 0600 {
				t.Fatal("nonprivate database permissions")
			}
		}
	}
}

func TestHistoryConcurrentReadersAndShutdown(t *testing.T) {
	c := newClock()
	s := fixture(t, DefaultLimits(), c, nil)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			s.Submit(entry(c.Now(), "a"))
			if i%16 == 0 {
				_ = s.Flush(context.Background())
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range 40 {
			_, _ = s.Query(context.Background(), Query{Limit: 10})
			_ = s.Status()
		}
	}()
	wg.Wait()
	flush(t, s)
	if s.Status().Events != 100 {
		t.Fatalf("concurrent events %+v", s.Status())
	}
	_ = s.Close()
	if s.Submit(entry(c.Now(), "a")) {
		t.Fatal("closed journal accepted event")
	}
}

func TestHistorySanitizesMetadata(t *testing.T) {
	c := newClock()
	s := fixture(t, DefaultLimits(), c, nil)
	e := entry(c.Now(), "a")
	e.Host = "example.com/private?token=secret"
	if s.Submit(e) {
		t.Fatal("full URL admitted")
	}
	e = entry(c.Now(), "a")
	e.Route = []string{"https://name:password@example.com"}
	e.DeviceName = "Safe\nname"
	if !s.Submit(e) {
		t.Fatal("valid event rejected")
	}
	flush(t, s)
	p := all(t, s)
	if len(p.Events) != 1 || len(p.Events[0].Route) != 0 || strings.Contains(p.Events[0].DeviceName, "\n") {
		t.Fatal("unsafe metadata persisted")
	}
}

func BenchmarkHistoryBatchedJournal(b *testing.B) {
	c := newClock()
	s, err := Open(context.Background(), filepath.Join(b.TempDir(), "history", "traffic.sqlite"), Options{Validate: func(string) error { return nil }, Now: c.Now, FlushInterval: 3 * time.Second})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for range 128 {
			if !s.Submit(entry(c.Now(), "benchmark-device")) {
				b.Fatal("queue dropped")
			}
		}
		if err := s.Flush(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func TestHistoryBusyReaderDoesNotGrowWAL(t *testing.T) {
	c := newClock()
	l := DefaultLimits()
	l.MaxBytes = 4 << 20
	s := fixture(t, l, c, nil)
	for range 128 {
		s.Submit(entry(c.Now(), "a"))
	}
	flush(t, s)
	tx, err := s.reader.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	for range 128 {
		s.Submit(entry(c.Now(), "a"))
	}
	if err = s.Flush(context.Background()); err == nil {
		t.Fatal("writer ignored reader holding a checkpoint")
	}
	// The first batch may already have committed before the reader prevents
	// its checkpoint. A following batch must stop before adding more WAL.
	for range 128 {
		s.Submit(entry(c.Now(), "a"))
	}
	if err = s.Flush(context.Background()); err == nil {
		t.Fatal("writer ignored checkpoint backpressure")
	}
	size, err := s.physicalBytes()
	if err != nil || size > l.MaxBytes {
		t.Fatal("reader caused unbounded WAL", size, err)
	}
	_ = tx.Rollback()
	s.Submit(entry(c.Now(), "a"))
	flush(t, s)
	if s.Status().Dropped < 128 {
		t.Fatal("backpressure losses not reported")
	}
}

func TestHistoryIdleCleanupNeedsNoNewEvents(t *testing.T) {
	c := newClock()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "history", "traffic.sqlite"), Options{Validate: func(string) error { return nil }, Now: c.Now, FlushInterval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Submit(entry(c.Now().Add(-24*time.Hour+time.Minute), "a"))
	flush(t, s)
	c.at.Add(int64(2 * time.Minute))
	deadline := time.Now().Add(2 * time.Second)
	for s.Status().Events != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Status().Events != 0 || s.Status().Expired != 1 {
		t.Fatalf("idle expiry did not run: %+v", s.Status())
	}
}
