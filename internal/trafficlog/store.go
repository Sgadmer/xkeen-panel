//go:build (linux && (amd64 || arm64)) || (windows && amd64)

package trafficlog

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

const applicationID = 0x584b504c
const batchSize = 128
const deleteChunk = 1000

var errDisk = errors.New("диск истории недоступен; запись журнала приостановлена")
var errWrite = errors.New("не удалось записать историю; работа VPN не изменена")
var errClosed = errors.New("история соединений остановлена")
var errCheckpoint = errors.New("чтение истории задержало запись; журнал повторит попытку")

type request struct {
	ctx  context.Context
	done chan error
}

type Store struct {
	path           string
	options        Options
	writer, reader *sql.DB
	queue          chan Entry
	flush          chan request
	stop           chan struct{}
	done           chan struct{}
	closing        atomic.Bool
	dropped        atomic.Uint64
	sequence       atomic.Uint64
	session        string
	mu             sync.RWMutex
	status         Status
	closeOnce      sync.Once
	nextCleanup    time.Time
	submitMu       sync.RWMutex
}

func Supported() bool       { return true }
func SupportReason() string { return "" }

func openStore(ctx context.Context, path string, options Options) (_ *Store, returned error) {
	if options.Limits == (Limits{}) {
		options.Limits = DefaultLimits()
	}
	if err := options.Limits.Validate(); err != nil {
		return nil, err
	}
	if options.Validate == nil {
		return nil, errors.New("для истории требуется проверка внешнего диска")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.QueueSize == 0 {
		options.QueueSize = 1024
	}
	if options.QueueSize < 1 || options.QueueSize > 2048 {
		return nil, errors.New("недопустимый размер очереди истории")
	}
	if options.FlushInterval == 0 {
		options.FlushInterval = 2 * time.Second
	}
	if options.FlushInterval < 50*time.Millisecond || options.FlushInterval > 3*time.Second {
		return nil, errors.New("недопустимый интервал записи истории")
	}
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "?\x00") {
		return nil, errors.New("укажите абсолютный путь истории на внешнем диске")
	}
	path = filepath.Clean(path)
	if err := options.Validate(path); err != nil {
		return nil, errDisk
	}
	dir := filepath.Dir(path)
	if st, err := os.Lstat(dir); os.IsNotExist(err) {
		// Create only one leaf below an existing, already validated mount path.
		// Never recreate a missing mount hierarchy on the router's internal disk.
		if parent, e := os.Stat(filepath.Dir(dir)); e != nil || !parent.IsDir() {
			return nil, errDisk
		}
		if err = os.Mkdir(dir, 0700); err != nil {
			return nil, errDisk
		}
	} else if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, errDisk
	} else if runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0 {
		// A custom folder may be the disk root or contain unrelated data.
		// Do not silently change its access permissions for the whole disk.
		return nil, errors.New("выберите отдельную приватную папку для журнала")
	}
	if err := options.Validate(path); err != nil {
		return nil, errDisk
	}
	created := false
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if e != nil {
			return nil, errDisk
		}
		_ = file.Close()
		created = true
	} else if err != nil || !st.Mode().IsRegular() {
		return nil, errDisk
	}
	s := &Store{path: path, options: options, queue: make(chan Entry, options.QueueSize), flush: make(chan request), stop: make(chan struct{}), done: make(chan struct{})}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, errWrite
	}
	s.session = hex.EncodeToString(random[:])
	defer func() {
		if returned != nil {
			if s.reader != nil {
				_ = s.reader.Close()
			}
			if s.writer != nil {
				_ = s.writer.Close()
			}
			if created {
				_ = os.Remove(path)
				_ = os.Remove(path + "-wal")
				_ = os.Remove(path + "-shm")
			}
		}
	}()
	s.writer, err = sql.Open("sqlite", databaseDSN(path, false))
	if err != nil {
		return nil, errWrite
	}
	s.writer.SetMaxOpenConns(1)
	var app int
	if err = s.writer.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); err != nil {
		return nil, errWrite
	}
	if !created && st.Size() > 0 && app != applicationID {
		return nil, errors.New("выбранный файл не является журналом этой панели")
	}
	if err = os.Chmod(path, 0600); err != nil {
		return nil, errDisk
	}
	// Reserve > half the physical quota for WAL frame overhead/checkpointing.
	// max_page_count bounds the database itself even if the filesystem is huge.
	pages := options.Limits.MaxBytes * 45 / 100 / 4096
	setup := []string{
		"PRAGMA page_size=4096", "PRAGMA auto_vacuum=INCREMENTAL", "PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL", "PRAGMA wal_autocheckpoint=128", "PRAGMA temp_store=MEMORY",
		"PRAGMA trusted_schema=OFF", "PRAGMA journal_size_limit=0",
		fmt.Sprintf("PRAGMA application_id=%d", applicationID), fmt.Sprintf("PRAGMA max_page_count=%d", pages),
		`CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,at INTEGER NOT NULL,device_id TEXT NOT NULL,device TEXT NOT NULL,service TEXT NOT NULL,kind TEXT NOT NULL,search TEXT NOT NULL,payload BLOB NOT NULL,count INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS events_at ON events(at DESC,seq DESC)`,
		`CREATE INDEX IF NOT EXISTS events_device_at ON events(device_id,at DESC,seq DESC)`,
		`CREATE INDEX IF NOT EXISTS events_ip_at ON events(device,at DESC,seq DESC)`,
		`CREATE INDEX IF NOT EXISTS events_service_at ON events(service,at DESC,seq DESC)`,
		`CREATE INDEX IF NOT EXISTS events_kind_at ON events(kind,at DESC,seq DESC)`,
		`CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,name TEXT NOT NULL,ip TEXT NOT NULL,last_at INTEGER NOT NULL,records INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS devices_last ON devices(last_at DESC)`,
	}
	for _, statement := range setup {
		if _, err = s.writer.ExecContext(ctx, statement); err != nil {
			return nil, errWrite
		}
	}
	var actualPages, actualMaxPages int64
	if s.writer.QueryRowContext(ctx, "PRAGMA page_count").Scan(&actualPages) != nil || s.writer.QueryRowContext(ctx, "PRAGMA max_page_count").Scan(&actualMaxPages) != nil || actualMaxPages > pages || actualPages > pages {
		return nil, errors.New("существующая история больше выбранного бюджета диска")
	}
	s.reader, err = sql.Open("sqlite", databaseDSN(path, true))
	if err != nil {
		return nil, errWrite
	}
	s.reader.SetMaxOpenConns(1)
	s.status = Status{Running: true, StorageAvailable: true, RetentionHours: int(options.Limits.Retention / time.Hour), MaxEvents: options.Limits.MaxEvents, MaxDeviceEvents: options.Limits.MaxDeviceEvents, MaxBytes: options.Limits.MaxBytes, QueueCapacity: options.QueueSize}
	if err = s.maintain(ctx); err != nil {
		return nil, err
	}
	if err = s.publish(ctx); err != nil {
		return nil, err
	}
	go s.run(ctx)
	return s, nil
}

func databaseDSN(path string, readOnly bool) string {
	p := filepath.ToSlash(path)
	if filepath.VolumeName(path) != "" {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	q := url.Values{"mode": []string{"rw"}, "_pragma": []string{"busy_timeout(250)", "cache_size(-2048)", "mmap_size(0)"}}
	if readOnly {
		q.Set("mode", "ro")
		q.Add("_pragma", "query_only(ON)")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Submit only validates/copies one bounded record and attempts a channel send.
// It never performs disk or router I/O and never waits for a database lock.
func (s *Store) Submit(entry Entry) bool {
	s.submitMu.RLock()
	defer s.submitMu.RUnlock()
	if s.closing.Load() {
		return false
	}
	if len(s.queue) == cap(s.queue) {
		s.dropped.Add(1)
		return false
	}
	entry, ok := s.normalize(entry)
	if !ok {
		s.dropped.Add(1)
		return false
	}
	select {
	case s.queue <- entry:
		return true
	default:
		s.dropped.Add(1)
		return false
	}
}

func (s *Store) normalize(e Entry) (Entry, bool) {
	switch e.Kind {
	case "connection", "kill_switch", "quic", "error":
	default:
		return Entry{}, false
	}
	if e.At.IsZero() {
		e.At = s.options.Now()
	}
	e.At = e.At.UTC()
	if !e.At.After(s.options.Now().Add(-s.options.Limits.Retention)) || e.At.After(s.options.Now().Add(time.Minute)) {
		return Entry{}, false
	}
	if e.ID == "" {
		e.ID = fmt.Sprintf("%s-%d", s.session, s.sequence.Add(1))
	}
	e.ID = clean(e.ID, 128)
	e.DeviceID = clean(e.DeviceID, 128)
	e.Device = clean(e.Device, 64)
	e.DeviceName = clean(e.DeviceName, 128)
	e.ServiceID = clean(e.ServiceID, 32)
	e.Host = clean(e.Host, 253)
	if strings.ContainsAny(e.Host, "/?#@ ") {
		return Entry{}, false
	}
	e.Port = clean(e.Port, 8)
	e.Network = clean(e.Network, 8)
	e.Rule = clean(e.Rule, 384)
	if e.DeviceID == "" {
		e.DeviceID = "ip:" + e.Device
	}
	if e.Device == "" || e.ID == "" {
		return Entry{}, false
	}
	if e.Count < 1 {
		e.Count = 1
	}
	if e.Count > 1000000 {
		e.Count = 1000000
	}
	route := make([]string, 0, min(len(e.Route), 8))
	for _, v := range e.Route[:min(len(e.Route), 8)] {
		if v = clean(v, 160); v != "" {
			route = append(route, v)
		}
	}
	e.Route = route
	if e.Exit != nil {
		v := *e.Exit
		v.Kind = clean(v.Kind, 24)
		v.Name = clean(v.Name, 160)
		v.Source = clean(v.Source, 128)
		v.Country = clean(v.Country, 8)
		e.Exit = &v
	}
	b, err := json.Marshal(e)
	if err != nil || len(b) > MaxEntryBytes {
		return Entry{}, false
	}
	return e, true
}

func clean(v string, n int) string {
	if !utf8.ValidString(v) || strings.Contains(v, "://") {
		return ""
	}
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, v)
	if len(v) > n {
		v = v[:n]
		for !utf8.ValidString(v) {
			v = v[:len(v)-1]
		}
	}
	return strings.Clone(strings.TrimSpace(v))
}

func (s *Store) Status() Status {
	s.mu.RLock()
	st := s.status
	s.mu.RUnlock()
	st.Dropped = s.dropped.Load()
	st.Queued = len(s.queue)
	if st.OldestAt != nil {
		v := *st.OldestAt
		st.OldestAt = &v
	}
	if st.LatestAt != nil {
		v := *st.LatestAt
		st.LatestAt = &v
	}
	return st
}

func (s *Store) Flush(ctx context.Context) error {
	if s.closing.Load() {
		return errClosed
	}
	r := request{ctx: ctx, done: make(chan error, 1)}
	select {
	case s.flush <- r:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return errClosed
	}
	select {
	case err := <-r.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return errClosed
	}
}

func (s *Store) Close() error {
	s.closeOnce.Do(func() { s.submitMu.Lock(); s.closing.Store(true); close(s.stop); s.submitMu.Unlock() })
	select {
	case <-s.done:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("завершение записи истории продолжается в фоне")
	}
}

func (s *Store) run(ctx context.Context) {
	tick := time.NewTicker(s.options.FlushInterval)
	defer tick.Stop()
	defer close(s.done)
	defer func() {
		_ = s.reader.Close()
		_ = s.writer.Close()
		s.mu.Lock()
		s.status.Running = false
		s.mu.Unlock()
	}()
	for {
		select {
		case <-ctx.Done():
			s.submitMu.Lock()
			s.closing.Store(true)
			s.submitMu.Unlock()
			s.finalFlush()
			return
		case <-s.stop:
			s.finalFlush()
			return
		case r := <-s.flush:
			err := s.drain(r.ctx)
			for err == nil && len(s.queue) > 0 && r.ctx.Err() == nil {
				err = s.drain(r.ctx)
			}
			if err == nil {
				err = r.ctx.Err()
			}
			r.done <- err
		case <-tick.C:
			_ = s.drain(ctx)
		}
	}
}

func (s *Store) finalFlush() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		if s.drain(ctx) != nil || len(s.queue) == 0 || ctx.Err() != nil {
			break
		}
	}
	s.dropQueue()
}

func (s *Store) drain(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	if err := s.options.Validate(s.path); err != nil {
		s.dropQueue()
		s.failed(errDisk, false)
		return errDisk
	}
	batch := make([]Entry, 0, min(len(s.queue), batchSize))
	for len(batch) < batchSize {
		select {
		case e := <-s.queue:
			batch = append(batch, e)
		default:
			goto collected
		}
	}
collected:
	if !s.options.Now().Before(s.nextCleanup) {
		if err := s.maintain(ctx); err != nil {
			s.dropped.Add(uint64(len(batch)))
			s.failed(err, true)
			return err
		}
		s.nextCleanup = s.options.Now().Add(time.Minute)
	}
	if len(batch) > 0 {
		if err := s.insert(ctx, batch); err != nil {
			var code interface{ Code() int }
			if errors.As(err, &code) && code.Code()&255 == 13 {
				// SQLite's independent page quota fired before the filesystem
				// filled. Make FIFO space and retry once, never grow the quota.
				n, cleanup := s.deleteEvents(ctx, `seq IN (SELECT seq FROM events ORDER BY at,seq LIMIT ?)`, deleteChunk)
				if cleanup == nil {
					s.addEvicted(n)
					_, _ = s.writer.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
					err = s.insert(ctx, batch)
				}
			}
			if err != nil {
				s.dropped.Add(uint64(len(batch)))
				s.failed(errWrite, true)
				return errWrite
			}
		}
	}
	if err := s.boundFiles(ctx); err != nil {
		s.failed(err, true)
		return err
	}
	if err := s.publish(ctx); err != nil {
		s.failed(errWrite, true)
		return errWrite
	}
	s.mu.Lock()
	s.status.Error = ""
	s.status.StorageAvailable = true
	s.mu.Unlock()
	return nil
}

func (s *Store) dropQueue() {
	for {
		select {
		case <-s.queue:
			s.dropped.Add(1)
		default:
			return
		}
	}
}
func (s *Store) failed(err error, available bool) {
	s.mu.Lock()
	s.status.Error = err.Error()
	s.status.StorageAvailable = available
	s.mu.Unlock()
}

func (s *Store) insert(ctx context.Context, entries []Entry) error {
	if err := s.options.Validate(s.path); err != nil {
		return errDisk
	}
	if err := s.checkpoint(ctx); err != nil {
		return err
	}
	if size, err := s.physicalBytes(); err != nil || size >= s.options.Limits.MaxBytes*80/100 {
		if err := s.boundFiles(ctx); err != nil {
			return err
		}
	}
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	insert, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO events(id,at,device_id,device,service,kind,search,payload,count) VALUES(?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer insert.Close()
	device, err := tx.PrepareContext(ctx, `INSERT INTO devices(id,name,ip,last_at,records) VALUES(?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET name=CASE WHEN excluded.last_at>=devices.last_at THEN excluded.name ELSE devices.name END,ip=CASE WHEN excluded.last_at>=devices.last_at THEN excluded.ip ELSE devices.ip END,last_at=MAX(devices.last_at,excluded.last_at),records=devices.records+1`)
	if err != nil {
		return err
	}
	defer device.Close()
	for _, e := range entries {
		if !e.At.After(s.options.Now().Add(-s.options.Limits.Retention)) {
			s.dropped.Add(1)
			continue
		}
		payload, err := json.Marshal(e)
		if err != nil {
			return err
		}
		search := strings.ToLower(strings.Join([]string{e.DeviceName, e.Device, e.Host, e.ServiceID, e.Rule, strings.Join(e.Route, " ")}, " "))
		result, err := insert.ExecContext(ctx, e.ID, e.At.UnixNano(), e.DeviceID, e.Device, e.ServiceID, e.Kind, search, payload, e.Count)
		if err != nil {
			return err
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			if _, err = tx.ExecContext(ctx, `UPDATE events SET count=MAX(count,?) WHERE id=? AND device_id=?`, e.Count, e.ID, e.DeviceID); err != nil {
				return err
			}
			continue
		}
		if _, err = device.ExecContext(ctx, e.DeviceID, e.DeviceName, e.Device, e.At.UnixNano()); err != nil {
			return err
		}
	}
	evicted, err := s.enforceWithin(ctx, tx)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.addEvicted(evicted)
	return nil
}

func (s *Store) maintain(ctx context.Context) error {
	if err := s.options.Validate(s.path); err != nil {
		return errDisk
	}
	cutoff := s.options.Now().Add(-s.options.Limits.Retention).UnixNano()
	// At most four chunks per flush; reads apply the cutoff immediately even
	// while a large expired backlog is being removed after a long shutdown.
	for range 4 {
		n, err := s.deleteEvents(ctx, `seq IN (SELECT seq FROM events WHERE at<=? ORDER BY at,seq LIMIT ?)`, cutoff, deleteChunk)
		if err != nil {
			return errWrite
		}
		s.mu.Lock()
		s.status.Expired += uint64(n)
		s.mu.Unlock()
		if n < deleteChunk {
			break
		}
	}
	if err := s.enforceCounts(ctx); err != nil {
		return errWrite
	}
	return s.boundFiles(ctx)
}

func (s *Store) enforceCounts(ctx context.Context) error {
	if err := s.checkpoint(ctx); err != nil {
		return err
	}
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	n, err := s.enforceWithin(ctx, tx)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.addEvicted(n)
	return nil
}

func (s *Store) enforceWithin(ctx context.Context, tx *sql.Tx) (int, error) {
	total := 0
	rows, err := tx.QueryContext(ctx, `SELECT id,records FROM devices WHERE records>? LIMIT 128`, s.options.Limits.MaxDeviceEvents)
	if err != nil {
		return 0, err
	}
	type excess struct {
		id string
		n  int
	}
	var excesses []excess
	for rows.Next() {
		var x excess
		if err = rows.Scan(&x.id, &x.n); err != nil {
			rows.Close()
			return 0, err
		}
		x.n -= s.options.Limits.MaxDeviceEvents
		excesses = append(excesses, x)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, x := range excesses {
		for x.n > 0 {
			n, err := deleteWithin(ctx, tx, `seq IN (SELECT seq FROM events WHERE device_id=? ORDER BY at,seq LIMIT ?)`, x.id, min(x.n, deleteChunk))
			if err != nil {
				return 0, err
			}
			if n == 0 {
				break
			}
			x.n -= n
			total += n
		}
	}
	var count int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(records),0) FROM devices`).Scan(&count); err != nil {
		return 0, err
	}
	for over := count - int64(s.options.Limits.MaxEvents); over > 0; {
		n, err := deleteWithin(ctx, tx, `seq IN (SELECT seq FROM events ORDER BY at,seq LIMIT ?)`, min(over, int64(deleteChunk)))
		if err != nil {
			return 0, err
		}
		if n == 0 {
			break
		}
		over -= int64(n)
		total += n
	}
	return total, nil
}

func (s *Store) addEvicted(n int) { s.mu.Lock(); s.status.Evicted += uint64(n); s.mu.Unlock() }

func (s *Store) deleteEvents(ctx context.Context, where string, args ...any) (int, error) {
	if err := s.options.Validate(s.path); err != nil {
		return 0, errDisk
	}
	if err := s.checkpoint(ctx); err != nil {
		return 0, err
	}
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n, err := deleteWithin(ctx, tx, where, args...)
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

func deleteWithin(ctx context.Context, tx *sql.Tx, where string, args ...any) (int, error) {
	rows, err := tx.QueryContext(ctx, `DELETE FROM events WHERE `+where+` RETURNING device_id`, args...)
	if err != nil {
		return 0, err
	}
	counts := map[string]int{}
	n := 0
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		counts[id]++
		n++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for id, count := range counts {
		if _, err = tx.ExecContext(ctx, `UPDATE devices SET records=records-? WHERE id=?`, count, id); err != nil {
			return 0, err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM devices WHERE records<=0`); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) physicalBytes() (int64, error) {
	var n int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		st, err := os.Lstat(s.path + suffix)
		if os.IsNotExist(err) && suffix != "" {
			continue
		}
		if err != nil || !st.Mode().IsRegular() {
			return 0, errDisk
		}
		n += st.Size()
	}
	return n, nil
}

func (s *Store) boundFiles(ctx context.Context) error {
	if err := s.options.Validate(s.path); err != nil {
		return errDisk
	}
	// A bounded, short read transaction cannot hold a checkpoint indefinitely.
	if err := s.checkpoint(ctx); err != nil {
		return err
	}
	for range 4 {
		size, err := s.physicalBytes()
		if err != nil {
			return errDisk
		}
		if size < s.options.Limits.MaxBytes*75/100 {
			for _, suffix := range []string{"", "-wal", "-shm"} {
				st, statErr := os.Lstat(s.path + suffix)
				if os.IsNotExist(statErr) {
					continue
				}
				if statErr != nil {
					return errDisk
				}
				if runtime.GOOS == "windows" || st.Mode().Perm() == 0600 {
					continue
				}
				if err = os.Chmod(s.path+suffix, 0600); err != nil {
					return errDisk
				}
			}
			return nil
		}
		n, err := s.deleteEvents(ctx, `seq IN (SELECT seq FROM events ORDER BY at,seq LIMIT ?)`, deleteChunk)
		if err != nil {
			return errWrite
		}
		s.addEvicted(n)
		if _, err = s.writer.ExecContext(ctx, `PRAGMA incremental_vacuum(512)`); err != nil {
			return errWrite
		}
		if err = s.checkpoint(ctx); err != nil {
			return err
		}
		if n == 0 {
			break
		}
	}
	return errors.New("достигнут бюджет диска истории; запись приостановлена")
}

func (s *Store) checkpoint(ctx context.Context) error {
	var busy, frames, done int
	if err := s.writer.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &frames, &done); err != nil {
		return errWrite
	}
	if busy != 0 {
		return errCheckpoint
	}
	return nil
}

func (s *Store) publish(ctx context.Context) error {
	var n int64
	var oldest, latest sql.NullInt64
	if err := s.writer.QueryRowContext(ctx, `SELECT COALESCE(SUM(records),0) FROM devices`).Scan(&n); err != nil {
		return err
	}
	if err := s.writer.QueryRowContext(ctx, `SELECT (SELECT at FROM events ORDER BY at,seq LIMIT 1),(SELECT at FROM events ORDER BY at DESC,seq DESC LIMIT 1)`).Scan(&oldest, &latest); err != nil {
		return err
	}
	bytes, err := s.physicalBytes()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Events = n
	s.status.Bytes = bytes
	s.status.OldestAt = nil
	s.status.LatestAt = nil
	if oldest.Valid {
		v := time.Unix(0, oldest.Int64).UTC()
		s.status.OldestAt = &v
	}
	if latest.Valid {
		v := time.Unix(0, latest.Int64).UTC()
		s.status.LatestAt = &v
	}
	return nil
}
