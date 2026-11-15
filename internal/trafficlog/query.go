//go:build (linux && (amd64 || arm64)) || (windows && amd64)

package trafficlog

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type cursor struct {
	At       int64  `json:"at"`
	Seq      int64  `json:"seq"`
	Snapshot int64  `json:"snapshot"`
	Filter   string `json:"filter"`
}

func filterHash(q Query) string {
	raw, _ := json.Marshal([]string{q.Device, q.Service, q.Kind, q.Search})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:8])
}

// Query reads at most 101 short rows, never holds a transaction while the
// browser scrolls, and filters expired entries even before disk cleanup runs.
func (s *Store) Query(parent context.Context, q Query) (Page, error) {
	page := Page{Events: []Entry{}, Status: s.Status()}
	if s.closing.Load() {
		return page, errClosed
	}
	if err := s.options.Validate(s.path); err != nil {
		return page, errDisk
	}
	if len(q.Device) > 128 || len(q.Service) > 32 || len(q.Search) > 128 || len(q.Cursor) > 512 {
		return page, errors.New("слишком длинный фильтр истории")
	}
	if q.Kind != "" && q.Kind != "connection" && q.Kind != "kill_switch" && q.Kind != "quic" && q.Kind != "error" {
		return page, errors.New("неизвестный тип события истории")
	}
	if q.Limit == 0 {
		q.Limit = 50
	}
	if q.Limit < 1 || q.Limit > 100 {
		return page, errors.New("размер страницы истории должен быть от 1 до 100")
	}
	q.Search = strings.ToLower(strings.TrimSpace(q.Search))
	ctx, cancel := context.WithTimeout(parent, 750*time.Millisecond)
	defer cancel()
	c := cursor{Filter: filterHash(q)}
	if q.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(q.Cursor)
		if err != nil || json.Unmarshal(raw, &c) != nil || c.At < 1 || c.Seq < 1 || c.Snapshot < c.Seq || c.Filter != filterHash(q) {
			return page, errors.New("недопустимая страница истории")
		}
	} else if err := s.reader.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq),0) FROM events`).Scan(&c.Snapshot); err != nil {
		return page, errors.New("история сейчас занята; повторите запрос")
	}
	where := []string{"at>?", "seq<=?"}
	args := []any{s.options.Now().Add(-s.options.Limits.Retention).UnixNano(), c.Snapshot}
	if q.Cursor != "" {
		where = append(where, "(at<? OR (at=? AND seq<?))")
		args = append(args, c.At, c.At, c.Seq)
	}
	if q.Device != "" {
		where = append(where, "(device_id=? OR device=?)")
		args = append(args, q.Device, q.Device)
	}
	if q.Service != "" {
		where = append(where, "service=?")
		args = append(args, q.Service)
	}
	if q.Kind != "" {
		where = append(where, "kind=?")
		args = append(args, q.Kind)
	}
	if q.Search != "" {
		where = append(where, "instr(search,?)>0")
		args = append(args, q.Search)
	}
	args = append(args, q.Limit+1)
	rows, err := s.reader.QueryContext(ctx, `SELECT seq,at,payload,count FROM events WHERE `+strings.Join(where, " AND ")+` ORDER BY at DESC,seq DESC LIMIT ?`, args...)
	if err != nil {
		return page, errors.New("история сейчас занята; повторите запрос")
	}
	defer rows.Close()
	last := c
	for rows.Next() {
		var seq, at int64
		var payload []byte
		var repeats int
		if err = rows.Scan(&seq, &at, &payload, &repeats); err != nil {
			return page, errors.New("не удалось прочитать историю")
		}
		if len(page.Events) == q.Limit {
			page.HasMore = true
			break
		}
		var entry Entry
		if len(payload) > MaxEntryBytes || json.Unmarshal(payload, &entry) != nil {
			return page, errors.New("повреждена запись истории")
		}
		entry.At = time.Unix(0, at).UTC()
		entry.Count = repeats
		page.Events = append(page.Events, entry)
		last.At, last.Seq = at, seq
	}
	if err = rows.Err(); err != nil {
		return page, errors.New("история сейчас занята; повторите запрос")
	}
	if page.HasMore {
		raw, _ := json.Marshal(last)
		page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return page, nil
}

// Devices returns a small, stable-ID directory for the filter; IP addresses are
// historical metadata and never replace an already known router device ID.
func (s *Store) Devices(parent context.Context) ([]Device, error) {
	devices := []Device{}
	if s.closing.Load() {
		return devices, errClosed
	}
	if err := s.options.Validate(s.path); err != nil {
		return devices, errDisk
	}
	ctx, cancel := context.WithTimeout(parent, 750*time.Millisecond)
	defer cancel()
	rows, err := s.reader.QueryContext(ctx, `SELECT id,name,ip,last_at FROM devices WHERE records>0 AND last_at>? ORDER BY last_at DESC LIMIT 512`, s.options.Now().Add(-s.options.Limits.Retention).UnixNano())
	if err != nil {
		return devices, errors.New("не удалось прочитать устройства истории")
	}
	defer rows.Close()
	for rows.Next() {
		var d Device
		var at int64
		if err = rows.Scan(&d.ID, &d.Name, &d.IP, &at); err != nil {
			return devices, errors.New("не удалось прочитать устройства истории")
		}
		d.LastSeen = time.Unix(0, at).UTC()
		devices = append(devices, d)
	}
	if rows.Err() != nil {
		return devices, errors.New("не удалось прочитать устройства истории")
	}
	return devices, nil
}
