package trafficjournal

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"xkeen-panel/internal/trafficlog"
)

// recentLog keeps the newest journal records in memory. The list of active
// connections forgets a connection the moment it closes; this short memory
// answers "where did the device go a minute ago" without a disk. It is bounded
// by a number of records and by their age, and is lost when the panel restarts.
type recentLog struct {
	mu      sync.Mutex
	entries []trafficlog.Entry // a ring: head is the oldest record
	seqs    []int64
	head    int
	count   int
	next    int64
	keep    time.Duration
	now     func() time.Time
	session string
}

const (
	DefaultRecentEvents = 5000
	minRecentEvents     = 500
	maxRecentEvents     = 20000
	recentKeep          = time.Hour
	// A repeated block or error within its 15-second window updates the row it
	// already has. Only the newest rows need to be searched for it.
	repeatLookBack = 128
)

func newRecentLog(capacity int, session string) *recentLog {
	return &recentLog{entries: make([]trafficlog.Entry, capacity), seqs: make([]int64, capacity), keep: recentKeep, now: time.Now, session: session}
}

func (r *recentLog) at(i int) int { return (r.head + i) % len(r.entries) }

func (r *recentLog) add(entry trafficlog.Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry.At.IsZero() {
		entry.At = r.now().UTC()
	}
	if entry.Route == nil {
		entry.Route = []string{}
	}
	if entry.ID != "" {
		for i := r.count - 1; i >= 0 && i >= r.count-repeatLookBack; i-- {
			if at := r.at(i); r.entries[at].ID == entry.ID {
				r.entries[at].Count = entry.Count
				return
			}
		}
	}
	r.next++
	if entry.ID == "" {
		entry.ID = "recent-" + r.session + "-" + strconv.FormatInt(r.next, 10)
	}
	if entry.Count < 1 {
		entry.Count = 1
	}
	slot := r.at(r.count)
	if r.count == len(r.entries) {
		slot = r.head
		r.head = (r.head + 1) % len(r.entries)
	} else {
		r.count++
	}
	r.entries[slot], r.seqs[slot] = entry, r.next
}

func (r *recentLog) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.entries)
	r.head, r.count = 0, 0
}

func (r *recentLog) size() (count, capacity int, oldest time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := r.now().Add(-r.keep)
	for i := 0; i < r.count; i++ {
		if entry := r.entries[r.at(i)]; entry.At.After(cutoff) {
			return r.count - i, len(r.entries), entry.At
		}
	}
	return 0, len(r.entries), time.Time{}
}

func recentMatches(e trafficlog.Entry, q trafficlog.Query, search string) bool {
	if q.Device != "" && e.DeviceID != q.Device && e.Device != q.Device {
		return false
	}
	if q.Service != "" && e.ServiceID != q.Service || q.Kind != "" && e.Kind != q.Kind {
		return false
	}
	if !q.Since.IsZero() && e.At.Before(q.Since) || !q.Before.IsZero() && !e.At.Before(q.Before) {
		return false
	}
	if search == "" {
		return true
	}
	// The same fields the disk journal indexes for its search.
	for _, field := range []string{e.DeviceName, e.Device, e.Host, e.ServiceID, e.Rule} {
		if strings.Contains(strings.ToLower(field), search) {
			return true
		}
	}
	for _, hop := range e.Route {
		if strings.Contains(strings.ToLower(hop), search) {
			return true
		}
	}
	return e.Exit != nil && (strings.Contains(strings.ToLower(e.Exit.Name), search) || strings.Contains(strings.ToLower(e.Exit.Source), search))
}

// query returns one page, newest first. The cursor is the sequence number of
// the last row of the previous page, so new records never shift a page.
func (r *recentLog) query(q trafficlog.Query) trafficlog.Page {
	page := trafficlog.Page{Events: []trafficlog.Entry{}}
	limit := q.Limit
	if limit < 1 || limit > 200 {
		limit = 50
	}
	below := int64(0)
	if q.Cursor != "" {
		below, _ = strconv.ParseInt(q.Cursor, 10, 64)
		if below < 1 {
			return page
		}
	}
	search := strings.ToLower(strings.TrimSpace(q.Search))
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := r.now().Add(-r.keep)
	last := int64(0)
	for i := r.count - 1; i >= 0; i-- {
		at := r.at(i)
		entry, seq := r.entries[at], r.seqs[at]
		if !entry.At.After(cutoff) {
			break
		}
		if below > 0 && seq >= below || !recentMatches(entry, q, search) {
			continue
		}
		if len(page.Events) == limit {
			page.HasMore = true
			break
		}
		entry.Route = append([]string{}, entry.Route...)
		page.Events = append(page.Events, entry)
		last = seq
	}
	if page.HasMore {
		page.NextCursor = strconv.FormatInt(last, 10)
	}
	return page
}

func (r *recentLog) devices() []trafficlog.Device {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := r.now().Add(-r.keep)
	seen := map[string]int{}
	result := []trafficlog.Device{}
	for i := r.count - 1; i >= 0; i-- {
		entry := r.entries[r.at(i)]
		if !entry.At.After(cutoff) {
			break
		}
		if _, known := seen[entry.DeviceID]; known || entry.DeviceID == "" {
			continue
		}
		seen[entry.DeviceID] = len(result)
		result = append(result, trafficlog.Device{ID: entry.DeviceID, Name: entry.DeviceName, IP: entry.Device, LastSeen: entry.At})
	}
	return result
}

// Site is what one device, or all of them, did with one address: how often,
// and which way the traffic went.
type Site struct {
	Host      string    `json:"host"`
	ServiceID string    `json:"service_id,omitempty"`
	Count     int       `json:"count"`
	VPN       int       `json:"vpn"`
	Direct    int       `json:"direct"`
	Blocked   int       `json:"blocked"`
	Errors    int       `json:"errors"`
	LastAt    time.Time `json:"last_at"`
	Exit      string    `json:"exit,omitempty"`
	Devices   int       `json:"devices"`
}

const maxSites = 300

// sites groups the matching records by address, busiest first.
func (r *recentLog) sites(q trafficlog.Query) []Site {
	search := strings.ToLower(strings.TrimSpace(q.Search))
	r.mu.Lock()
	cutoff := r.now().Add(-r.keep)
	index := map[string]*Site{}
	devices := map[string]map[string]bool{}
	for i := r.count - 1; i >= 0; i-- {
		entry := r.entries[r.at(i)]
		if !entry.At.After(cutoff) {
			break
		}
		if entry.Host == "" || !recentMatches(entry, q, search) {
			continue
		}
		site := index[entry.Host]
		if site == nil {
			site = &Site{Host: entry.Host, ServiceID: entry.ServiceID, LastAt: entry.At}
			index[entry.Host], devices[entry.Host] = site, map[string]bool{}
		}
		times := max(entry.Count, 1)
		site.Count += times
		devices[entry.Host][entry.DeviceID] = true
		switch {
		case entry.Kind == "error":
			site.Errors += times
		case entry.Kind == "kill_switch" || entry.Kind == "quic" || entry.Exit != nil && entry.Exit.Kind == "reject":
			site.Blocked += times
		case entry.Exit != nil && entry.Exit.Kind == "direct":
			site.Direct += times
		case entry.Exit != nil && entry.Exit.Kind == "server":
			site.VPN += times
			if site.Exit == "" {
				site.Exit = entry.Exit.Name
			}
		}
	}
	r.mu.Unlock()
	result := make([]Site, 0, len(index))
	for host, site := range index {
		site.Devices = len(devices[host])
		result = append(result, *site)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].Host < result[j].Host
	})
	if len(result) > maxSites {
		result = result[:maxSites]
	}
	return result
}
