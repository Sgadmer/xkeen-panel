// Package trafficlog is an optional, bounded journal of routing metadata.
// Importing it opens no files and starts no goroutines. Open is explicit.
package trafficlog

import (
	"context"
	"errors"
	"time"
)

const (
	DefaultMaxEvents       = 200000
	DefaultMaxDeviceEvents = 50000
	DefaultMaxBytes        = int64(256 << 20)
	MaxEntryBytes          = 4096
)

type Limits struct {
	Retention       time.Duration `json:"-"`
	MaxEvents       int           `json:"max_events"`
	MaxDeviceEvents int           `json:"max_device_events"`
	MaxBytes        int64         `json:"max_bytes"`
}

func DefaultLimits() Limits {
	return Limits{24 * time.Hour, DefaultMaxEvents, DefaultMaxDeviceEvents, DefaultMaxBytes}
}

func (l Limits) Validate() error {
	if l.Retention <= 0 || l.Retention > 24*time.Hour || l.MaxEvents < 1 || l.MaxEvents > 1000000 || l.MaxDeviceEvents < 1 || l.MaxDeviceEvents > l.MaxEvents || l.MaxBytes < 4<<20 || l.MaxBytes > 2<<30 {
		return errors.New("недопустимые ограничения истории соединений")
	}
	return nil
}

type Exit struct {
	Kind    string `json:"kind"`
	Name    string `json:"name,omitempty"`
	Country string `json:"country,omitempty"`
	Source  string `json:"source,omitempty"`
}

type Entry struct {
	ID         string    `json:"id"`
	At         time.Time `json:"at"`
	Kind       string    `json:"kind"`
	DeviceID   string    `json:"device_id"`
	Device     string    `json:"device"`
	DeviceName string    `json:"device_name,omitempty"`
	ServiceID  string    `json:"service_id,omitempty"`
	Host       string    `json:"host,omitempty"`
	Port       string    `json:"port,omitempty"`
	Network    string    `json:"network,omitempty"`
	Route      []string  `json:"route"`
	Rule       string    `json:"rule,omitempty"`
	Exit       *Exit     `json:"exit,omitempty"`
	Count      int       `json:"count"`
}

type Options struct {
	Limits Limits
	// Validate must verify that path is on the intended mounted writable disk.
	// It is called before mkdir/Open and before every write transaction.
	Validate func(path string) error
	// Now is only needed for deterministic expiry tests.
	Now func() time.Time
	// Zero values select a 1024-entry queue and a two-second write interval.
	QueueSize     int
	FlushInterval time.Duration
}

type Status struct {
	Running          bool       `json:"running"`
	StorageAvailable bool       `json:"storage_available"`
	Events           int64      `json:"events"`
	Bytes            int64      `json:"bytes"`
	Dropped          uint64     `json:"dropped"`
	Evicted          uint64     `json:"evicted"`
	Expired          uint64     `json:"expired"`
	OldestAt         *time.Time `json:"oldest_at,omitempty"`
	LatestAt         *time.Time `json:"latest_at,omitempty"`
	Error            string     `json:"error,omitempty"`
	RetentionHours   int        `json:"retention_hours"`
	MaxEvents        int        `json:"max_events"`
	MaxDeviceEvents  int        `json:"max_device_events"`
	MaxBytes         int64      `json:"max_bytes"`
	QueueCapacity    int        `json:"queue_capacity"`
	Queued           int        `json:"queued"`
}

type Query struct {
	Device  string
	Service string
	Kind    string
	Search  string
	Cursor  string
	Limit   int
	// Optional time bounds: records at or after Since, and before Before.
	Since  time.Time
	Before time.Time
}

type Device struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	IP       string    `json:"ip"`
	LastSeen time.Time `json:"last_seen"`
}

type Page struct {
	Events     []Entry `json:"events"`
	NextCursor string  `json:"next_cursor,omitempty"`
	HasMore    bool    `json:"has_more"`
	Status     Status  `json:"status"`
}

// Open initializes an explicit disk journal. Disabled installations must never
// call Open; they need no SQLite connection, buffers or background writer.
func Open(ctx context.Context, path string, options Options) (*Store, error) {
	return openStore(ctx, path, options)
}
