package notifications

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
)

type Snapshot struct {
	Route     string
	Checked   bool
	Connected bool
	Latest    string
}

type message struct {
	Kind    string `json:"kind"`
	Version string `json:"version,omitempty"`
}

func (n message) category() string {
	if n.Kind == "offline" || n.Kind == "online" {
		return "health"
	}
	return n.Kind
}
func (p Preferences) allows(category string) bool {
	switch category {
	case "server":
		return p.Server
	case "update":
		return p.Update
	case "health":
		return p.Health
	}
	return false
}

type deliveryKey struct{ device, category string }
type delivery struct {
	msg      message
	next     time.Time
	attempts int
}
type transitions struct {
	route  string
	health string
}

func (s *transitions) changes(now Snapshot) []message {
	var out []message
	if now.Route != "" {
		if s.route != "" && now.Route != s.route {
			out = append(out, message{Kind: "server"})
		}
		s.route = now.Route
	}
	if now.Checked {
		kind := "offline"
		if now.Connected {
			kind = "online"
		}
		// A startup sample establishes a baseline. Send the first outage,
		// and wait for a real transition before reporting a recovery.
		if kind != s.health && (s.health != "" || kind == "offline") {
			out = append(out, message{Kind: kind})
		}
		s.health = kind
	}
	return out
}

// Route and release checks use the same controller and measurements as the panel.
// No periodic HTTP probe is added to user traffic.
func (m *Manager) Run(ctx context.Context, snapshot func(context.Context) Snapshot) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	var observed transitions
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-ticker.C:
		}
		m.mu.Lock()
		active := len(m.state.Devices) > 0
		m.mu.Unlock()
		if !active {
			observed = transitions{}
			continue
		}
		now := snapshot(ctx)
		m.observe(&observed, now)
		m.deliver(ctx)
	}
}

func (m *Manager) observe(s *transitions, now Snapshot) {
	messages := s.changes(now)
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, d := range m.state.Devices {
		for _, msg := range messages {
			if d.Preferences.allows(msg.category()) {
				if msg.category() == "health" && d.LastHealth == msg.Kind {
					// A transient outage may have recovered before delivery.
					delete(m.pending, deliveryKey{id, "health"})
					continue
				}
				m.pending[deliveryKey{id, msg.category()}] = delivery{msg: msg}
			}
		}
		if now.Checked && d.Preferences.Health && d.LastHealth != "" && d.LastHealth != s.health {
			key := deliveryKey{id, "health"}
			if m.pending[key].msg.Kind != s.health {
				m.pending[key] = delivery{msg: message{Kind: s.health}}
			}
		}
		key := deliveryKey{id, "update"}
		if !d.Preferences.Update || now.Latest == "" || now.Latest == d.LastVersion {
			delete(m.pending, key)
			continue
		}
		if m.pending[key].msg.Version != now.Latest {
			m.pending[key] = delivery{msg: message{Kind: "update", Version: now.Latest}}
		}
	}
}

func (m *Manager) deliver(ctx context.Context) {
	m.mu.Lock()
	jobs := maps.Clone(m.pending)
	m.mu.Unlock()
	for key, job := range jobs {
		if ctx.Err() != nil {
			return
		}
		m.mu.Lock()
		d, ok := m.state.Devices[key.device]
		current := m.pending[key]
		m.mu.Unlock()
		if !ok || current != job || !d.Preferences.allows(key.category) || time.Now().Before(job.next) {
			continue
		}
		status := m.send(ctx, d.Subscription, job.msg)
		if ctx.Err() != nil {
			return
		}
		m.mu.Lock()
		if m.pending[key] == job {
			switch {
			case status == http.StatusGone || status == http.StatusNotFound:
				_ = m.removeLocked(key.device)
			case status >= 200 && status < 300:
				if job.msg.Kind == "update" || key.category == "health" {
					// Preserve a preference changed while the request was in flight.
					s := m.state
					d = s.Devices[key.device]
					if key.category == "health" {
						d.LastHealth = job.msg.Kind
					} else {
						d.LastVersion = job.msg.Version
					}
					s.Devices = maps.Clone(s.Devices)
					s.Devices[key.device] = d
					if err := m.saveLocked(s); err != nil {
						m.mu.Unlock()
						continue
					}
				}
				delete(m.pending, key)
			default:
				// A disconnected router cannot send until uplink service returns.
				// Keep the newest event per category and retry with bounded backoff.
				job.attempts++
				job.next = time.Now().Add(time.Duration(1<<min(job.attempts, 6)) * 15 * time.Second)
				m.pending[key] = job
			}
		}
		m.mu.Unlock()
	}
}

func (m *Manager) send(ctx context.Context, sub webpush.Subscription, msg message) int {
	// Do not expose subscription URLs, selected locations, device addresses or account data.
	raw, err := json.Marshal(msg)
	if err != nil || !validSubscription(sub) {
		return 0
	}
	m.mu.Lock()
	priv, pub := m.state.Private, m.state.Public
	m.mu.Unlock()
	resp, err := webpush.SendNotificationWithContext(ctx, raw, &sub, &webpush.Options{
		HTTPClient: m.client, Subscriber: "https://github.com/Sgadmer/xkeen-panel", VAPIDPublicKey: pub,
		VAPIDPrivateKey: priv, TTL: 3600, RecordSize: 512,
	})
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 1024)
	return resp.StatusCode
}

func (m *Manager) removeLocked(id string) error {
	s := m.state
	if _, exists := s.Devices[id]; !exists {
		return nil
	}
	s.Devices = maps.Clone(s.Devices)
	delete(s.Devices, id)
	if err := m.saveLocked(s); err != nil {
		return err
	}
	for k := range m.pending {
		if k.device == id {
			delete(m.pending, k)
		}
	}
	delete(m.lastTest, id)
	return nil
}
