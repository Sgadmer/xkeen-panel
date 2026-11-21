package api

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"xkeen-panel/internal/auth"
)

type contextKey string

const usernameKey contextKey = "username"

// AuthMiddleware validates the JWT from the Authorization header.
func AuthMiddleware(userManager *auth.UserManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")

			// Fall back to the token query param: EventSource cannot send headers
			if header == "" {
				if t := r.URL.Query().Get("token"); t != "" {
					header = "Bearer " + t
				}
			}

			if header == "" {
				http.Error(w, `{"error":"отсутствует токен авторизации"}`, http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(header, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, `{"error":"неверный формат токена"}`, http.StatusUnauthorized)
				return
			}

			user := userManager.GetUser()
			if user == nil {
				http.Error(w, `{"error":"пользователь не настроен"}`, http.StatusUnauthorized)
				return
			}

			username, err := auth.ValidateToken(parts[1], user.JWTSecret)
			if err != nil {
				http.Error(w, `{"error":"невалидный или просроченный токен"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), usernameKey, username)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// LimitBody caps the request body of every API call. Handlers that expect more
// (a pasted subscription) are listed in larger and apply their own limit.
func LimitBody(limit int64, larger ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, prefix := range larger {
				if strings.HasPrefix(r.URL.Path, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}
			if r.ContentLength > limit {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				w.Write([]byte(`{"error":"слишком большой запрос"}`))
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
}

// boundedRead gives a client that is not signed in a short time to send its
// small request, so a connection that trickles bytes can not be held open.
func boundedRead(w http.ResponseWriter, r *http.Request, limit int64, read func() error) error {
	control := http.NewResponseController(w)
	_ = control.SetReadDeadline(time.Now().Add(10 * time.Second))
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	err := read()
	_ = control.SetReadDeadline(time.Time{})
	return err
}

// clientIP names the client for attempt limits: an address without the port,
// because every new connection comes from a new port.
//
// X-Forwarded-For is honoured with trust_proxy_headers, and for requests that
// arrive from the router itself: its own HTTPS proxy is the only program there
// that forwards browser requests to the panel. The rightmost hop is taken, the
// one that proxy appended.
func clientIP(r *http.Request, trustProxy bool) string {
	remote := hostOnly(r.RemoteAddr)
	if trustProxy || fromThisRouter(r, remote) {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			parts := strings.Split(forwarded, ",")
			if ip, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				return ip.Unmap().String()
			}
		}
	}
	return remote
}

func hostOnly(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String()
	}
	return host
}

func fromThisRouter(r *http.Request, remote string) bool {
	ip, err := netip.ParseAddr(remote)
	if err != nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return ok && hostOnly(local.String()) == remote
}

// RateLimiter caps how often one address may call a route at all.
type RateLimiter struct {
	mu          sync.Mutex
	attempts    map[string][]time.Time
	maxAttempts int
	window      time.Duration
}

func NewRateLimiter(maxAttempts int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		attempts:    make(map[string][]time.Time),
		maxAttempts: maxAttempts,
		window:      window,
	}
}

// Allow reports whether a request from this address may proceed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Addresses that went quiet are forgotten, so the table can not grow
	// with every address that ever tried.
	if len(rl.attempts) > 256 {
		for key, times := range rl.attempts {
			if len(times) == 0 || !times[len(times)-1].After(cutoff) {
				delete(rl.attempts, key)
			}
		}
	}

	var recent []time.Time
	for _, t := range rl.attempts[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= rl.maxAttempts {
		rl.attempts[ip] = recent
		return false
	}
	rl.attempts[ip] = append(recent, now)
	return true
}

// Reset clears the counter for an address after a successful login.
func (rl *RateLimiter) Reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, ip)
}

// RateLimitMiddleware applies the rate limiter to a route.
func RateLimitMiddleware(limiter *RateLimiter, trustProxy bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow(clientIP(r, trustProxy)) {
				tooManyAttempts(w, time.Minute)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func tooManyAttempts(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Content-Type", "application/json")
	if seconds := int(wait.Round(time.Second) / time.Second); seconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
	}
	w.WriteHeader(http.StatusTooManyRequests)
	w.Write([]byte(`{"error":"слишком много попыток, попробуйте позже"}`))
}

// LoginGuard pauses sign-in after repeated failures. It counts failures only:
// the owner who signs in correctly never meets it.
//
// Each address gets a few free mistakes, then growing pauses. A second, shared
// counter covers an attacker who changes addresses: enough failures from
// anywhere pause the guarded way in for everyone, while the other way in
// (password or passkey, each has its own guard) stays open.
type LoginGuard struct {
	mu      sync.Mutex
	entries map[string]*guardEntry
	shared  []time.Time
	paused  time.Time
	now     func() time.Time
	// Called outside the lock when an address or the shared counter is paused.
	OnPause func(address string, wait time.Duration)
}

type guardEntry struct {
	failures int
	last     time.Time
	until    time.Time
}

const (
	guardFreeFailures  = 5
	guardForgetAfter   = time.Hour
	guardSharedLimit   = 30
	guardSharedWindow  = 10 * time.Minute
	guardSharedPause   = 10 * time.Minute
	guardMaxAddresses  = 1024
	guardSharedAddress = "*"
)

var guardPauses = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute}

func NewLoginGuard() *LoginGuard {
	return &LoginGuard{entries: map[string]*guardEntry{}, now: time.Now}
}

// Wait is how long this address still has to wait; zero means it may try.
func (g *LoginGuard) Wait(address string) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	wait := g.paused.Sub(now)
	if entry := g.entries[address]; entry != nil && entry.until.Sub(now) > wait {
		wait = entry.until.Sub(now)
	}
	if wait < 0 {
		return 0
	}
	return wait
}

// Fail records a failed attempt and returns the pause it caused, if any.
func (g *LoginGuard) Fail(address string) time.Duration {
	g.mu.Lock()
	now := g.now()
	for key, entry := range g.entries {
		if now.Sub(entry.last) > guardForgetAfter && !entry.until.After(now) {
			delete(g.entries, key)
		}
	}
	entry := g.entries[address]
	if entry == nil {
		if len(g.entries) >= guardMaxAddresses {
			// Too many addresses to remember each one: the shared counter
			// below still slows all of them down.
			entry = &guardEntry{}
		} else {
			entry = &guardEntry{}
			g.entries[address] = entry
		}
	}
	entry.failures++
	entry.last = now
	var wait time.Duration
	if over := entry.failures - guardFreeFailures; over >= 0 {
		wait = guardPauses[min(over, len(guardPauses)-1)]
		entry.until = now.Add(wait)
	}

	recent := g.shared[:0]
	for _, at := range g.shared {
		if now.Sub(at) < guardSharedWindow {
			recent = append(recent, at)
		}
	}
	g.shared = append(recent, now)
	sharedPause := false
	if len(g.shared) >= guardSharedLimit {
		g.paused, g.shared, sharedPause = now.Add(guardSharedPause), nil, true
	}
	notify := g.OnPause
	g.mu.Unlock()

	if notify != nil {
		if sharedPause {
			notify(guardSharedAddress, guardSharedPause)
		} else if wait > 0 {
			notify(address, wait)
		}
	}
	if sharedPause && guardSharedPause > wait {
		return guardSharedPause
	}
	return wait
}

// Success forgets the failures of an address that signed in.
func (g *LoginGuard) Success(address string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.entries, address)
}
