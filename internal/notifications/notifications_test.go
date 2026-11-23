package notifications

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/go-chi/chi/v5"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func fixture(t *testing.T, path string) webpush.Subscription {
	t.Helper()
	key, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return webpush.Subscription{Endpoint: "https://web.push.apple.com/" + path,
		Keys: webpush.Keys{P256dh: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), Auth: base64.RawURLEncoding.EncodeToString(make([]byte, 16))}}
}
func TestValidatedPush(t *testing.T) {
	s := fixture(t, "fixture")
	if !validSubscription(s) {
		t.Fatal("validation of platform subscription")
	}
	for _, endpoint := range []string{
		"https://localhost/fixture", "https://web.push.apple.com.example.org/test", "http://web.push.apple.com/a",
		"https://user@web.push.apple.com/x", "https://web.push.apple.com:8090/x", "https://fcm.googleapis.com/",
	} {
		invalid := s
		invalid.Endpoint = endpoint
		if validSubscription(invalid) {
			t.Errorf("accepted %s", endpoint)
		}
	}
	s.Keys.P256dh = base64.RawURLEncoding.EncodeToString(make([]byte, 65))
	if validSubscription(s) {
		t.Fatal("invalid public key")
	}
}
func TestPreferencesEventsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	m, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	mux := chi.NewRouter()
	m.Mount(mux)
	request := func(method, path string, b any) *httptest.ResponseRecorder {
		var input bytes.Buffer
		if b != nil {
			if e := json.NewEncoder(&input).Encode(b); e != nil {
				t.Fatal(e)
			}
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(method, "/notifications/"+path, &input))
		return w
	}
	endpoint := fixture(t, "first")
	second := fixture(t, "second")
	if w := request("GET", "key", nil); w.Code != 200 || strings.Contains(w.Body.String(), m.state.Private) {
		t.Fatal("public key response")
	}
	register := func(sub webpush.Subscription, p Preferences) {
		if w := request("PUT", "device", map[string]any{"subscription": sub, "preferences": p}); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	register(endpoint, Preferences{Server: true, Update: true, Health: true})
	register(second, Preferences{Health: true})
	id := idFor(endpoint.Endpoint)
	var deliveries []string
	code := 201
	mock := transportFunc(func(r *http.Request) (*http.Response, error) {
		raw, err := io.ReadAll(r.Body)
		if err != nil || len(raw) != 512 || r.Header.Get("Content-Encoding") != "aes128gcm" || !strings.HasPrefix(r.Header.Get("Authorization"), "vapid t=") || bytes.Contains(raw, []byte("fixture")) {
			t.Fatal("expected encrypted, signed web push")
		}
		deliveries = append(deliveries, r.URL.Path)
		return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	})
	m.client = mock
	var s transitions
	start := time.Now()
	m.observe(&s, Snapshot{Route: "first", Checked: true, Connected: true, At: start})
	m.deliver(context.Background())
	if len(deliveries) != 0 {
		t.Fatal("sent initial snapshot as a change")
	}
	m.observe(&s, Snapshot{Route: "first", Checked: true, Connected: false, At: start.Add(time.Minute)})
	if len(m.pending) != 0 {
		t.Fatal("a short outage must not be announced")
	}
	m.observe(&s, Snapshot{Route: "second", Latest: "v1", Checked: true, Connected: false, At: start.Add(3 * time.Minute)})
	if len(m.pending) != 4 {
		t.Fatalf("category selection got %d", len(m.pending))
	}
	m.deliver(context.Background())
	slices.Sort(deliveries)
	if !slices.Equal(deliveries, []string{"/first", "/first", "/first", "/second"}) {
		t.Fatalf("unexpected delivery count: %d", len(deliveries))
	}
	again, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again.state.Private != m.state.Private || again.state.Devices[id].LastVersion != "v1" || again.state.Devices[id].Preferences != m.state.Devices[id].Preferences {
		t.Fatal("reload lost settings")
	}
	var restarted transitions
	again.observe(&restarted, Snapshot{Route: "second", Latest: "v1", Checked: true, Connected: false})
	if len(again.pending) != 0 {
		t.Fatal("duplicate release or stale snapshot notification")
	}
	again.client = mock
	again.observe(&restarted, Snapshot{Route: "second", Latest: "v1", Checked: true, Connected: true})
	code = 503
	again.deliver(context.Background())
	if len(again.pending) != 2 {
		t.Fatal("temporary failure lost pending recovery")
	}
	code = 410
	for key, job := range again.pending {
		job.next = job.next.AddDate(-1, 0, 0)
		again.pending[key] = job
	}
	again.deliver(context.Background())
	if len(again.state.Devices) != 0 || len(again.pending) != 0 {
		t.Fatal("retired device not removed")
	}
}
