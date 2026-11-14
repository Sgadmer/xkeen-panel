// Package notifications delivers opt-in system notifications to browser push services.
package notifications

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
)

type Preferences struct {
	Server bool `json:"server"`
	Update bool `json:"update"`
	Health bool `json:"health"`
}

type device struct {
	Subscription webpush.Subscription `json:"subscription"`
	Preferences  Preferences          `json:"preferences"`
	LastVersion  string               `json:"last_version,omitempty"`
	LastHealth   string               `json:"last_health,omitempty"`
}

type state struct {
	Public  string            `json:"public"`
	Private string            `json:"private"`
	Devices map[string]device `json:"devices"`
}

type Manager struct {
	mu       sync.Mutex
	file     string
	state    state
	client   webpush.HTTPClient
	pending  map[deliveryKey]delivery
	lastTest map[string]time.Time
	wake     chan struct{}
}

func New(dir string) (*Manager, error) {
	m := &Manager{file: filepath.Join(dir, "web-push.json"), client: pushClient(), wake: make(chan struct{}, 1),
		pending: make(map[deliveryKey]delivery), lastTest: make(map[string]time.Time)}
	raw, err := os.ReadFile(m.file)
	if errors.Is(err, os.ErrNotExist) {
		m.state.Devices = make(map[string]device)
		return m, nil
	}
	if err != nil {
		return nil, errors.New("не удалось прочитать настройки уведомлений")
	}
	if json.Unmarshal(raw, &m.state) != nil || !validState(m.state) {
		return nil, errors.New("повреждены настройки уведомлений")
	}
	return m, nil
}

func validState(s state) bool {
	key, err := base64.RawURLEncoding.DecodeString(s.Private)
	if err != nil {
		return false
	}
	priv, err := ecdh.P256().NewPrivateKey(key)
	if err != nil || base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()) != s.Public || s.Devices == nil || len(s.Devices) > 32 {
		return false
	}
	for id, d := range s.Devices {
		if id != idFor(d.Subscription.Endpoint) || !validSubscription(d.Subscription) {
			return false
		}
	}
	return true
}

func (m *Manager) saveLocked(s state) error {
	f, err := os.CreateTemp(filepath.Dir(m.file), ".web-push-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = json.NewEncoder(f).Encode(s); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), m.file); err != nil {
		return err
	}
	m.state = s
	return nil
}

func (m *Manager) publicKey() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Public != "" {
		return m.state.Public, nil
	}
	s := m.state
	var err error
	s.Private, s.Public, err = webpush.GenerateVAPIDKeys()
	if err == nil {
		err = m.saveLocked(s)
	}
	return s.Public, err
}

func idFor(endpoint string) string {
	sum := sha256.Sum256([]byte(endpoint))
	return hex.EncodeToString(sum[:])
}

func validSubscription(s webpush.Subscription) bool {
	if len(s.Endpoint) > 4096 {
		return false
	}
	u, err := url.Parse(s.Endpoint)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" && u.Port() != "443" || u.Path == "" || u.Path == "/" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host != "fcm.googleapis.com" && host != "updates.push.services.mozilla.com" && host != "web.push.apple.com" && !strings.HasSuffix(host, ".push.apple.com") && !strings.HasSuffix(host, ".notify.windows.com") {
		return false
	}
	auth, err := base64.RawURLEncoding.DecodeString(s.Keys.Auth)
	if err != nil || len(auth) != 16 {
		return false
	}
	key, err := base64.RawURLEncoding.DecodeString(s.Keys.P256dh)
	if err != nil {
		return false
	}
	_, err = ecdh.P256().NewPublicKey(key)
	return err == nil
}

func pushClient() *http.Client {
	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	for _, p := range []string{"/opt/etc/ssl/certs/ca-certificates.crt", "/opt/etc/ssl/cert.pem"} {
		if pem, err := os.ReadFile(p); err == nil && roots.AppendCertsFromPEM(pem) {
			break
		}
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true,
		IdleConnTimeout: 30 * time.Second, MaxIdleConns: 4, DialContext: dialPush}
	return &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func dialPush(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return nil, errors.New("invalid push service")
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	// Dial the validated IP directly, so a second DNS lookup cannot change the destination.
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || cgnat.Contains(ip) {
			continue
		}
		conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, errors.New("push service unreachable")
}
