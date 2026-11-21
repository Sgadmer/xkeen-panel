package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"xkeen-panel/internal/models"
)

const proofPath = "/api/auth/address-proof"

var domainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type faceIDView struct {
	Available bool   `json:"available"`
	Status    string `json:"status"`
	Label     string `json:"label,omitempty"`
	URL       string `json:"https_url,omitempty"`
	QR        string `json:"qr,omitempty"`
	Message   string `json:"message,omitempty"`
}

// This intent never establishes a new WebAuthn trust anchor by itself. The
// authenticated router configuration supplies the domain; a verified TLS
// request to the LAN listener confirms the mapping reaches this process.
type faceIDIntent struct {
	Label  string `json:"label"`
	Origin string `json:"origin"`
}

type PanelFaceID struct {
	listen      string
	ip          string
	port        int
	path        string
	prepare     func(context.Context, string, string, int, string) (string, error)
	plan        func(context.Context, string) (string, bool, error)
	roots       *x509.CertPool
	key         [32]byte
	mu          sync.Mutex
	lastOrigin  string
	lastChecked time.Time
	lastError   error
}

func hasExplicitWebAuthn(cfg *models.Config) bool {
	return cfg.WebAuthnRPID != "" || len(cfg.WebAuthnOrigins) > 0 || cfg.TrustProxyHeaders
}

func NewPanelFaceID(cfg *models.Config, listen string, devices *DevicesHandler) *PanelFaceID {
	host, port, err := net.SplitHostPort(listen)
	ip, addrErr := netip.ParseAddr(host)
	p, portErr := strconv.Atoi(port)
	if err != nil || addrErr != nil || !ip.IsPrivate() || !ip.Is4() || portErr != nil || p < 1 || p > 65535 || cfg.DataDir == "" || devices == nil {
		return nil
	}
	f := &PanelFaceID{listen: listen, ip: ip.String(), port: p, path: filepath.Join(cfg.DataDir, "face-id-origin.json")}
	f.prepare = func(ctx context.Context, label, ip string, port int, admin string) (string, error) {
		return devices.client().PreparePanelHTTPS(ctx, label, ip, port, admin)
	}
	f.plan = func(ctx context.Context, label string) (string, bool, error) {
		return devices.client().PanelHTTPSPlan(ctx, label)
	}
	if _, err = rand.Read(f.key[:]); err != nil {
		return nil
	}
	// The router installs Entware's CA bundle below /opt, outside Go's
	// standard Linux trust-store search path.
	f.roots, _ = x509.SystemCertPool()
	if f.roots == nil {
		f.roots = x509.NewCertPool()
	}
	for _, path := range []string{"/opt/etc/ssl/certs/ca-certificates.crt", "/opt/etc/ssl/cert.pem"} {
		if pem, err := os.ReadFile(path); err == nil && f.roots.AppendCertsFromPEM(pem) {
			break
		}
	}
	return f
}

func parsePanelOrigin(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("роутер вернул некорректный HTTPS-адрес")
	}
	host := u.Hostname()
	if !strings.Contains(host, ".") || len(host) > 253 || net.ParseIP(host) != nil {
		return nil, errors.New("для ключа входа нужно доменное имя панели")
	}
	for _, label := range strings.Split(host, ".") {
		if !domainLabel.MatchString(label) {
			return nil, errors.New("некорректное доменное имя панели")
		}
	}
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil || p < 1 || p > 65535 {
			return nil, errors.New("некорректный порт HTTPS панели")
		}
	}
	u.Path = ""
	if u.Port() == "443" {
		u.Host = host
	}
	return u, nil
}

func (f *PanelFaceID) readIntent() (faceIDIntent, error) {
	var in faceIDIntent
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return in, nil
	}
	if err != nil || len(data) > 1024 || json.Unmarshal(data, &in) != nil || !domainLabel.MatchString(in.Label) {
		return faceIDIntent{}, errors.New("не удалось прочитать сохранённый адрес панели")
	}
	u, err := parsePanelOrigin(in.Origin)
	if err != nil || u.String() != in.Origin {
		return faceIDIntent{}, errors.New("сохранённый адрес панели некорректен")
	}
	return in, nil
}

func (f *PanelFaceID) writeIntent(in faceIDIntent) error {
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".face-id-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	err = json.NewEncoder(tmp).Encode(in)
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), f.path)
	}
	return err
}

func (f *PanelFaceID) configure(ctx context.Context, label, admin, expected string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	in, err := f.readIntent()
	if err != nil {
		return err
	}
	planned, public, err := f.plan(ctx, label)
	if err != nil {
		return err
	}
	u, err := parsePanelOrigin(planned)
	if err != nil {
		return err
	}
	if u.String() != expected || (in.Origin != "" && in.Origin != expected) {
		return errors.New("HTTPS-адрес изменился. Обновите предварительный просмотр перед применением.")
	}
	if public && admin != "private" {
		return errors.New("Подтвердите ограничение штатной админки роутера домашней сетью.")
	}
	raw, err := f.prepare(ctx, label, f.ip, f.port, admin)
	if err != nil {
		return err
	}
	u, err = parsePanelOrigin(raw)
	if err != nil {
		return err
	}
	if u.String() != expected {
		return errors.New("Фактический адрес отличается от согласованного. Проверьте настройки роутера.")
	}
	if err := f.writeIntent(faceIDIntent{Label: label, Origin: u.String()}); err != nil {
		return errors.New("не удалось сохранить адрес ключей входа на роутере")
	}
	f.lastChecked = time.Time{}
	return nil
}

func (f *PanelFaceID) proof(challenge string) []byte {
	mac := hmac.New(sha256.New, f.key[:])
	mac.Write([]byte(challenge))
	return mac.Sum(nil)
}

func (f *PanelFaceID) AddressProof(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("challenge")
	if len(challenge) != 64 {
		http.NotFound(w, r)
		return
	}
	if _, err := hex.DecodeString(challenge); err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, hex.EncodeToString(f.proof(challenge)))
}

// Dial only the configured router LAN IP, with the published domain used for
// TLS SNI, hostname/certificate verification and HTTP Host. No session tokens
// are sent. A redirect/login page or another router installation fails proof.
func (f *PanelFaceID) probe(ctx context.Context, origin string) error {
	u, err := parsePanelOrigin(origin)
	if err != nil {
		return err
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	tr := http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(f.ip, port))
		},
		TLSClientConfig:   &tls.Config{RootCAs: f.roots, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: &tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return errors.New("не удалось проверить HTTPS-адрес")
	}
	challenge := hex.EncodeToString(nonce[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+proofPath+"?challenge="+challenge, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("Ожидаем доверенный сертификат и доступность HTTPS на роутере.")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65))
	sig, decodeErr := hex.DecodeString(string(raw))
	if resp.StatusCode != http.StatusOK || err != nil || decodeErr != nil || !hmac.Equal(sig, f.proof(challenge)) {
		return errors.New("HTTPS отвечает, но маршрут к этой панели пока не подтверждён.")
	}
	return nil
}

func (f *PanelFaceID) checkLocked(ctx context.Context, origin string) error {
	if f.lastOrigin == origin && time.Since(f.lastChecked) < 5*time.Second {
		return f.lastError
	}
	err := f.probe(ctx, origin)
	if ctx.Err() == nil {
		f.lastOrigin, f.lastChecked, f.lastError = origin, time.Now(), err
	}
	return err
}

func (f *PanelFaceID) verifiedURL(ctx context.Context) (*url.URL, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	in, err := f.readIntent()
	if err != nil {
		return nil, err
	}
	if in.Origin == "" {
		return nil, errors.New("сначала подготовьте HTTPS-адрес в настройках панели")
	}
	if err = f.checkLocked(ctx, in.Origin); err != nil {
		return nil, err
	}
	return parsePanelOrigin(in.Origin)
}

// SecureAddress is the panel's HTTPS address, with the closing slash, once the
// router serves it with a trusted certificate and it reaches this panel. It is
// empty until then.
func (f *PanelFaceID) SecureAddress(ctx context.Context) string {
	address, err := f.verifiedURL(ctx)
	if err != nil {
		return ""
	}
	return address.String() + "/"
}

func (f *PanelFaceID) status(ctx context.Context) faceIDView {
	f.mu.Lock()
	defer f.mu.Unlock()
	view := faceIDView{Available: true, Status: "unconfigured"}
	in, err := f.readIntent()
	if err != nil {
		view.Message = err.Error()
		return view
	}
	if in.Origin == "" {
		return view
	}
	view.Label = in.Label
	view.URL = in.Origin + "/"
	if err = f.checkLocked(ctx, in.Origin); err != nil {
		view.Status = "pending"
		view.Message = err.Error()
		return view
	}
	view.QR, err = addressQR(view.URL)
	if err != nil {
		view.Message = "Не удалось сформировать QR-код."
	}
	view.Status = "ready"
	return view
}
