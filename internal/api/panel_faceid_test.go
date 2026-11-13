package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xkeen-panel/internal/models"
)

func TestFaceIDPlanAndAuthenticatedPreparation(t *testing.T) {
	dir := t.TempDir()
	cfg := &models.Config{DataDir: dir}
	const origin = "https://panel.fixture.example:8443"
	var prepared bool
	f := &PanelFaceID{
		listen: "192.168.1.1:3000", ip: "192.168.1.1", port: 3000,
		path: filepath.Join(dir, "origin.json"),
		plan: func(context.Context, string) (string, bool, error) { return origin, true, nil },
		prepare: func(_ context.Context, label, ip string, port int, admin string) (string, error) {
			if label != "fixture" || ip != "192.168.1.1" || port != 3000 || admin != "private" {
				return "", errors.New("нужно подтвердить ограничения штатной панели")
			}
			prepared = true
			return origin, nil
		},
	}
	h := &Handlers{config: cfg, FaceID: f}
	req := httptest.NewRequest("GET", "http://untrusted.example/api/access/face-id/plan?label=fixture", nil)
	req.Header.Set("X-Forwarded-Host", "spoof.example")
	w := httptest.NewRecorder()
	h.HandlePlanFaceID(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), origin) || !strings.Contains(w.Body.String(), `"router_admin_public":true`) || prepared {
		t.Fatalf("plan %d %s", w.Code, w.Body)
	}
	ask := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://spoof.example/api/access/face-id/prepare", strings.NewReader(body))
		record := httptest.NewRecorder()
		h.HandlePrepareFaceID(record, r)
		return record
	}
	if r := ask(`{"label":"bad/label","admin_access":"private"}`); r.Code != 400 {
		t.Fatal(r.Body)
	}
	if r := ask(`{"label":"fixture","admin_access":"public"}`); r.Code != 400 {
		t.Fatal(r.Body)
	}
	if r := ask(`{"label":"fixture","expected_url":"https://panel.fixture.example:8443"}`); r.Code != 409 || prepared {
		t.Fatal(r.Body)
	}
	if r := ask(`{"label":"fixture","admin_access":"private","expected_url":"https://wrong.example"}`); r.Code != 409 || prepared {
		t.Fatal(r.Body)
	}
	// Cancel the request after provisioning. The GET proof must never
	// attempt to reach an actual LAN host when run on a developer machine.
	var cancel context.CancelFunc
	ctx, cancel := context.WithCancel(context.Background())
	realPrepare := f.prepare
	f.prepare = func(ctx context.Context, label, ip string, port int, admin string) (string, error) {
		defer cancel()
		return realPrepare(ctx, label, ip, port, admin)
	}
	request := httptest.NewRequest("POST", "http://spoof.example/api/access/face-id/prepare", strings.NewReader(`{"label":"fixture","admin_access":"private","expected_url":"https://panel.fixture.example:8443/"}`)).WithContext(ctx)
	request.Header.Set("X-Forwarded-Host", "spoof.example")
	w = httptest.NewRecorder()
	h.HandlePrepareFaceID(w, request)
	if !prepared || w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"pending"`) || strings.Contains(w.Body.String(), "spoof.example") {
		t.Fatal(w.Body)
	}
	raw, err := os.ReadFile(f.path)
	if err != nil || !strings.Contains(string(raw), origin) {
		t.Fatal(err, string(raw))
	}
}

func TestFaceIDRequiresTrustedTLSAndOwnPanel(t *testing.T) {
	const host = "panel.fixture.example"
	cfg := &models.Config{DataDir: t.TempDir()}
	f := &PanelFaceID{ip: "127.0.0.1", path: filepath.Join(cfg.DataDir, "origin.json"), roots: x509.NewCertPool()}
	rand.Read(f.key[:])
	mux := http.NewServeMux()
	mux.HandleFunc(proofPath, f.AddressProof)
	server := httptest.NewUnstartedServer(mux)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	origin := "https://" + net.JoinHostPort(host, port)
	if err := f.writeIntent(faceIDIntent{Label: "fixture", Origin: origin}); err != nil {
		t.Fatal(err)
	}
	if v := f.status(context.Background()); v.Status != "pending" || v.QR != "" {
		t.Fatalf("%+v", v)
	}
	leaf, _ := x509.ParseCertificate(der)
	f.roots.AddCert(leaf)
	f.lastChecked = time.Time{}
	if v := f.status(context.Background()); v.Status != "ready" || !strings.HasPrefix(v.QR, "data:image/png") {
		t.Fatalf("%+v", v)
	}
	if err := f.probe(context.Background(), "https://"+net.JoinHostPort("other.fixture.example", port)); err == nil {
		t.Fatal("accepted wrong certificate name")
	}
	fresh := &PanelFaceID{ip: "127.0.0.1", roots: f.roots, path: f.path}
	rand.Read(fresh.key[:])
	if err := fresh.probe(context.Background(), origin); err == nil {
		t.Fatal("other instance passed proof")
	}
	if a, err := fresh.verifiedURL(context.Background()); err == nil || a != nil {
		t.Fatal("unverified origin used")
	}
	req := httptest.NewRequest("POST", "http://forged.example/api/account/passkey/register/begin", nil)
	req.Header.Set("X-Forwarded-Host", "forged.example")
	wa := NewWebAuthnHandler(nil, nil, cfg)
	wa.FaceID = f
	actual, err := wa.webAuthn(req)
	if err != nil || actual.Config.RPID != host || len(actual.Config.RPOrigins) != 1 || actual.Config.RPOrigins[0] != origin {
		t.Fatalf("%v, %+v", err, actual)
	}
	w := httptest.NewRecorder()
	f.AddressProof(w, httptest.NewRequest("GET", proofPath+"?challenge=short", nil))
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestFaceIDRejectsInvalidInputsAndExplicitConfigWins(t *testing.T) {
	for _, s := range []string{"http://panel.example", "https://panel.example/path", "https://u@panel.example", "https://panel.example?q=x", "https://127.0.0.1", "https://panel.example:99999", "https://a..example", "https://panel.example/#x"} {
		if _, err := parsePanelOrigin(s); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	cfg := &models.Config{DataDir: t.TempDir(), WebAuthnRPID: "pinned.example", WebAuthnOrigins: []string{"https://pinned.example"}}
	h := NewWebAuthnHandler(nil, nil, cfg)
	h.FaceID = &PanelFaceID{}
	actual, err := h.webAuthn(httptest.NewRequest("POST", "http://spoof.example/", nil))
	if err != nil || actual.Config.RPID != "pinned.example" {
		t.Fatal("explicit setting lost")
	}
	handlers := &Handlers{config: cfg, FaceID: h.FaceID}
	w := httptest.NewRecorder()
	handlers.HandlePrepareFaceID(w, httptest.NewRequest("POST", "/api/access/face-id/prepare", strings.NewReader(`{"label":"other"}`)))
	var result map[string]string
	if w.Code != 409 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result["error"] == "" {
		t.Fatal(w.Code, w.Body)
	}
}
