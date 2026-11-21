package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"xkeen-panel/internal/auth"
	"xkeen-panel/internal/models"
)

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !rl.Allow("1.1.1.1") {
			t.Fatalf("attempt %d must be allowed", i+1)
		}
	}
	if rl.Allow("1.1.1.1") {
		t.Fatal("the 4th attempt must be rejected")
	}

	// A different IP is counted independently
	if !rl.Allow("2.2.2.2") {
		t.Fatal("the first attempt from another IP must be allowed")
	}

	rl.Reset("1.1.1.1")
	if !rl.Allow("1.1.1.1") {
		t.Fatal("after Reset an attempt must be allowed again")
	}
}

func TestRateLimiterWindowExpiry(t *testing.T) {
	rl := NewRateLimiter(2, 50*time.Millisecond)

	if !rl.Allow("9.9.9.9") {
		t.Fatal("the first attempt must be allowed")
	}
	if !rl.Allow("9.9.9.9") {
		t.Fatal("the second attempt must be allowed")
	}
	if rl.Allow("9.9.9.9") {
		t.Fatal("the third attempt must be rejected")
	}

	time.Sleep(70 * time.Millisecond)

	if !rl.Allow("9.9.9.9") {
		t.Fatal("an attempt must be allowed once the window expires")
	}
}

func TestRateLimiterForgetsQuietAddresses(t *testing.T) {
	rl := NewRateLimiter(2, 20*time.Millisecond)
	for i := 0; i < 400; i++ {
		rl.Allow("10.0." + strings.Repeat("1", 1+i%3) + "." + string(rune('a'+i%26)) + string(rune('a'+i/26)))
	}
	time.Sleep(40 * time.Millisecond)
	rl.Allow("fresh")
	if len(rl.attempts) > 2 {
		t.Fatalf("%d addresses are still remembered after they went quiet", len(rl.attempts))
	}
}

func TestClientIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "9.9.9.9:111"
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2")

	// Proxy not trusted: the address of the connection, without its port. A new
	// connection uses a new port and must not look like a new client.
	if got := clientIP(req, false); got != "9.9.9.9" {
		t.Errorf("trustProxy=false: got %q, want the address without a port", got)
	}
	other := httptest.NewRequest(http.MethodGet, "/", nil)
	other.RemoteAddr = "9.9.9.9:54321"
	if clientIP(other, false) != clientIP(req, false) {
		t.Error("two connections of one client are counted as two clients")
	}
	// Proxy trusted: the rightmost hop, the one the proxy appended
	if got := clientIP(req, true); got != "2.2.2.2" {
		t.Errorf("trustProxy=true: got %q, want rightmost XFF", got)
	}
	// Trusted but no XFF: the connection address
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "9.9.9.9:111"
	if got := clientIP(req2, true); got != "9.9.9.9" {
		t.Errorf("trustProxy=true without XFF: got %q", got)
	}
	// Garbage in the header falls back to the connection address
	req2.Header.Set("X-Forwarded-For", "1.1.1.1, not-an-address")
	if got := clientIP(req2, true); got != "9.9.9.9" {
		t.Errorf("malformed XFF: got %q", got)
	}

	// The router's own HTTPS proxy reaches the panel from the router's address.
	// Only then is the header believed without the config switch.
	local := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 3000}
	proxied := httptest.NewRequest(http.MethodGet, "/", nil)
	proxied = proxied.WithContext(context.WithValue(proxied.Context(), http.LocalAddrContextKey, net.Addr(local)))
	proxied.RemoteAddr = "192.168.1.1:40000"
	proxied.Header.Set("X-Forwarded-For", "192.168.1.50")
	if got := clientIP(proxied, false); got != "192.168.1.50" {
		t.Errorf("request forwarded by the router: got %q", got)
	}
	neighbour := httptest.NewRequest(http.MethodGet, "/", nil)
	neighbour = neighbour.WithContext(context.WithValue(neighbour.Context(), http.LocalAddrContextKey, net.Addr(local)))
	neighbour.RemoteAddr = "192.168.1.77:40000"
	neighbour.Header.Set("X-Forwarded-For", "192.168.1.50")
	if got := clientIP(neighbour, false); got != "192.168.1.77" {
		t.Errorf("a device in the home network set its own XFF and was believed: %q", got)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	limiter := NewRateLimiter(1, time.Minute)
	handler := RateLimitMiddleware(limiter, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodGet, "/login", nil)
	req1.RemoteAddr = "5.5.5.5:12345"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", rec1.Code)
	}

	// The same client on a new connection.
	req2 := httptest.NewRequest(http.MethodGet, "/login", nil)
	req2.RemoteAddr = "5.5.5.5:23456"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: got %d, want 429", rec2.Code)
	}
}

func TestLoginGuardPausesGrow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	guard := NewLoginGuard()
	guard.now = func() time.Time { return now }
	var paused []string
	guard.OnPause = func(address string, wait time.Duration) { paused = append(paused, address+" "+wait.String()) }

	for i := 1; i < guardFreeFailures; i++ {
		if wait := guard.Fail("10.0.0.5"); wait != 0 || guard.Wait("10.0.0.5") != 0 {
			t.Fatalf("mistake %d already caused a pause", i)
		}
	}
	if wait := guard.Fail("10.0.0.5"); wait != time.Minute || guard.Wait("10.0.0.5") != time.Minute {
		t.Fatalf("the fifth failure paused for %s", wait)
	}
	if guard.Wait("10.0.0.6") != 0 {
		t.Fatal("another address was paused too")
	}
	now = now.Add(time.Minute)
	if guard.Wait("10.0.0.5") != 0 {
		t.Fatal("the pause did not end")
	}
	if wait := guard.Fail("10.0.0.5"); wait != 5*time.Minute {
		t.Fatalf("the next failure paused for %s, want 5m", wait)
	}
	now = now.Add(5 * time.Minute)
	if wait := guard.Fail("10.0.0.5"); wait != 30*time.Minute {
		t.Fatalf("the next failure paused for %s, want 30m", wait)
	}
	now = now.Add(30 * time.Minute)
	if wait := guard.Fail("10.0.0.5"); wait != 30*time.Minute {
		t.Fatalf("the pause grew past its cap: %s", wait)
	}
	if len(paused) != 4 || paused[0] != "10.0.0.5 1m0s" {
		t.Fatalf("pauses were not reported: %v", paused)
	}

	guard.Success("10.0.0.5")
	if guard.Wait("10.0.0.5") != 0 || guard.Fail("10.0.0.5") != 0 {
		t.Fatal("a successful sign-in did not clear the failures")
	}

	// An hour without failures is forgotten.
	for i := 0; i < guardFreeFailures-1; i++ {
		guard.Fail("10.0.0.9")
	}
	now = now.Add(guardForgetAfter + time.Minute)
	if wait := guard.Fail("10.0.0.9"); wait != 0 {
		t.Fatalf("old failures were still counted: %s", wait)
	}
}

func TestLoginGuardSharedPause(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	guard := NewLoginGuard()
	guard.now = func() time.Time { return now }
	shared := 0
	guard.OnPause = func(address string, wait time.Duration) {
		if address == guardSharedAddress {
			shared++
		}
	}
	// One failure each from many addresses: no single address reaches its limit.
	for i := 0; i < guardSharedLimit-1; i++ {
		guard.Fail("10.1.0." + string(rune('0'+i%10)) + string(rune('a'+i)))
	}
	if guard.Wait("192.168.1.2") != 0 {
		t.Fatal("the shared pause started too early")
	}
	guard.Fail("10.9.9.9")
	if guard.Wait("192.168.1.2") != guardSharedPause || shared != 1 {
		t.Fatalf("failures spread over addresses were not paused: %s, %d", guard.Wait("192.168.1.2"), shared)
	}
	now = now.Add(guardSharedPause)
	if guard.Wait("192.168.1.2") != 0 {
		t.Fatal("the shared pause did not end")
	}
}

func TestLimitBody(t *testing.T) {
	read := func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
	handler := LimitBody(64, "/api/sources")(http.HandlerFunc(read))
	call := func(path, body string, length bool) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if !length {
			req.ContentLength = -1
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	small := `{"a":"b"}`
	large := `{"a":"` + strings.Repeat("x", 200) + `"}`
	if got := call("/api/panel/settings", small, true); got != http.StatusOK {
		t.Fatalf("an ordinary request: %d", got)
	}
	if got := call("/api/panel/settings", large, true); got != http.StatusRequestEntityTooLarge {
		t.Fatalf("a large request with a declared size: %d", got)
	}
	if got := call("/api/panel/settings", large, false); got != http.StatusBadRequest {
		t.Fatalf("a large request without a declared size was read: %d", got)
	}
	if got := call("/api/sources/import", large, true); got != http.StatusOK {
		t.Fatalf("a route with its own larger limit was cut: %d", got)
	}
}

func newConfirmedUserManager(t *testing.T) *auth.UserManager {
	t.Helper()
	um := auth.NewUserManager(t.TempDir())
	if err := um.CreatePendingUser("bob", "password123", "SECRET"); err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	if err := um.ConfirmSetup(); err != nil {
		t.Fatalf("ConfirmSetup: %v", err)
	}
	return um
}

func TestAuthMiddleware(t *testing.T) {
	um := newConfirmedUserManager(t)
	user := um.GetUser()
	if user == nil {
		t.Fatal("want a configured user")
	}
	token, err := auth.GenerateToken(user.Username, user.JWTSecret)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	handler := AuthMiddleware(um)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		authHeader string
		query      string
		wantCode   int
	}{
		{"no token", "", "", http.StatusUnauthorized},
		{"valid Bearer", "Bearer " + token, "", http.StatusOK},
		{"token in query param", "", "?token=" + token, http.StatusOK},
		{"invalid token", "Bearer garbage", "", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/status"+tt.query, nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantCode {
				t.Fatalf("got code %d, want %d", rec.Code, tt.wantCode)
			}
		})
	}
}

func loginUser(t *testing.T) (*AuthHandler, string) {
	t.Helper()
	secret, _, err := auth.GenerateTOTP("bob")
	if err != nil {
		t.Fatal(err)
	}
	um := auth.NewUserManager(t.TempDir())
	if err := um.CreatePendingUser("bob", "password123", secret); err != nil {
		t.Fatal(err)
	}
	if err := um.ConfirmSetup(); err != nil {
		t.Fatal(err)
	}
	return NewAuthHandler(um, &models.Config{}), secret
}

func login(h *AuthHandler, address string, body any) (int, map[string]any) {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(raw))
	req.RemoteAddr = address
	rec := httptest.NewRecorder()
	h.HandleLogin(rec, req)
	var answer map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &answer)
	return rec.Code, answer
}

func TestLoginGivesOneAnswerForAnyMistake(t *testing.T) {
	h, secret := loginUser(t)
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wrongCode := "000000"
	if wrongCode == code {
		wrongCode = "111111"
	}
	mistakes := []models.LoginRequest{
		{Username: "bob", Password: "wrong-password", TOTPCode: code},
		{Username: "bob", Password: "password123", TOTPCode: wrongCode},
		{Username: "alice", Password: "password123", TOTPCode: code},
		{Username: "bob", Password: "password123"},
	}
	for i, request := range mistakes {
		status, answer := login(h, "10.0.0."+string(rune('1'+i))+":5000", request)
		if status != http.StatusUnauthorized || answer["error"] != loginRefused {
			t.Fatalf("mistake %d: %d %v — the answer tells which part was wrong", i, status, answer)
		}
	}
	// A code typed next to a wrong password was not spent.
	status, answer := login(h, "10.0.0.9:5000", models.LoginRequest{Username: "bob", Password: "password123", TOTPCode: code})
	if status != http.StatusOK || answer["token"] == "" {
		t.Fatalf("the correct sign-in was refused: %d %v", status, answer)
	}
	// The same code a second time is refused: it is single-use.
	if status, _ := login(h, "10.0.0.9:5001", models.LoginRequest{Username: "bob", Password: "password123", TOTPCode: code}); status != http.StatusUnauthorized {
		t.Fatalf("a one-time code was accepted twice: %d", status)
	}
}

func TestLoginPausesAnAddressAcrossConnections(t *testing.T) {
	h, _ := loginUser(t)
	// Every attempt arrives on a new connection, from a new port.
	for i := 0; i < guardFreeFailures; i++ {
		port := 40000 + i
		status, _ := login(h, "10.0.0.7:"+itoaTest(port), models.LoginRequest{Username: "bob", Password: "guess", TOTPCode: "000000"})
		if status != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i+1, status)
		}
	}
	status, _ := login(h, "10.0.0.7:49999", models.LoginRequest{Username: "bob", Password: "guess", TOTPCode: "000000"})
	if status != http.StatusTooManyRequests {
		t.Fatalf("the sixth attempt from a new port was not paused: %d", status)
	}
	// The owner on another device is not affected.
	if status, _ := login(h, "10.0.0.8:1000", models.LoginRequest{Username: "bob", Password: "guess", TOTPCode: "000000"}); status != http.StatusUnauthorized {
		t.Fatalf("another address was paused as well: %d", status)
	}
}

func TestLoginRememberAndRefresh(t *testing.T) {
	h, secret := loginUser(t)
	code, _ := totp.GenerateCode(secret, time.Now())
	status, answer := login(h, "10.0.0.2:1", models.LoginRequest{Username: "bob", Password: "password123", TOTPCode: code, Remember: true})
	token, _ := answer["token"].(string)
	if status != http.StatusOK || token == "" {
		t.Fatalf("sign-in: %d %v", status, answer)
	}
	user := h.userManager.GetUser()
	session, err := auth.ReadToken(token, user.JWTSecret)
	if err != nil || !session.Remember {
		t.Fatalf("the device was not remembered: %+v %v", session, err)
	}
	refresh := func(token string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, "/api/session/refresh", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.HandleRefresh(rec, req)
		var answer map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &answer)
		return rec.Code, answer
	}
	// A fresh token is left alone.
	if status, answer := refresh(token); status != http.StatusOK || answer["token"] != nil {
		t.Fatalf("a fresh session was reissued: %d %v", status, answer)
	}
	// A session that was not marked "remember" is never extended.
	plain, _ := auth.GenerateToken(user.Username, user.JWTSecret)
	if status, answer := refresh(plain); status != http.StatusOK || answer["token"] != nil || answer["remember"] != false {
		t.Fatalf("an ordinary session was extended: %d %v", status, answer)
	}
	if status, _ := refresh("garbage"); status != http.StatusUnauthorized {
		t.Fatalf("a bad token was accepted: %d", status)
	}
}

func itoaTest(n int) string {
	return string([]byte{byte('0' + n/10000%10), byte('0' + n/1000%10), byte('0' + n/100%10), byte('0' + n/10%10), byte('0' + n%10)})
}
