package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
	"xkeen-panel/internal/auth"
	"xkeen-panel/internal/models"
)

type accountFixture struct {
	t       *testing.T
	um      *auth.UserManager
	router  http.Handler
	secret  string
	token   string
	address string
}

func newAccountFixture(t *testing.T) *accountFixture {
	t.Helper()
	// The tests confirm with the code of a neighbouring 30-second step, which
	// the panel accepts only while the current step lasts. Started right before
	// the step turns, a test would present a code that is two steps old.
	if left := 30 - time.Now().Unix()%30; left <= 3 {
		time.Sleep(time.Duration(left) * time.Second)
	}
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
	user := um.GetUser()
	token, err := auth.IssueToken(user.Username, user.JWTSecret, true)
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(um))
		NewAccountHandler(um, &models.Config{}).Mount(r)
	})
	return &accountFixture{t: t, um: um, router: router, secret: secret, token: token, address: "10.0.0.2:1"}
}

func (f *accountFixture) call(method, path string, body any) (int, map[string]any) {
	f.t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.RemoteAddr = f.address
	req.Header.Set("Authorization", "Bearer "+f.token)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	var answer map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &answer)
	return rec.Code, answer
}

// Codes are single-use, so each confirmation takes the code of another step.
func (f *accountFixture) code(step int) string {
	f.t.Helper()
	code, err := totp.GenerateCode(f.secret, time.Now().Add(time.Duration(step)*30*time.Second))
	if err != nil {
		f.t.Fatal(err)
	}
	return code
}

func TestPasswordChangeNeedsPasswordAndCode(t *testing.T) {
	f := newAccountFixture(t)
	if status, account := f.call("GET", "/account", nil); status != 200 || account["username"] != "bob" || account["remember"] != true {
		t.Fatalf("account: %d %v", status, account)
	}
	change := func(password, code, next string) (int, map[string]any) {
		return f.call("POST", "/account/password", map[string]string{"current_password": password, "code": code, "new_password": next})
	}
	if status, _ := change("wrong", f.code(-1), "a new long password"); status != http.StatusForbidden {
		t.Fatalf("a wrong current password changed the password: %d", status)
	}
	if status, _ := change("password123", "000000", "a new long password"); status != http.StatusForbidden && f.code(0) != "000000" {
		t.Fatalf("a wrong code changed the password: %d", status)
	}
	if status, _ := change("password123", f.code(-1), "short"); status != http.StatusBadRequest {
		t.Fatalf("a weak password was accepted: %d", status)
	}
	if !f.um.CheckPassword("bob", "password123") {
		t.Fatal("a refused request changed the password")
	}
	old := f.token
	status, answer := change("password123", f.code(0), "a new long password")
	fresh, _ := answer["token"].(string)
	if status != 200 || fresh == "" || fresh == old {
		t.Fatalf("change: %d %v", status, answer)
	}
	if !f.um.CheckPassword("bob", "a new long password") {
		t.Fatal("the password did not change")
	}
	// The session that made the change continues, remembered as before; every other one ended.
	secret := f.um.GetUser().JWTSecret
	if session, err := auth.ReadToken(fresh, secret); err != nil || !session.Remember {
		t.Fatalf("this device was signed out or forgotten: %+v %v", session, err)
	}
	if _, err := auth.ReadToken(old, secret); err == nil {
		t.Fatal("a session opened with the old password is still valid")
	}
	if status, _ := f.call("GET", "/account", nil); status != http.StatusUnauthorized {
		t.Fatalf("the old token still opens the account: %d", status)
	}
}

func TestSignOutEverywhereKeepsThisDevice(t *testing.T) {
	f := newAccountFixture(t)
	old := f.token
	status, answer := f.call("POST", "/account/sessions/end", map[string]string{})
	fresh, _ := answer["token"].(string)
	if status != 200 || fresh == "" {
		t.Fatalf("end sessions: %d %v", status, answer)
	}
	if status, _ := f.call("GET", "/account", nil); status != http.StatusUnauthorized {
		t.Fatalf("an earlier token survived: %d", status)
	}
	f.token = fresh
	if status, _ := f.call("GET", "/account", nil); status != 200 {
		t.Fatalf("this device was signed out: %d", status)
	}
	_ = old
}

func TestAuthenticatorAndSpareCodesOverTheAPI(t *testing.T) {
	f := newAccountFixture(t)
	confirm := func(step int) map[string]string {
		return map[string]string{"current_password": "password123", "code": f.code(step)}
	}
	status, answer := f.call("POST", "/account/recovery-codes", confirm(-1))
	codes, _ := answer["codes"].([]any)
	if status != 200 || len(codes) != 10 {
		t.Fatalf("spare codes: %d %v", status, answer)
	}
	if _, account := f.call("GET", "/account", nil); account["recovery_codes_left"] != float64(10) {
		t.Fatalf("spare codes left: %v", account["recovery_codes_left"])
	}
	// A spare code confirms like a one-time code, once.
	spare := map[string]string{"current_password": "password123", "code": codes[0].(string)}
	if status, _ := f.call("POST", "/account/totp/begin", spare); status != 200 {
		t.Fatalf("a spare code was refused: %d", status)
	}
	if status, _ := f.call("POST", "/account/totp/begin", spare); status != http.StatusForbidden {
		t.Fatalf("a spare code worked twice: %d", status)
	}

	status, begun := f.call("POST", "/account/totp/begin", confirm(0))
	fresh, _ := begun["totp_secret"].(string)
	if status != 200 || fresh == "" || fresh == f.secret || begun["totp_qr"] == "" {
		t.Fatalf("begin: %d %v", status, begun)
	}
	wrong := "000000"
	if current, _ := totp.GenerateCode(fresh, time.Now()); current == wrong {
		wrong = "111111"
	}
	if status, _ := f.call("POST", "/account/totp/confirm", map[string]string{"code": wrong}); status != http.StatusBadRequest {
		t.Fatalf("a wrong code confirmed the new authenticator: %d", status)
	}
	if f.um.GetUser().TOTPSecret != f.secret {
		t.Fatal("the authenticator changed before the new one was confirmed")
	}
	code, _ := totp.GenerateCode(fresh, time.Now())
	if status, _ := f.call("POST", "/account/totp/confirm", map[string]string{"code": code}); status != 200 {
		t.Fatalf("confirm: %d", status)
	}
	if f.um.GetUser().TOTPSecret != fresh || f.um.RecoveryCodesLeft() != 0 {
		t.Fatal("the new authenticator was not saved, or old spare codes remained")
	}
	if status, _ := f.call("POST", "/account/totp/confirm", map[string]string{"code": code}); status != http.StatusConflict {
		t.Fatalf("a finished change could be confirmed again: %d", status)
	}
}

func TestAccountConfirmationsArePaused(t *testing.T) {
	f := newAccountFixture(t)
	for i := 0; i < guardFreeFailures; i++ {
		if status, _ := f.call("POST", "/account/recovery-codes", map[string]string{"current_password": "guess", "code": "000000"}); status != http.StatusForbidden {
			t.Fatalf("attempt %d: %d", i+1, status)
		}
	}
	// Even the right answer waits now: a stolen session can not keep guessing.
	status, _ := f.call("POST", "/account/recovery-codes", map[string]string{"current_password": "password123", "code": f.code(0)})
	if status != http.StatusTooManyRequests {
		t.Fatalf("confirmations were not paused: %d", status)
	}
}

func TestSecureAddressIsReportedAfterABackgroundCheck(t *testing.T) {
	h := NewAuthHandler(auth.NewUserManager(t.TempDir()), &models.Config{})
	status := func() map[string]any {
		rec := httptest.NewRecorder()
		h.HandleAuthStatus(rec, httptest.NewRequest("GET", "/api/auth/status", nil))
		var answer map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &answer)
		return answer
	}
	if _, present := status()["https_url"]; present {
		t.Fatal("an HTTPS address was reported without one being set up")
	}
	checked := make(chan struct{}, 4)
	h.Secure = func(context.Context) string { checked <- struct{}{}; return "https://panel.example.com/" }
	// The first answer does not wait for the check.
	if _, present := status()["https_url"]; present {
		t.Fatal("the answer waited for the check")
	}
	<-checked
	deadline := time.Now().Add(2 * time.Second)
	for status()["https_url"] != "https://panel.example.com/" {
		if time.Now().After(deadline) {
			t.Fatal("the verified address was never reported")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
