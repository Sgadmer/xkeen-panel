package auth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func userWithAuthenticator(t *testing.T, dir string) (*UserManager, string) {
	t.Helper()
	secret, _, err := GenerateTOTP("bob")
	if err != nil {
		t.Fatal(err)
	}
	um := NewUserManager(dir)
	if err := um.CreatePendingUser("bob", "password123", secret); err != nil {
		t.Fatal(err)
	}
	if err := um.ConfirmSetup(); err != nil {
		t.Fatal(err)
	}
	return um, secret
}

func currentCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestOneTimeCodeIsAcceptedOnce(t *testing.T) {
	um, secret := userWithAuthenticator(t, t.TempDir())
	code := currentCode(t, secret)
	if um.UseTOTP("000000") && code != "000000" {
		t.Fatal("a wrong code was accepted")
	}
	if !um.UseTOTP(code) {
		t.Fatal("the current code was refused")
	}
	if um.UseTOTP(code) {
		t.Fatal("the same code was accepted twice")
	}
	// An older step must not work either once a newer one was used.
	older, err := totp.GenerateCode(secret, time.Now().Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if um.UseTOTP(older) {
		t.Fatal("a code older than the one already used was accepted")
	}
}

func TestMatchTOTPRejectsMalformedCodes(t *testing.T) {
	secret, _, err := GenerateTOTP("bob")
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"", "12345", "1234567", "12a456", " 12345"} {
		if _, ok := MatchTOTP(code, secret, time.Now()); ok {
			t.Fatalf("malformed code %q was accepted", code)
		}
	}
	if _, ok := MatchTOTP("123456", "", time.Now()); ok {
		t.Fatal("a code was accepted without a secret")
	}
}

func TestAccountFileSurvivesDamage(t *testing.T) {
	dir := t.TempDir()
	newConfirmedUserIn(t, dir)
	main, spare := filepath.Join(dir, "user.json"), filepath.Join(dir, "user.json.bak")
	saved, err := os.ReadFile(main)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(spare)
	if err != nil || string(copied) != string(saved) {
		t.Fatalf("the copy does not hold the same account: %v", err)
	}

	// A file cut short by a power failure.
	if err := os.WriteFile(main, saved[:len(saved)/2], 0600); err != nil {
		t.Fatal(err)
	}
	restored := NewUserManager(dir)
	if err := restored.Load(); err != nil {
		t.Fatalf("a damaged account file stopped the panel: %v", err)
	}
	if restored.SetupRequired() || !restored.RestoredFromCopy() || !restored.CheckPassword("bob", "password123") {
		t.Fatal("the account was not taken from the copy")
	}
	if repaired, err := os.ReadFile(main); err != nil || string(repaired) != string(saved) {
		t.Fatalf("the damaged file was not rewritten: %v", err)
	}

	// Both unreadable: refuse to start rather than open a fresh setup to anyone.
	for _, path := range []string{main, spare} {
		if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := NewUserManager(dir).Load(); err == nil {
		t.Fatal("an unreadable account with no usable copy was accepted")
	}
}

func TestRemovedAccountStaysRemoved(t *testing.T) {
	dir := t.TempDir()
	newConfirmedUserIn(t, dir)
	// Deleting user.json is how access is reset over SSH. The copy must not undo it.
	if err := os.Remove(filepath.Join(dir, "user.json")); err != nil {
		t.Fatal(err)
	}
	um := NewUserManager(dir)
	if err := um.Load(); err != nil {
		t.Fatal(err)
	}
	if !um.SetupRequired() {
		t.Fatal("the copy brought a removed account back")
	}
}

func TestPasswordChangeEndsSessions(t *testing.T) {
	um := newConfirmedUser(t)
	before := um.GetUser()
	token, err := GenerateToken(before.Username, before.JWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	for _, weak := range []string{"short", string(make([]byte, 80))} {
		if err := um.ChangePassword(weak); err != ErrWeakPassword {
			t.Fatalf("password of %d bytes: %v", len(weak), err)
		}
	}
	if err := um.ChangePassword("a new long password"); err != nil {
		t.Fatal(err)
	}
	if um.CheckPassword("bob", "password123") || !um.CheckPassword("bob", "a new long password") {
		t.Fatal("the password did not change")
	}
	if _, err := ValidateToken(token, um.GetUser().JWTSecret); err == nil {
		t.Fatal("a session opened before the password change is still valid")
	}

	// The change is on disk, in the main file and in the copy.
	reloaded := NewUserManager(um.dataDir)
	if err := reloaded.Load(); err != nil || !reloaded.CheckPassword("bob", "a new long password") {
		t.Fatalf("the new password was not saved: %v", err)
	}

	after := um.GetUser()
	token, _ = GenerateToken(after.Username, after.JWTSecret)
	if err := um.EndSessions(); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateToken(token, um.GetUser().JWTSecret); err == nil {
		t.Fatal("ending the sessions left a token valid")
	}
}

func TestAuthenticatorCanBeReplaced(t *testing.T) {
	um, old := userWithAuthenticator(t, t.TempDir())
	if _, err := um.NewRecoveryCodes(); err != nil {
		t.Fatal(err)
	}
	if err := um.ConfirmTOTPChange("123456"); err != ErrNoPending {
		t.Fatalf("confirmation without a prepared secret: %v", err)
	}
	fresh, qr, err := um.BeginTOTPChange()
	if err != nil || fresh == "" || fresh == old || qr == "" {
		t.Fatalf("no new secret: %v", err)
	}
	// Until the new app proves itself, the old one keeps working.
	if !um.UseTOTP(currentCode(t, old)) {
		t.Fatal("the old authenticator stopped working before the change was confirmed")
	}
	wrong := "000000"
	if wrong == currentCode(t, fresh) {
		wrong = "111111"
	}
	if err := um.ConfirmTOTPChange(wrong); err != ErrWrongCode {
		t.Fatalf("a wrong code confirmed the change: %v", err)
	}
	code := currentCode(t, fresh)
	if err := um.ConfirmTOTPChange(code); err != nil {
		t.Fatal(err)
	}
	if um.GetUser().TOTPSecret != fresh || um.RecoveryCodesLeft() != 0 {
		t.Fatal("the new secret was not stored or the old spare codes remained")
	}
	if um.UseTOTP(code) {
		t.Fatal("the confirming code could be used again to sign in")
	}
	if um.UseTOTP(currentCode(t, old)) && currentCode(t, old) != code {
		t.Fatal("the old authenticator still works")
	}
}

func TestSpareCodesWorkOnce(t *testing.T) {
	um := newConfirmedUser(t)
	codes, err := um.NewRecoveryCodes()
	if err != nil || len(codes) != 10 || um.RecoveryCodesLeft() != 10 {
		t.Fatalf("spare codes: %d %v", len(codes), err)
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if len(code) != 19 || seen[code] {
			t.Fatalf("unexpected or repeated code %q", code)
		}
		seen[code] = true
	}
	if um.UseSecondFactor("not-a-real-code-00") {
		t.Fatal("an unknown spare code was accepted")
	}
	if !um.UseSecondFactor(codes[0]) || um.UseSecondFactor(codes[0]) {
		t.Fatal("a spare code must work exactly once")
	}
	// Typed in lower case, without the dashes and with spaces around it.
	typed := " " + strings.ToLower(strings.ReplaceAll(codes[3], "-", "")) + " "
	if !um.UseRecoveryCode(typed) {
		t.Fatal("a spare code typed without dashes was refused")
	}
	if um.RecoveryCodesLeft() != 8 {
		t.Fatalf("%d spare codes left, want 8", um.RecoveryCodesLeft())
	}
	// Only hashes are stored.
	for _, stored := range um.GetUser().RecoveryCodes {
		if seen[stored] {
			t.Fatal("a spare code is stored in the clear")
		}
	}
	// A new set replaces the old one.
	if _, err := um.NewRecoveryCodes(); err != nil || um.UseRecoveryCode(codes[5]) {
		t.Fatalf("an old spare code survived a new set: %v", err)
	}
}

func TestPasswordChecksRunOneAtATime(t *testing.T) {
	um := newConfirmedUser(t)
	um.checks <- struct{}{} // a check is in progress
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if ok, err := um.VerifyPassword(ctx, "bob", "password123"); err != ErrBusy || ok {
		t.Fatalf("a second check did not wait its turn: %v %v", ok, err)
	}
	<-um.checks
	if ok, err := um.VerifyPassword(context.Background(), "bob", "password123"); err != nil || !ok {
		t.Fatalf("the check did not run once free: %v %v", ok, err)
	}
	// With no account at all the answer is simply "no".
	empty := NewUserManager(t.TempDir())
	if ok, err := empty.VerifyPassword(context.Background(), "bob", "password123"); err != nil || ok {
		t.Fatalf("a password was accepted without an account: %v %v", ok, err)
	}
}
