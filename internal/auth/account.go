package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	MinPasswordLength = 8
	// bcrypt reads at most 72 bytes; a longer password would be cut silently.
	MaxPasswordBytes = 72
	recoveryCodes    = 10
)

var (
	ErrWeakPassword = errors.New("пароль должен быть не короче 8 символов и не длиннее 72 байт")
	ErrNoPending    = errors.New("новая привязка приложения не начата или устарела")
	ErrWrongCode    = errors.New("неверный одноразовый код")
)

// ValidPassword is the rule both the first setup and a later change apply.
func ValidPassword(password string) bool {
	return len([]rune(password)) >= MinPasswordLength && len(password) <= MaxPasswordBytes
}

// ChangePassword replaces the password and ends every session: the signing
// secret changes with it, so a token issued earlier stops working.
func (um *UserManager) ChangePassword(password string) error {
	if !ValidPassword(password) {
		return ErrWeakPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	secret, err := generateRandomKey(32)
	if err != nil {
		return err
	}
	um.mu.Lock()
	defer um.mu.Unlock()
	if um.user == nil {
		return os.ErrNotExist
	}
	previous := *um.user
	um.user.PasswordHash, um.user.JWTSecret = string(hash), secret
	if err := um.persistLocked(); err != nil {
		*um.user = previous
		return err
	}
	return nil
}

// EndSessions invalidates every token issued so far, on every device.
func (um *UserManager) EndSessions() error {
	secret, err := generateRandomKey(32)
	if err != nil {
		return err
	}
	um.mu.Lock()
	defer um.mu.Unlock()
	if um.user == nil {
		return os.ErrNotExist
	}
	previous := um.user.JWTSecret
	um.user.JWTSecret = secret
	if err := um.persistLocked(); err != nil {
		um.user.JWTSecret = previous
		return err
	}
	return nil
}

type pendingTOTP struct {
	secret string
	at     time.Time
}

const pendingTOTPLife = 10 * time.Minute

// BeginTOTPChange prepares a secret for a new authenticator. The current one
// keeps working until ConfirmTOTPChange accepts a code from the new one.
func (um *UserManager) BeginTOTPChange() (secret, qr string, err error) {
	um.mu.RLock()
	name := ""
	if um.user != nil {
		name = um.user.Username
	}
	um.mu.RUnlock()
	if name == "" {
		return "", "", os.ErrNotExist
	}
	secret, qr, err = GenerateTOTP(name)
	if err != nil {
		return "", "", err
	}
	um.mu.Lock()
	um.pendingTOTP = &pendingTOTP{secret: secret, at: time.Now()}
	um.mu.Unlock()
	return secret, qr, nil
}

// ConfirmTOTPChange switches to the prepared secret once the new authenticator
// has shown a valid code. The spare codes belong to the old binding and go.
func (um *UserManager) ConfirmTOTPChange(code string) error {
	um.mu.Lock()
	defer um.mu.Unlock()
	if um.user == nil {
		return os.ErrNotExist
	}
	pending := um.pendingTOTP
	if pending == nil || time.Since(pending.at) > pendingTOTPLife {
		um.pendingTOTP = nil
		return ErrNoPending
	}
	step, ok := MatchTOTP(code, pending.secret, time.Now())
	if !ok {
		return ErrWrongCode
	}
	previous := *um.user
	um.user.TOTPSecret, um.user.RecoveryCodes = pending.secret, nil
	if err := um.persistLocked(); err != nil {
		*um.user = previous
		return err
	}
	um.pendingTOTP, um.lastTOTPStep = nil, step
	return nil
}

var recoveryAlphabet = base32.NewEncoding("ABCDEFGHJKLMNPQRSTUVWXYZ23456789").WithPadding(base32.NoPadding)

func normalizeRecoveryCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	code = strings.NewReplacer("-", "", " ", "").Replace(code)
	return code
}

func recoveryHash(code string) string {
	sum := sha256.Sum256([]byte("xkeen-panel-recovery\n" + code))
	return hex.EncodeToString(sum[:])
}

// NewRecoveryCodes replaces the spare codes and returns the new ones. They are
// shown once: only their hashes are kept.
func (um *UserManager) NewRecoveryCodes() ([]string, error) {
	codes := make([]string, 0, recoveryCodes)
	hashes := make([]string, 0, recoveryCodes)
	for len(codes) < recoveryCodes {
		raw := make([]byte, 10)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		// Sixteen characters carry 80 random bits.
		code := recoveryAlphabet.EncodeToString(raw)[:16]
		codes = append(codes, code[:4]+"-"+code[4:8]+"-"+code[8:12]+"-"+code[12:])
		hashes = append(hashes, recoveryHash(code))
	}
	um.mu.Lock()
	defer um.mu.Unlock()
	if um.user == nil {
		return nil, os.ErrNotExist
	}
	previous := um.user.RecoveryCodes
	um.user.RecoveryCodes = hashes
	if err := um.persistLocked(); err != nil {
		um.user.RecoveryCodes = previous
		return nil, err
	}
	return codes, nil
}

// RecoveryCodesLeft tells how many spare codes are still unused.
func (um *UserManager) RecoveryCodesLeft() int {
	um.mu.RLock()
	defer um.mu.RUnlock()
	if um.user == nil {
		return 0
	}
	return len(um.user.RecoveryCodes)
}

// UseRecoveryCode spends a spare code. It is removed before the answer is
// given, so it can not be accepted twice.
func (um *UserManager) UseRecoveryCode(code string) bool {
	code = normalizeRecoveryCode(code)
	if len(code) != 16 {
		return false
	}
	want := recoveryHash(code)
	um.mu.Lock()
	defer um.mu.Unlock()
	if um.user == nil {
		return false
	}
	found := -1
	for i, stored := range um.user.RecoveryCodes {
		if subtle.ConstantTimeCompare([]byte(stored), []byte(want)) == 1 {
			found = i
		}
	}
	if found < 0 {
		return false
	}
	previous := um.user.RecoveryCodes
	kept := make([]string, 0, len(previous)-1)
	kept = append(kept, previous[:found]...)
	kept = append(kept, previous[found+1:]...)
	um.user.RecoveryCodes = kept
	if err := um.persistLocked(); err != nil {
		um.user.RecoveryCodes = previous
		return false
	}
	return true
}

// UseSecondFactor accepts either a code from the authenticator or a spare code.
func (um *UserManager) UseSecondFactor(code string) bool {
	if len(strings.TrimSpace(code)) == 6 {
		return um.UseTOTP(code)
	}
	return um.UseRecoveryCode(code)
}
