package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
	"xkeen-panel/internal/models"

	"golang.org/x/crypto/bcrypt"
)

type UserManager struct {
	dataDir string
	user    *models.User
	mu      sync.RWMutex
	// Holds the setup data until TOTP is confirmed
	pendingSetup *models.User
	// One password check at a time: bcrypt is deliberately slow, and a burst
	// of login attempts must not occupy every core of the router.
	checks chan struct{}
	// The newest one-time code step already accepted. A code is single-use.
	lastTOTPStep int64
	// Set by Load when the main file was unreadable and the copy was used.
	restored bool
	// A new authenticator secret waiting for its first valid code.
	pendingTOTP *pendingTOTP
}

func NewUserManager(dataDir string) *UserManager {
	return &UserManager{dataDir: dataDir, checks: make(chan struct{}, 1)}
}

func (um *UserManager) userFilePath() string {
	return filepath.Join(um.dataDir, "user.json")
}

func (um *UserManager) backupFilePath() string { return um.userFilePath() + ".bak" }

func readUserFile(path string) (*models.User, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var user models.User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}
	if user.Username == "" || user.PasswordHash == "" || user.JWTSecret == "" {
		return nil, errors.New("в файле учётной записи нет обязательных полей")
	}
	return &user, nil
}

// Load reads the stored user. A missing file means the panel is not set up: a
// deliberately removed account must stay removed, so the copy is not consulted.
// A damaged file is replaced from the copy written alongside it.
func (um *UserManager) Load() error {
	um.mu.Lock()
	defer um.mu.Unlock()

	user, err := readUserFile(um.userFilePath())
	if err == nil {
		um.user = user
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	copied, copyErr := readUserFile(um.backupFilePath())
	if copyErr != nil {
		return err
	}
	um.user, um.restored = copied, true
	// Best effort: the copy is already in use even if the rewrite fails.
	_ = um.persistLocked()
	return nil
}

// RestoredFromCopy reports that Load had to use the copy of the account file.
func (um *UserManager) RestoredFromCopy() bool {
	um.mu.RLock()
	defer um.mu.RUnlock()
	return um.restored
}

// SetupRequired reports whether no account exists yet.
func (um *UserManager) SetupRequired() bool {
	um.mu.RLock()
	defer um.mu.RUnlock()
	return um.user == nil
}

// CreatePendingUser builds the account in memory, before TOTP is confirmed.
func (um *UserManager) CreatePendingUser(username, password, totpSecret string) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	jwtSecret, err := generateRandomKey(32)
	if err != nil {
		return err
	}

	um.pendingSetup = &models.User{
		Username:     username,
		PasswordHash: string(hash),
		TOTPSecret:   totpSecret,
		JWTSecret:    jwtSecret,
		CreatedAt:    time.Now(),
	}
	return nil
}

// ConfirmSetup persists the pending account.
func (um *UserManager) ConfirmSetup() error {
	um.mu.Lock()
	defer um.mu.Unlock()

	if um.pendingSetup == nil {
		return os.ErrNotExist
	}

	previous := um.user
	um.user = um.pendingSetup
	if err := um.persistLocked(); err != nil {
		um.user = previous
		return err
	}
	um.pendingSetup = nil
	um.lastTOTPStep = 0
	return nil
}

// GetPendingTOTPSecret returns the TOTP secret of the pending setup.
func (um *UserManager) GetPendingTOTPSecret() string {
	um.mu.RLock()
	defer um.mu.RUnlock()
	if um.pendingSetup == nil {
		return ""
	}
	return um.pendingSetup.TOTPSecret
}

// HasPendingSetup reports whether setup was started but not finished.
func (um *UserManager) HasPendingSetup() bool {
	um.mu.RLock()
	defer um.mu.RUnlock()
	return um.pendingSetup != nil
}

// ErrBusy means another password check is still running.
var ErrBusy = errors.New("проверка пароля занята")

// A well-formed hash to spend the same time on when there is no account or the
// login name is wrong, so the answer does not reveal which part was wrong.
// Computed on first use: `-version` and other short runs never pay for it.
var decoyHash = sync.OnceValue(func() []byte {
	hash, _ := bcrypt.GenerateFromPassword([]byte("xkeen-panel-decoy"), bcrypt.DefaultCost)
	return hash
})

// CheckPassword verifies the account password.
func (um *UserManager) CheckPassword(username, password string) bool {
	ok, err := um.VerifyPassword(context.Background(), username, password)
	return err == nil && ok
}

// VerifyPassword checks the login name and password, one request at a time.
// It returns ErrBusy when ctx ends before its turn comes.
func (um *UserManager) VerifyPassword(ctx context.Context, username, password string) (bool, error) {
	select {
	case um.checks <- struct{}{}:
		defer func() { <-um.checks }()
	case <-ctx.Done():
		return false, ErrBusy
	}
	um.mu.RLock()
	hash, known := decoyHash(), false
	if um.user != nil {
		hash = []byte(um.user.PasswordHash)
		known = subtle.ConstantTimeCompare([]byte(um.user.Username), []byte(username)) == 1
	}
	um.mu.RUnlock()
	// bcrypt rejects passwords longer than 72 bytes; treat them as wrong
	// without telling a long password apart from a short one by timing.
	match := bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
	return match && known, nil
}

// UseTOTP accepts a one-time code once: the same code, or an older one, is
// refused afterwards even while its time window is still open.
func (um *UserManager) UseTOTP(code string) bool {
	um.mu.Lock()
	defer um.mu.Unlock()
	if um.user == nil {
		return false
	}
	step, ok := MatchTOTP(code, um.user.TOTPSecret, time.Now())
	if !ok || step <= um.lastTOTPStep {
		return false
	}
	um.lastTOTPStep = step
	return true
}

// GetUser returns a copy of the account.
func (um *UserManager) GetUser() *models.User {
	um.mu.RLock()
	defer um.mu.RUnlock()
	if um.user == nil {
		return nil
	}
	u := *um.user
	return &u
}

// persistLocked writes the current account to disk. Call with um.mu held.
//
// The file is replaced in one step, so a power cut leaves either the old or
// the new account, never half of one. The copy next to it always holds the same
// account: falling back to it can not bring back an old password.
func (um *UserManager) persistLocked() error {
	if um.user == nil {
		return os.ErrNotExist
	}
	if err := os.MkdirAll(um.dataDir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(um.user, "", "  ")
	if err != nil {
		return err
	}
	if err := replaceFile(um.userFilePath(), data); err != nil {
		return err
	}
	// The account is saved. A failed copy only loses the spare.
	_ = replaceFile(um.backupFilePath(), data)
	return nil
}

func replaceFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".user-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func generateRandomKey(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
