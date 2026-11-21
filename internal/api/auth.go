package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
	"xkeen-panel/internal/auth"
	"xkeen-panel/internal/models"
)

type AuthHandler struct {
	userManager *auth.UserManager
	cfg         *models.Config
	// Guard pauses password sign-in after repeated failures.
	Guard *LoginGuard
	// Secure, when set, checks the panel's HTTPS address and returns it, or ""
	// while that address is not set up or does not answer.
	Secure func(context.Context) string

	secure struct {
		sync.Mutex
		url  string
		at   time.Time
		busy bool
	}
}

// CheckSecureAddress schedules the first check, so that the first visitor
// after a start already gets the address. The check goes through the router
// back to this panel, which must be listening by then.
func (h *AuthHandler) CheckSecureAddress() {
	time.AfterFunc(5*time.Second, func() { h.secureURL() })
}

// secureURL is the HTTPS address a browser on the plain address should move
// to. The check dials the router, so it runs in the background and this
// request answers with what the last check found. That is a hint: the browser
// tries the address itself before it leaves the plain one.
func (h *AuthHandler) secureURL() string {
	if h.Secure == nil {
		return ""
	}
	h.secure.Lock()
	defer h.secure.Unlock()
	age := time.Since(h.secure.at)
	if age > 20*time.Second && !h.secure.busy {
		h.secure.busy = true
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			found := h.Secure(ctx)
			cancel()
			h.secure.Lock()
			h.secure.url, h.secure.at, h.secure.busy = found, time.Now(), false
			h.secure.Unlock()
		}()
	}
	if age > 24*time.Hour {
		return ""
	}
	return h.secure.url
}

func NewAuthHandler(um *auth.UserManager, cfg *models.Config) *AuthHandler {
	return &AuthHandler{userManager: um, cfg: cfg, Guard: NewLoginGuard()}
}

// One answer for a wrong name, password or code: telling them apart would let
// the password be guessed first and the code afterwards.
const loginRefused = "неверный логин, пароль или одноразовый код"

// HandleAuthStatus — GET /api/auth/status
func (h *AuthHandler) HandleAuthStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"setup_required":  h.userManager.SetupRequired(),
		"passkey_enabled": h.userManager.HasWebAuthnCredentials(),
	}
	if address := h.secureURL(); address != "" {
		status["https_url"] = address
	}
	writeJSON(w, http.StatusOK, status)
}

// HandleSetup — POST /api/auth/setup
func (h *AuthHandler) HandleSetup(w http.ResponseWriter, r *http.Request) {
	if !h.userManager.SetupRequired() {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "пользователь уже настроен",
		})
		return
	}

	var req models.SetupRequest
	if err := boundedRead(w, r, 4096, func() error { return json.NewDecoder(r.Body).Decode(&req) }); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "неверный формат запроса"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" || len(req.Username) > 64 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "логин и пароль обязательны"})
		return
	}

	if !auth.ValidPassword(req.Password) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": auth.ErrWeakPassword.Error()})
		return
	}

	// Generate the TOTP secret
	secret, qrBase64, err := auth.GenerateTOTP(req.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ошибка генерации TOTP"})
		return
	}

	// Create the pending account
	if err := h.userManager.CreatePendingUser(req.Username, req.Password, secret); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ошибка создания пользователя"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"totp_secret": secret,
		"totp_qr":     qrBase64,
	})
}

// HandleSetupConfirm — POST /api/auth/setup/confirm
func (h *AuthHandler) HandleSetupConfirm(w http.ResponseWriter, r *http.Request) {
	if !h.userManager.HasPendingSetup() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "setup не начат"})
		return
	}

	var req models.SetupConfirmRequest
	if err := boundedRead(w, r, 1024, func() error { return json.NewDecoder(r.Body).Decode(&req) }); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "неверный формат запроса"})
		return
	}

	secret := h.userManager.GetPendingTOTPSecret()
	if !auth.ValidateTOTP(req.Code, secret) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "неверный одноразовый код"})
		return
	}

	if err := h.userManager.ConfirmSetup(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ошибка сохранения пользователя"})
		return
	}

	user := h.userManager.GetUser()
	token, err := auth.GenerateToken(user.Username, user.JWTSecret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ошибка генерации токена"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// HandleLogin — POST /api/auth/login
func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	address := clientIP(r, h.cfg.TrustProxyHeaders)
	if wait := h.Guard.Wait(address); wait > 0 {
		tooManyAttempts(w, wait)
		return
	}

	var req models.LoginRequest
	if err := boundedRead(w, r, 4096, func() error { return json.NewDecoder(r.Body).Decode(&req) }); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "неверный формат запроса"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	passwordOK, err := h.userManager.VerifyPassword(ctx, req.Username, req.Password)
	if err != nil {
		// Another sign-in is being checked. This is not a wrong attempt.
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "сейчас проверяется другой вход, повторите через несколько секунд"})
		return
	}
	// The code is looked at only after the password: a code typed next to a
	// wrong password must not be spent.
	if !passwordOK || !h.userManager.UseSecondFactor(req.TOTPCode) {
		h.Guard.Fail(address)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": loginRefused})
		return
	}

	user := h.userManager.GetUser()
	token, err := auth.IssueToken(user.Username, user.JWTSecret, req.Remember)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ошибка генерации токена"})
		return
	}

	h.Guard.Success(address)
	writeJSON(w, http.StatusOK, map[string]interface{}{"token": token, "recovery_codes_left": h.userManager.RecoveryCodesLeft()})
}

func bearerToken(r *http.Request) string {
	parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}
	return ""
}

// HandleRefresh — POST /api/auth/refresh. A remembered device keeps its
// session while it is in use: a token older than half a day is exchanged for a
// fresh one. A session that was not marked "remember" simply runs out.
func (h *AuthHandler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	user := h.userManager.GetUser()
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "пользователь не настроен"})
		return
	}
	session, err := auth.ReadToken(bearerToken(r), user.JWTSecret)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "невалидный или просроченный токен"})
		return
	}
	if !session.Remember || time.Since(session.IssuedAt) < 12*time.Hour {
		writeJSON(w, http.StatusOK, map[string]interface{}{"remember": session.Remember})
		return
	}
	token, err := auth.IssueToken(user.Username, user.JWTSecret, true)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ошибка генерации токена"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"token": token, "remember": true})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
