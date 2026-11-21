package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/internal/auth"
	"xkeen-panel/internal/models"
)

// AccountHandler changes how the owner signs in. Every change of a secret asks
// for the current password and a one-time code again: an unlocked phone or a
// tab left open must not be enough to take the panel over.
type AccountHandler struct {
	userManager *auth.UserManager
	cfg         *models.Config
	// Guard pauses confirmations after repeated wrong passwords or codes.
	Guard *LoginGuard
	Log   func(format string, args ...interface{})
}

func NewAccountHandler(um *auth.UserManager, cfg *models.Config) *AccountHandler {
	return &AccountHandler{userManager: um, cfg: cfg, Guard: NewLoginGuard()}
}

type confirmation struct {
	Password string `json:"current_password"`
	Code     string `json:"code"`
}

func (h *AccountHandler) log(format string, args ...interface{}) {
	if h.Log != nil {
		h.Log(format, args...)
	}
}

func readAccount(w http.ResponseWriter, r *http.Request, into interface{}) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if dec.Decode(into) != nil || dec.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "неверный формат запроса"})
		return false
	}
	return true
}

// confirmed checks the current password and a one-time (or spare) code.
func (h *AccountHandler) confirmed(w http.ResponseWriter, r *http.Request, c confirmation) bool {
	address := clientIP(r, h.cfg.TrustProxyHeaders)
	if wait := h.Guard.Wait(address); wait > 0 {
		tooManyAttempts(w, wait)
		return false
	}
	user := h.userManager.GetUser()
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "пользователь не настроен"})
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	passwordOK, err := h.userManager.VerifyPassword(ctx, user.Username, c.Password)
	if err != nil {
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "сейчас проверяется другой вход, повторите через несколько секунд"})
		return false
	}
	if !passwordOK || !h.userManager.UseSecondFactor(c.Code) {
		h.Guard.Fail(address)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "неверный текущий пароль или одноразовый код"})
		return false
	}
	h.Guard.Success(address)
	return true
}

// freshToken keeps this device signed in after every session was ended.
func (h *AccountHandler) freshToken(r *http.Request, previousSecret string) (string, error) {
	remember := false
	if session, err := auth.ReadToken(bearerToken(r), previousSecret); err == nil {
		remember = session.Remember
	}
	user := h.userManager.GetUser()
	if user == nil {
		return "", errors.New("пользователь не настроен")
	}
	return auth.IssueToken(user.Username, user.JWTSecret, remember)
}

// Mount belongs inside the authenticated API group.
func (h *AccountHandler) Mount(r chi.Router) {
	r.Get("/account", func(w http.ResponseWriter, r *http.Request) {
		user := h.userManager.GetUser()
		if user == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "пользователь не настроен"})
			return
		}
		remember := false
		if session, err := auth.ReadToken(bearerToken(r), user.JWTSecret); err == nil {
			remember = session.Remember
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"username":            user.Username,
			"recovery_codes_left": h.userManager.RecoveryCodesLeft(),
			"passkeys":            len(user.Credentials),
			"remember":            remember,
		})
	})

	r.Post("/account/password", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			confirmation
			NewPassword string `json:"new_password"`
		}
		if !readAccount(w, r, &req) {
			return
		}
		if !auth.ValidPassword(req.NewPassword) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": auth.ErrWeakPassword.Error()})
			return
		}
		if !h.confirmed(w, r, req.confirmation) {
			return
		}
		previous := h.userManager.GetUser().JWTSecret
		if err := h.userManager.ChangePassword(req.NewPassword); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось сохранить новый пароль; прежний пароль действует"})
			return
		}
		token, err := h.freshToken(r, previous)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "пароль изменён; войдите заново"})
			return
		}
		h.log("[SECURITY] Пароль панели изменён, все прежние входы завершены")
		writeJSON(w, http.StatusOK, map[string]string{"token": token})
	})

	// Sign out everywhere. It only ends sessions, so it asks for nothing more.
	r.Post("/account/sessions/end", func(w http.ResponseWriter, r *http.Request) {
		user := h.userManager.GetUser()
		if user == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "пользователь не настроен"})
			return
		}
		previous := user.JWTSecret
		if err := h.userManager.EndSessions(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось завершить входы"})
			return
		}
		token, err := h.freshToken(r, previous)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "входы завершены; войдите заново"})
			return
		}
		h.log("[SECURITY] Входы на всех устройствах завершены")
		writeJSON(w, http.StatusOK, map[string]string{"token": token})
	})

	r.Post("/account/totp/begin", func(w http.ResponseWriter, r *http.Request) {
		var req confirmation
		if !readAccount(w, r, &req) || !h.confirmed(w, r, req) {
			return
		}
		secret, qr, err := h.userManager.BeginTOTPChange()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось подготовить новую привязку"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"totp_secret": secret, "totp_qr": qr})
	})

	r.Post("/account/totp/confirm", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code string `json:"code"`
		}
		if !readAccount(w, r, &req) {
			return
		}
		address := clientIP(r, h.cfg.TrustProxyHeaders)
		if wait := h.Guard.Wait(address); wait > 0 {
			tooManyAttempts(w, wait)
			return
		}
		switch err := h.userManager.ConfirmTOTPChange(req.Code); {
		case errors.Is(err, auth.ErrWrongCode):
			h.Guard.Fail(address)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "код из нового приложения не подошёл; прежняя привязка действует"})
		case errors.Is(err, auth.ErrNoPending):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "новая привязка не начата или устарела; начните заново"})
		case err != nil:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось сохранить новую привязку; прежняя действует"})
		default:
			h.log("[SECURITY] Приложение-аутентификатор привязано заново; запасные коды сброшены")
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "recovery_codes_left": 0})
		}
	})

	r.Post("/account/recovery-codes", func(w http.ResponseWriter, r *http.Request) {
		var req confirmation
		if !readAccount(w, r, &req) || !h.confirmed(w, r, req) {
			return
		}
		codes, err := h.userManager.NewRecoveryCodes()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось создать запасные коды"})
			return
		}
		h.log("[SECURITY] Созданы новые запасные коды входа")
		writeJSON(w, http.StatusOK, map[string]interface{}{"codes": codes})
	})
}
