package notifications

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/go-chi/chi/v5"
)

func result(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, code int, err string) {
	result(w, code, map[string]string{"error": err})
}
func read(w http.ResponseWriter, r *http.Request, value any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	if dec.Decode(value) != nil || dec.Decode(&struct{}{}) != io.EOF {
		fail(w, 400, "Некорректный запрос уведомлений")
		return false
	}
	return true
}

type deviceRequest struct {
	ID string `json:"id"`
}

func requestedID(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req deviceRequest
	if !read(w, r, &req) {
		return "", false
	}
	if b, err := hex.DecodeString(req.ID); err != nil || len(b) != 32 {
		fail(w, 400, "Некорректное устройство")
		return "", false
	}
	return req.ID, true
}

func (m *Manager) Mount(r chi.Router) {
	r.Route("/notifications", func(r chi.Router) {
		// Device IDs and endpoint URLs stay out of access logs.
		r.Get("/key", func(w http.ResponseWriter, r *http.Request) {
			key, err := m.publicKey()
			if err != nil {
				fail(w, 503, "Не удалось сохранить ключ Web Push")
				return
			}
			result(w, 200, map[string]string{"key": key})
		})
		r.Post("/status", func(w http.ResponseWriter, r *http.Request) {
			id, ok := requestedID(w, r)
			if !ok {
				return
			}
			m.mu.Lock()
			d, exists := m.state.Devices[id]
			m.mu.Unlock()
			result(w, 200, map[string]any{"enabled": exists, "preferences": d.Preferences})
		})
		r.Put("/device", m.register)
		r.Delete("/device", func(w http.ResponseWriter, r *http.Request) {
			id, ok := requestedID(w, r)
			if !ok {
				return
			}
			m.mu.Lock()
			err := m.removeLocked(id)
			m.mu.Unlock()
			if err != nil {
				fail(w, 500, "Не удалось отключить уведомления")
				return
			}
			result(w, 200, map[string]bool{"enabled": false})
		})
		r.Post("/test", m.test)
	})
}

func (m *Manager) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subscription webpush.Subscription `json:"subscription"`
		Preferences  *Preferences         `json:"preferences"`
	}
	if !read(w, r, &req) {
		return
	}
	if req.Preferences == nil || !validSubscription(req.Subscription) {
		fail(w, 400, "Служба Web Push этого браузера не поддерживается или подписка недействительна")
		return
	}
	id := idFor(req.Subscription.Endpoint)
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.state
	if s.Public == "" {
		fail(w, 409, "Сначала получите ключ уведомлений панели")
		return
	}
	d, exists := s.Devices[id]
	if !exists && len(s.Devices) >= 32 {
		fail(w, 409, "Достигнут лимит устройств с уведомлениями")
		return
	}
	d.Subscription = req.Subscription
	d.Preferences = *req.Preferences
	s.Devices = maps.Clone(s.Devices)
	s.Devices[id] = d
	if err := m.saveLocked(s); err != nil {
		fail(w, 500, "Не удалось сохранить настройки уведомлений")
		return
	}
	for k := range m.pending {
		if k.device == id && !d.Preferences.allows(k.category) {
			delete(m.pending, k)
		}
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
	result(w, 200, map[string]any{"enabled": true, "preferences": d.Preferences})
}
func (m *Manager) test(w http.ResponseWriter, r *http.Request) {
	id, ok := requestedID(w, r)
	if !ok {
		return
	}
	m.mu.Lock()
	d, exists := m.state.Devices[id]
	if !exists {
		m.mu.Unlock()
		fail(w, 404, "Сначала включите уведомления")
		return
	}
	if time.Since(m.lastTest[id]) < 5*time.Second {
		m.mu.Unlock()
		fail(w, 429, "Повторите проверку через несколько секунд")
		return
	}
	m.lastTest[id] = time.Now()
	m.mu.Unlock()
	status := m.send(r.Context(), d.Subscription, message{Kind: "test"})
	if status == 404 || status == 410 {
		m.mu.Lock()
		_ = m.removeLocked(id)
		m.mu.Unlock()
		fail(w, 410, "Подписка браузера истекла. Включите уведомления снова")
		return
	}
	if status < 200 || status >= 300 {
		fail(w, 502, "Служба Web Push не приняла уведомление")
		return
	}
	result(w, 200, map[string]bool{"accepted": true})
}
