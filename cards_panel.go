package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"xkeen-panel/installer"
	"xkeen-panel/internal/api"
	"xkeen-panel/internal/auth"
	"xkeen-panel/internal/cardcontroller"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

// The panel can manage an already running Mihomo without starting an XKeen
// watchdog, migrating the main Xray files, or restarting the router's proxy.
func runCardsPanel(configPath, address string) error {
	host, _, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !(ip.IsLoopback() || ip.IsPrivate()) {
		return errors.New("для панели укажите локальный IP роутера и порт")
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	user := auth.NewUserManager(cfg.DataDir)
	if err := user.Load(); err != nil {
		return err
	}
	if user.SetupRequired() {
		return errors.New("для панели сервисов требуется настроенная учётная запись XKeen Panel")
	}
	sub := xkeen.NewSubscriptionManager(cfg.DataDir)
	if err := sub.Load(); err != nil {
		return err
	}
	if len(sub.GetServers()) == 0 {
		return errors.New("сохранённая подписка панели пуста")
	}
	base := filepath.Join(cfg.DataDir, "service-cards")
	rt := xkeen.Runtime{Core: xkeen.CoreXray, CoreBin: "/opt/sbin/xray", XrayConfDir: filepath.Join(base, "configs")}
	if err := os.MkdirAll(rt.XrayConfDir, 0700); err != nil {
		return err
	}
	assets := filepath.Join(base, "dat")
	if err := os.Symlink("/opt/etc/xray/dat", assets); err != nil && !os.IsExist(err) {
		return err
	}
	if value, err := os.Readlink(assets); err != nil || value != "/opt/etc/xray/dat" {
		return errors.New("неожиданный каталог геоданных панели сервисов")
	}
	mihomoConfig := cfg.MihomoConfig
	if mihomoConfig == "" {
		mihomoConfig = "/opt/etc/mihomo/config.yaml"
	}
	controller := cardcontroller.New(mihomoConfig, base, rt, sub.GetServers)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go maintainCardRoutes(ctx, controller, sub, cfg.SubscriptionRefreshInterval)
	assetsFS, err := fs.Sub(frontendDist, "frontend/dist")
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: address, Handler: cardsHandler(cfg, user, controller, sub, assetsFS, host),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second,
	}
	return server.ListenAndServe()
}

func maintainCardRoutes(ctx context.Context, controller *cardcontroller.Controller, sub *xkeen.SubscriptionManager, refreshSeconds int) {
	refreshAfter := time.Duration(refreshSeconds) * time.Second
	lastRefresh := time.Now()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		if refreshAfter > 0 && time.Since(lastRefresh) >= refreshAfter && sub.CanRefresh() {
			lastRefresh = time.Now()
			if _, err := sub.Refresh(); err != nil {
				log.Print("Не удалось обновить подписку сервиса. Сохранённые назначения остаются в силе.")
			}
		}
		attempt, cancel := context.WithTimeout(ctx, 90*time.Second)
		if err := controller.Reconcile(attempt); err != nil && ctx.Err() == nil {
			log.Print("Маршруты сервисов ожидают готовности локального контроллера.")
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func cardsHandler(cfg *models.Config, user *auth.UserManager, controller *cardcontroller.Controller, sub *xkeen.SubscriptionManager, assets fs.FS, host string) http.Handler {
	r := chi.NewRouter()
	var changes sync.Mutex
	jsonResponse := func(w http.ResponseWriter, code int, value any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(value)
	}
	limiter := api.NewRateLimiter(5, time.Minute)
	login := api.NewAuthHandler(user, limiter, cfg)
	passkey := api.NewWebAuthnHandler(user, limiter, cfg)
	guard := api.RateLimitMiddleware(limiter, cfg.TrustProxyHeaders)
	r.Get("/api/auth/status", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]any{"setup_required": false, "passkey_enabled": user.HasWebAuthnCredentials(), "cards_panel": true})
	})
	r.With(guard).Post("/api/auth/login", login.HandleLogin)
	r.With(guard).Post("/api/auth/login/passkey/begin", passkey.HandleLoginBegin)
	r.With(guard).Post("/api/auth/login/passkey/finish", passkey.HandleLoginFinish)
	r.Group(func(r chi.Router) {
		r.Use(api.AuthMiddleware(user))
		controller.MountExclusions(r, cfg.DataDir)
		r.Post("/api/service-routes/{service}/client", func(w http.ResponseWriter, r *http.Request) {
			changes.Lock()
			defer changes.Unlock()
			access, err := controller.EnableServiceProxy(r.Context(), host, chi.URLParam(r, "service"))
			if err != nil {
				jsonResponse(w, 409, map[string]string{"error": err.Error()})
				return
			}
			jsonResponse(w, 200, access)
		})
		r.Post("/api/subscription/refresh", func(w http.ResponseWriter, r *http.Request) {
			changes.Lock()
			defer changes.Unlock()
			if !sub.CanRefresh() {
				jsonResponse(w, 409, map[string]string{"error": "Источник подписки не поддерживает обновление."})
				return
			}
			servers, err := sub.Refresh()
			if err != nil {
				jsonResponse(w, 502, map[string]string{"error": "Провайдер не вернул подписку. Сохранённый список доступен."})
				return
			}
			if err := controller.Reconcile(r.Context()); err != nil {
				jsonResponse(w, 503, map[string]string{"error": "Список получен. Ядро пока не подтвердило назначения."})
				return
			}
			jsonResponse(w, 200, map[string]int{"count": len(servers)})
		})
		r.Get("/api/service-routes/claude-api-firewall", func(w http.ResponseWriter, r *http.Request) {
			jsonResponse(w, 200, installer.ClaudeFirewallStatus(r.Context()))
		})
		r.Post("/api/service-routes/claude-api-firewall", func(w http.ResponseWriter, r *http.Request) {
			changes.Lock()
			defer changes.Unlock()
			status, err := installer.InstallClaudeFirewall(r.Context())
			if err != nil {
				jsonResponse(w, 409, map[string]string{"error": err.Error()})
				return
			}
			jsonResponse(w, 200, status)
		})
		r.Get("/api/service-routes", func(w http.ResponseWriter, r *http.Request) {
			data, err := controller.View(r.Context())
			if err != nil {
				jsonResponse(w, 503, map[string]string{"error": err.Error()})
				return
			}
			jsonResponse(w, 200, data)
		})
		r.Put("/api/service-routes", func(w http.ResponseWriter, r *http.Request) {
			changes.Lock()
			defer changes.Unlock()
			var choice struct {
				ServiceID string `json:"service_id"`
				TargetID  string `json:"target_id"`
			}
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
			dec.DisallowUnknownFields()
			if dec.Decode(&choice) != nil || dec.Decode(&struct{}{}) != io.EOF || choice.ServiceID == "" {
				jsonResponse(w, 400, map[string]string{"error": "Не удалось прочитать выбор сервиса."})
				return
			}
			data, err := controller.Set(r.Context(), choice.ServiceID, choice.TargetID)
			if err != nil {
				jsonResponse(w, 409, map[string]string{"error": err.Error()})
				return
			}
			jsonResponse(w, 200, data)
		})
	})
	r.Handle("/assets/*", http.FileServer(http.FS(assets)))
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Path) >= 5 && r.URL.Path[:5] == "/api/" {
			http.NotFound(w, r)
			return
		}
		// Serve "/" through FileServer so index.html is returned without the
		// canonical /index.html -> / redirect for SPA deep links.
		r.URL.Path = "/"
		http.FileServer(http.FS(assets)).ServeHTTP(w, r)
	})
	return r
}
