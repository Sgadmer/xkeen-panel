package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"time"
	"xkeen-panel/internal/api"
	"xkeen-panel/internal/auth"
	"xkeen-panel/internal/cardcontroller"
	"xkeen-panel/internal/keenetic"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/monitor"
	"xkeen-panel/internal/notifications"
	"xkeen-panel/internal/sse"
	"xkeen-panel/internal/trafficjournal"
	"xkeen-panel/internal/updater"
	"xkeen-panel/internal/xkeen"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	History       *trafficjournal.Manager
	Notifications *notifications.Manager
	Lifetime      context.Context
	Cards         *cardcontroller.Controller
	CardsHost     string
	CardsListen   string
	config        *models.Config
	userManager   *auth.UserManager
	subscription  *xkeen.SubscriptionManager
	watchdog      *monitor.Watchdog
	detector      *xkeen.Detector
	pool          *xkeen.PoolStore
	sites         *xkeen.SiteManager
	eventBus      *sse.EventBus
	updater       *updater.Updater
	settings      *api.PanelSettingsHandler
	frontendFS    fs.FS
}

func New(cfg *models.Config, um *auth.UserManager, sub *xkeen.SubscriptionManager, wd *monitor.Watchdog, det *xkeen.Detector, pool *xkeen.PoolStore, sites *xkeen.SiteManager, bus *sse.EventBus, upd *updater.Updater, settings *api.PanelSettingsHandler, frontendFS fs.FS) *Server {
	return &Server{
		config:       cfg,
		userManager:  um,
		subscription: sub,
		watchdog:     wd,
		detector:     det,
		pool:         pool,
		sites:        sites,
		eventBus:     bus,
		updater:      upd,
		settings:     settings,
		frontendFS:   frontendFS,
	}
}

// EventSource authenticates using a query token. Log only the request path.
type pathLogFormatter struct{ middleware.DefaultLogFormatter }

func (f *pathLogFormatter) NewLogEntry(r *http.Request) middleware.LogEntry {
	logged := new(http.Request)
	*logged = *r
	logged.RequestURI = r.URL.EscapedPath()
	return f.DefaultLogFormatter.NewLogEntry(logged)
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	lifetime := s.Lifetime
	if lifetime == nil {
		lifetime = context.Background()
	}

	// Middleware
	r.Use(middleware.RequestLogger(&pathLogFormatter{middleware.DefaultLogFormatter{Logger: log.Default(), NoColor: true}}))
	r.Use(middleware.Recoverer)

	// A plain cap on how often one address may knock at all. The guards inside
	// the handlers count failures and pause sign-in for growing periods.
	rateLimiter := api.NewRateLimiter(30, time.Minute)

	// Handlers
	authHandler := api.NewAuthHandler(s.userManager, s.config)
	webAuthnHandler := api.NewWebAuthnHandler(s.userManager, s.config)
	authHandler.Guard.OnPause = s.loginPaused("с паролем")
	webAuthnHandler.Guard.OnPause = s.loginPaused("по ключу доступа")
	updateHandler := api.NewUpdateHandler(s.updater)
	devicesHandler := api.NewDevicesHandler(s.detector, keenetic.DefaultAddr)
	setupHandler := api.NewSetupHandler(s.detector, s.subscription, s.watchdog, devicesHandler)
	setupHandler.Updater = s.updater
	sitesHandler := api.NewSitesHandler(s.sites)
	handlers := api.NewHandlers(s.config, s.subscription, s.watchdog, s.detector, s.pool)
	handlers.Cards = s.Cards
	handlers.History = s.History
	if s.History != nil {
		s.History.SetDeviceProvider(devicesHandler.TrafficIdentities)
		go s.History.Run(lifetime)
	}
	handlers.Checks = sse.NewProbeJobs(s.subscription, xkeen.ProbeOptions{Context: lifetime, StateDir: s.config.DataDir, Concurrency: s.config.ProbeConcurrency, Timeout: time.Duration(s.config.ProbeTimeoutMs) * time.Millisecond}, func(servers []models.Server, options xkeen.ProbeOptions) ([]models.Server, error) {
		if s.Cards != nil {
			return s.Cards.CheckServers(servers, options)
		}
		rt := s.detector.Runtime()
		if rt.Core == xkeen.CoreMihomo {
			return xkeen.CheckCardServersHTTPS(rt, servers, options)
		}
		return xkeen.CheckServersHTTPS(rt, servers, options)
	}, func(ctx context.Context, checked []models.Server) error {
		s.watchdog.LockChanges()
		defer s.watchdog.UnlockChanges()
		if err := s.subscription.UpdateLatencies(checked); err != nil {
			return err
		}
		if s.Cards != nil && s.Cards.Reconcile(ctx) != nil {
			return sse.ErrPoolUpdate
		}
		return nil
	})
	if s.Cards != nil {
		s.Cards.SetPingRecorder(func(samples []models.Server, full bool) {
			store := s.subscription.RecordPings
			if full {
				store = s.subscription.UpdateLatencies
			}
			if err := store(samples); err != nil {
				log.Printf("Не удалось сохранить замеры роутера: %v", err)
			}
		})
		go runBackgroundChecks(lifetime, handlers.Checks, s.Cards.PoolMemberIDs, s.subscription.GetServers)
		go maintainPools(lifetime, s.Cards, s.watchdog)
		if s.watchdog != nil {
			s.watchdog.SetPoolRecheck(func() bool { return handlers.Checks.StartBackground(s.Cards.PoolMemberIDs()) })
		}
	}
	if s.Cards != nil {
		handlers.FaceID = api.NewPanelFaceID(s.config, s.CardsListen, devicesHandler)
		webAuthnHandler.FaceID = handlers.FaceID
		if handlers.FaceID != nil {
			authHandler.Secure = handlers.FaceID.SecureAddress
			authHandler.CheckSecureAddress()
		}
	}
	accountHandler := api.NewAccountHandler(s.userManager, s.config)
	accountHandler.Guard.OnPause = s.loginPaused("в настройках входа")
	if s.watchdog != nil {
		accountHandler.Log = s.watchdog.Log
		api.SessionLog = s.watchdog.Log
	}
	componentsHandler := api.NewComponentsHandler(handlers)

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Use(middleware.NoCache)
		// Pasted subscriptions are the only large requests; their handlers
		// apply their own, larger limit.
		r.Use(api.LimitBody(1<<20, "/api/sources"))
		// Authentication, no JWT required
		r.Route("/auth", func(r chi.Router) {
			r.Get("/status", authHandler.HandleAuthStatus)
			if handlers.FaceID != nil {
				r.Get("/address-proof", handlers.FaceID.AddressProof)
			}
			r.Post("/setup", authHandler.HandleSetup)
			r.Post("/setup/confirm", authHandler.HandleSetupConfirm)
			r.With(api.RateLimitMiddleware(rateLimiter, s.config.TrustProxyHeaders)).Post("/login", authHandler.HandleLogin)
			r.With(api.RateLimitMiddleware(rateLimiter, s.config.TrustProxyHeaders)).Post("/login/passkey/begin", webAuthnHandler.HandleLoginBegin)
			r.With(api.RateLimitMiddleware(rateLimiter, s.config.TrustProxyHeaders)).Post("/login/passkey/finish", webAuthnHandler.HandleLoginFinish)
		})

		// SSE routes: JWT required, no timeout
		r.Group(func(r chi.Router) {
			r.Use(api.AuthMiddleware(s.userManager))

			r.Get("/events", sse.HandleEvents(s.eventBus, s.watchdog))
			r.Get("/servers/check", handlers.Checks.Stream)
		})

		// Protected REST routes: JWT and a timeout
		r.Group(func(r chi.Router) {
			r.Use(api.AuthMiddleware(s.userManager))
			r.Use(middleware.Timeout(120 * time.Second))

			r.Get("/status", handlers.HandleStatus)
			r.Post("/session/refresh", authHandler.HandleRefresh)
			r.Get("/diagnostics", api.NewDiagnosticsHandler(lifetime, s.Cards, devicesHandler))
			handlers.MountTrafficHistory(r)
			r.Get("/access", handlers.HandlePanelAccess)
			if s.Notifications != nil {
				s.Notifications.Mount(r)
			}
			r.Get("/access/face-id/plan", handlers.HandlePlanFaceID)
			r.Post("/access/face-id/prepare", handlers.HandlePrepareFaceID)
			r.Post("/sources/import", handlers.HandleImportSource)
			r.Get("/sources", handlers.HandleSources)
			r.Post("/sources", handlers.HandleAddSource)
			r.Put("/sources/{id}", handlers.HandleRenameSource)
			r.Post("/sources/{id}/refresh", handlers.HandleRefreshSource)
			r.Post("/sources/{id}/url", handlers.HandleReplaceSourceURL)
			r.Delete("/sources/{id}", handlers.HandleDeleteSource)
			r.Get("/routing-mode", handlers.HandleGetRoutingPolicy)
			r.Put("/routing-mode", handlers.HandlePutRoutingPolicy)
			if s.Cards == nil {
				r.Get("/service-routes", handlers.HandleGetServiceRoutes)
				r.Put("/service-routes", handlers.HandlePutServiceRoutes)
				r.Get("/exclusions", handlers.HandleGetExclusions)
				r.Post("/exclusions", handlers.HandleCreateExclusion)
				r.Delete("/exclusions/{id}", handlers.HandleDeleteExclusion)
			} else {
				handlers.MountMihomoCards(r, s.CardsHost)
			}
			r.Get("/service-routes/claude-api-firewall", handlers.HandleClaudeFirewallStatus)
			r.Post("/service-routes/claude-api-firewall", handlers.HandleInstallClaudeFirewall)
			r.Get("/components", componentsHandler.HandleState)
			r.Get("/components/releases", componentsHandler.HandleReleases)
			r.Post("/components/preview", componentsHandler.HandlePreview)
			r.Post("/components/apply", componentsHandler.HandleApply)
			r.Post("/components/rollback", componentsHandler.HandleRollback)
			r.Put("/components/geodata", componentsHandler.HandleGeodata)
			componentsHandler.MountMihomo(r)

			r.Get("/subscription", handlers.HandleGetSubscription)
			r.Post("/subscription", handlers.HandleUpdateSubscription)
			r.Post("/subscription/refresh", handlers.HandleRefreshSubscription)

			r.Get("/servers", handlers.HandleGetServers)
			r.Post("/servers/select", handlers.HandleSelectServer)
			r.Post("/servers/check", handlers.HandleCheckServers)
			r.Get("/servers/check/job", handlers.HandleProbeJob)
			r.Post("/servers/check/job", handlers.HandleProbeJob)
			r.Delete("/servers/check/job", handlers.HandleProbeJob)
			r.Get("/ui/servers", handlers.HandleServersView)
			r.Put("/ui/servers", handlers.HandleServersView)
			r.Post("/servers/country", handlers.HandleSetCountry)

			accountHandler.Mount(r)

			// Passkey management
			r.Post("/account/passkey/register/begin", webAuthnHandler.HandleRegisterBegin)
			r.Post("/account/passkey/register/finish", webAuthnHandler.HandleRegisterFinish)
			r.Get("/account/passkey", webAuthnHandler.HandlePasskeyList)
			r.Delete("/account/passkey", webAuthnHandler.HandlePasskeyDelete)

			r.Post("/xkeen/restart", handlers.HandleRestart)
			r.Post("/xkeen/start", handlers.HandleStart)
			r.Post("/xkeen/stop", handlers.HandleStop)
			r.Post("/xkeen/selftest", handlers.HandleSelfTest)

			r.Get("/xkeen/settings", handlers.HandleGetSettings)
			r.Put("/xkeen/settings", handlers.HandleUpdateSettings)
			r.Get("/xkeen/lists/{name}", handlers.HandleGetList)
			r.Put("/xkeen/lists/{name}", handlers.HandleUpdateList)

			r.Post("/mihomo/sync", handlers.HandleMihomoSync)

			r.Get("/setup/state", setupHandler.HandleState)
			r.Post("/setup/policy", setupHandler.HandlePolicy)
			r.Post("/setup/finish", setupHandler.HandleFinish)

			r.Get("/panel/settings", s.settings.HandleGet)
			r.Put("/panel/settings", s.settings.HandlePut)
			api.NewTransferHandler(handlers, s.settings).Mount(r)

			r.Get("/devices", devicesHandler.HandleList)
			r.Post("/devices/rename", devicesHandler.HandleRename)
			r.Post("/devices/forget", devicesHandler.HandleForget)
			r.Post("/devices/vpn", devicesHandler.HandleSetVPN)
			r.Post("/devices/new", devicesHandler.HandleNewDevicesVPN)

			r.Get("/pool", handlers.HandlePoolStatus)
			r.Post("/pool/enable", handlers.HandlePoolEnable)
			r.Post("/pool/disable", handlers.HandlePoolDisable)
			r.Post("/pool/sync", handlers.HandlePoolSync)
			r.Post("/pool/pin", handlers.HandlePoolPin)
			r.Post("/pool/auto", handlers.HandlePoolAuto)

			r.Get("/sites", sitesHandler.HandleList)
			r.Post("/sites", sitesHandler.HandleCreate)
			r.Post("/sites/{id}/check", sitesHandler.HandleCheck)
			r.Delete("/sites/{id}", sitesHandler.HandleDelete)

			r.Get("/update", updateHandler.HandleStatus)
			r.Post("/update/check", updateHandler.HandleCheck)
			r.Post("/update/apply", updateHandler.HandleApply)
			r.Put("/update/settings", updateHandler.HandleSettings)

			r.Get("/logs", handlers.HandleLogs)

			// Watchdog toggle
			r.Post("/watchdog/toggle", func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Active bool `json:"active"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{"error": "неверный формат"})
					return
				}
				s.watchdog.SetActive(req.Active)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]bool{"active": req.Active})
			})
		})
	})

	// SPA fallback: serve the frontend
	if s.frontendFS != nil {
		fileServer := http.FileServer(http.FS(s.frontendFS))
		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			// Try to serve a static file
			path := r.URL.Path
			if path == "/" {
				path = "/index.html"
			}

			// Check whether the file exists
			f, err := s.frontendFS.Open(path[1:]) // drop the leading /
			if err == nil {
				f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}

			// SPA fallback: serve index.html
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
		})
	}

	return r
}

// loginPaused writes a pause of sign-in to the panel journal. The address is
// the only detail: it is what the owner needs to find the device.
func (s *Server) loginPaused(way string) func(string, time.Duration) {
	return func(address string, wait time.Duration) {
		if s.watchdog == nil {
			return
		}
		if address == "*" {
			s.watchdog.Log("[SECURITY] Много неудачных попыток входа %s с разных адресов — этот способ входа приостановлен на %s", way, wait)
			return
		}
		s.watchdog.Log("[SECURITY] Неудачные попытки входа %s с адреса %s — для него вход приостановлен на %s", way, address, wait)
	}
}

func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.config.Port)
	log.Printf("Сервер запущен на %s", addr)
	return http.ListenAndServe(addr, s.Handler())
}
