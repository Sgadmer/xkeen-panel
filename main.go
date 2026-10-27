package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	"xkeen-panel/internal/api"
	"xkeen-panel/internal/auth"
	"xkeen-panel/internal/demo"
	"xkeen-panel/internal/geoip"
	"xkeen-panel/internal/localtz"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/monitor"
	"xkeen-panel/internal/server"
	"xkeen-panel/internal/sse"
	"xkeen-panel/internal/updater"
	"xkeen-panel/internal/version"
	"xkeen-panel/internal/xkeen"

	"gopkg.in/yaml.v3"
)

// Written by install.sh; the update guard restarts the panel through it.
const panelInitScript = "/opt/etc/init.d/S99xkeen-panel"

func main() {
	configPath := flag.String("config", "config.yaml", "путь к конфигурационному файлу")
	showVersion := flag.Bool("version", false, "вывести версию и выйти")
	demoMode := flag.Bool("demo", false, "обезличенная демонстрация интерфейса на 127.0.0.1:3300")
	flag.Parse()

	// The updater runs the new binary with -version before switching to it
	if *showVersion {
		fmt.Println(version.Version)
		return
	}
	if *demoMode {
		frontend, err := fs.Sub(frontendDist, "frontend/dist")
		if err != nil {
			log.Fatal(err)
		}
		log.Print("Демонстрационные данные: http://127.0.0.1:3300; роутер не используется")
		log.Fatal(http.ListenAndServe("127.0.0.1:3300", demo.Handler(frontend)))
	}

	if rule, ok := localtz.Apply("/etc/localtime"); ok {
		log.Printf("Часовой пояс взят из /etc/localtime: %s", rule)
	}

	// Resolved now: once an update renames the running file, the link points at .prev
	binPath, err := os.Executable()
	if err == nil {
		binPath, err = filepath.EvalSymlinks(binPath)
	}
	if err != nil {
		log.Printf("Путь к бинарю не определён (%v) — самообновление недоступно", err)
		binPath = ""
	}

	// Load the configuration
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Ошибка загрузки конфига: %v", err)
	}
	if err := api.LoadPanelSettings(cfg); err != nil {
		log.Printf("Предупреждение: настройки из панели не загружены: %v", err)
	}

	// User manager
	userManager := auth.NewUserManager(cfg.DataDir)
	if err := userManager.Load(); err != nil {
		log.Fatalf("Ошибка загрузки пользователя: %v", err)
	}

	// Subscription manager
	subManager := xkeen.NewSubscriptionManager(cfg.DataDir)
	if err := subManager.Load(); err != nil {
		log.Printf("Предупреждение: ошибка загрузки подписки: %v", err)
	}

	// Detect the XKeen layout: generation (S05xkeen/S24xray), core, mode, version
	detector := xkeen.NewDetector("", cfg.XKeenPath, cfg.InitScript,
		cfg.XrayConfigDir, cfg.RoutingFile, cfg.MihomoConfig, cfg.XkeenJSON)
	rt := detector.Runtime()
	if !rt.Installed {
		log.Printf("XKeen не найден (%s) — управление ядром недоступно", rt.InitScript)
	} else {
		log.Printf("XKeen %s (поколение %d), ядро %s, режим %s", rt.Version, rt.Generation, rt.Core, rt.Mode)
	}

	// Pool state: the tag the routing rules were written against is what makes a
	// correct return to a single outbound possible
	poolStore := xkeen.NewPoolStore(cfg.DataDir)
	if err := poolStore.Load(); err != nil {
		log.Printf("Предупреждение: не удалось загрузить состояние пула: %v", err)
	}

	// Watchdog and SSE
	watchdog := monitor.NewWatchdog(cfg, subManager, detector)
	eventBus := sse.NewEventBus()
	watchdog.SetEventBus(eventBus)
	watchdog.SetPoolStore(poolStore)

	siteStore := xkeen.NewSiteStore(cfg.DataDir)
	if err := siteStore.Load(); err != nil {
		log.Printf("Предупреждение: не удалось загрузить сайты: %v", err)
	}
	sites := xkeen.NewSiteManager(siteStore, detector, subManager, cfg.OutboundsFile, cfg.XrayAPIAddr, 12*time.Second)
	sites.Logf = watchdog.Log
	sites.Notify = func() { eventBus.Publish(sse.Event{Type: "sites", Data: struct{}{}}) }
	sites.Restart = func() { go watchdog.RestartCore() }

	// Package xkeen logs to stdout by default, which the init script discards —
	// send its pool and restart events to the panel log instead
	xkeen.Log = watchdog.Log

	// Both migrations need a core restart; doing them together keeps it to one
	restartCore := false
	if migrated, err := xkeen.EnsureAPIConfig(poolStore.Get(), cfg.XrayAPIAddr); err != nil {
		log.Printf("Не удалось обновить api-блок Xray: %v", err)
	} else if migrated {
		log.Printf("api-блок Xray приведён к текущей форме")
		restartCore = true
	}
	if changed, err := watchdog.EnsureProbe(); err != nil {
		log.Printf("Не удалось добавить проверочный вход в Xray — статус будет проверяться мимо прокси: %v", err)
	} else if changed {
		log.Printf("В Xray добавлен проверочный вход %s", cfg.ProbeAddr)
		restartCore = true
	}
	if restartCore && rt.Installed {
		log.Printf("Конфиг Xray изменён при запуске — перезапускаю ядро")
		xkeen.Restart(rt.Dispatcher)
	}

	// GeoIP reuses the geoip.dat already installed for Xray
	var geoMatcher *geoip.Matcher
	geoPath := geoip.FindDat(cfg.GeoIPPath)
	if geoPath == "" {
		log.Printf("GeoIP: geoip.dat не найден (%s) — гео-фильтр по IP отключён, используется определение по имени", cfg.GeoIPPath)
	} else if matcher, err := geoip.Load(geoPath, cfg.AvoidCountries()); err != nil {
		log.Printf("GeoIP: ошибка загрузки %s: %v — гео-фильтр по IP отключён", geoPath, err)
	} else {
		geoMatcher = matcher
		watchdog.SetGeoIP(matcher)
		log.Printf("GeoIP: загружен %s (избегаемые страны: %v)", geoPath, cfg.AvoidCountries())
	}

	refreshReset := make(chan struct{}, 1)
	panelSettings := api.NewPanelSettingsHandler(cfg, geoMatcher, geoPath, refreshReset)

	// Autostart the watchdog for unattended operation
	if cfg.WatchdogAutoStart && len(subManager.GetServers()) > 0 {
		watchdog.SetActive(true)
		log.Printf("Watchdog включён автоматически (watchdog_auto_start)")
	}

	// Publish restart events over SSE
	xkeen.OnRestartStateChange = func(restarting bool) {
		eventBus.Publish(sse.Event{
			Type: "restart",
			Data: map[string]bool{"restarting": restarting},
		})
		eventBus.Publish(sse.Event{
			Type: "status",
			Data: watchdog.GetStatus(),
		})
		if !restarting {
			// RestartAndWait may be called while a config transaction holds
			// changeMu. Restore on a separate goroutine and read the preference
			// only after acquiring that same lock.
			go func() {
				if err := watchdog.ReapplySelection(); err != nil {
					watchdog.Log("[PIN] Не удалось восстановить выбор после перезапуска: %v", err)
				}
				watchdog.CheckNow()
			}()
		}
	}

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run the watchdog
	watchdogDone := make(chan struct{})
	go func() {
		watchdog.Start(ctx)
		close(watchdogDone)
	}()

	go sites.Run(ctx)

	// Periodic subscription refresh
	go runSubscriptionRefresh(ctx, cfg, subManager, watchdog, detector, poolStore, geoMatcher, eventBus, refreshReset)

	// The process is replaced only after the HTTP server and the watchdog have stopped
	reexec := make(chan struct{}, 1)
	upd := updater.New(updater.Options{
		Locked:     false,
		Repo:       updater.DefaultRepo,
		Current:    version.Version,
		BinPath:    binPath,
		DataDir:    cfg.DataDir,
		InitScript: panelInitScript,
		AutoHour:   cfg.AutoUpdateHour,
		Log:        watchdog.Log,
		Publish: func(state updater.State) {
			eventBus.Publish(sse.Event{Type: "update", Data: state})
		},
		Restart: func() error {
			select {
			case reexec <- struct{}{}:
			default:
			}
			return nil
		},
		Busy: xkeen.IsRestarting,
	})
	upd.Startup(ctx, func() bool { return panelResponds(cfg.Port) })
	go upd.Run(ctx)

	// Frontend assets
	var frontendFS fs.FS
	distFS, err := fs.Sub(frontendDist, "frontend/dist")
	if err != nil {
		log.Printf("Предупреждение: встроенный фронтенд недоступен: %v", err)
	} else {
		frontendFS = distFS
	}

	// HTTP server
	srv := server.New(cfg, userManager, subManager, watchdog, detector, poolStore, sites, geoMatcher, eventBus, upd, panelSettings, frontendFS)
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: srv.Handler(),
		// SSE streams never go idle, so Shutdown would wait out its timeout unless cancelling ctx ends them
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	stopped := make(chan bool, 1)
	go func() {
		restart := false
		select {
		case <-sigChan:
			log.Println("Получен сигнал завершения, останавливаем сервер...")
		case <-reexec:
			restart = true
			log.Println("Перезапуск в новую версию, останавливаем сервер...")
		}
		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("Ошибка при остановке сервера: %v", err)
		}

		// A watchdog cut off mid-check could leave a core config half-applied
		select {
		case <-watchdogDone:
		case <-time.After(60 * time.Second):
			log.Println("Watchdog не остановился за минуту — продолжаю")
		}

		stopped <- restart
	}()

	log.Printf("XKeen Panel %s запущена на порту %d (xkeen=%s, outbounds=%s)", version.Version, cfg.Port, cfg.XKeenPath, cfg.OutboundsFile)
	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Ошибка сервера: %v", err)
	}

	if <-stopped {
		// Same PID and name, so the init script keeps recognising the process
		err := syscall.Exec(binPath, os.Args, os.Environ())
		log.Fatalf("Не удалось запустить новую версию: %v", err)
	}

	log.Println("Сервер остановлен")
}

func panelResponds(port int) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/auth/status", port))
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// runSubscriptionRefresh refreshes the subscription on a timer. The core is
// restarted only when the active server was actually replaced (it vanished from
// the subscription) — a refresh must not drop a working connection.
func runSubscriptionRefresh(ctx context.Context, cfg *models.Config, sm *xkeen.SubscriptionManager, wd *monitor.Watchdog, det *xkeen.Detector, pool *xkeen.PoolStore, matcher *geoip.Matcher, bus *sse.EventBus, reset <-chan struct{}) {
	handler := api.NewHandlers(cfg, sm, wd, det, pool, matcher)
	for {
		var tick <-chan time.Time
		if interval := cfg.RefreshInterval(); interval > 0 {
			tick = time.After(interval)
		}
		select {
		case <-ctx.Done():
			return
		case <-reset:
			continue
		case <-tick:
			if !sm.CanRefresh() {
				continue
			}
			if err := handler.RefreshManaged(ctx); err != nil {
				wd.Log("[AUTO-UPDATE] Подписка не обновлена: %v", err)
				continue
			}
			bus.Publish(sse.Event{Type: "subscription", Data: map[string]bool{"updated": true}})
			wd.Log("[AUTO-UPDATE] Подписка обновлена (%d серверов)", len(sm.GetServers()))
		}
	}
}

// liveSuffix says whether the pool update avoided a restart.
func liveSuffix(res xkeen.SyncResult) string {
	if res.Live {
		return " (без перезапуска)"
	}
	if res.Restarted {
		return " (с перезапуском ядра)"
	}
	return ""
}

func loadConfig(path string) (*models.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &models.Config{
		Port:          3000,
		DataDir:       "data",
		XKeenPath:     "/opt/sbin/xkeen",
		OutboundsFile: "/opt/etc/xray/configs/04_outbounds.json",
		XrayAPIAddr:   "127.0.0.1:10085",
		ProbeAddr:     "127.0.0.1:10086",
		CheckInterval: 120,
		CheckURL:      "https://www.google.com",
		MaxFails:      3,
		LogFile:       "xkeen-panel.log",

		ProbeTimeoutMs:     2000,
		ProbeConcurrency:   20,
		LatencyAutoSwitch:  true,
		LatencyThresholdMs: 1000,
		LatencySwitchCount: 3,
		BlacklistTTLSec:    300,
		WatchdogAutoStart:  true,

		SubscriptionRefreshInterval: 3600,
		AutoUpdateHour:              4,

		PoolMaxNodes:             xkeen.DefaultPoolMaxNodes,
		HealthCheckURLs:          monitor.DefaultHealthURLs,
		HealthCheckEvery:         5,
		HealthFailThreshold:      2,
		HealthQuorum:             2,
		GeoIPPath:                "/opt/etc/xray/dat/geoip_v2fly.dat",
		AutoSwitchAvoidCountries: []string{"RU", "BY"},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
