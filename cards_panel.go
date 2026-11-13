package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"xkeen-panel/internal/cardcontroller"
	"xkeen-panel/internal/monitor"
	"xkeen-panel/internal/xkeen"
)

func cardsBindHost(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	n, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || !(ip.IsLoopback() || ip.IsPrivate()) || portErr != nil || n < 1 || n > 65535 {
		return "", errors.New("для панели укажите локальный IP роутера и порт")
	}
	return host, nil
}

func newCardsController(dataDir, mihomoConfig string, sub *xkeen.SubscriptionManager) (*cardcontroller.Controller, error) {
	base := filepath.Join(dataDir, "service-cards")
	rt := xkeen.Runtime{Core: xkeen.CoreXray, CoreBin: "/opt/sbin/xray", XrayConfDir: filepath.Join(base, "configs")}
	if err := os.MkdirAll(rt.XrayConfDir, 0700); err != nil {
		return nil, err
	}
	assets := filepath.Join(base, "dat")
	if err := os.Symlink("/opt/etc/xray/dat", assets); err != nil && !os.IsExist(err) {
		return nil, err
	}
	if value, err := os.Readlink(assets); err != nil || value != "/opt/etc/xray/dat" {
		return nil, errors.New("неожиданный каталог геоданных панели сервисов")
	}
	cards := cardcontroller.New(mihomoConfig, base, rt, sub.GetServers)
	cards.SetSourceProviderURLs(sub.SourceProviderURLs)
	return cards, nil
}

func maintainCardRoutes(ctx context.Context, controller *cardcontroller.Controller, wd *monitor.Watchdog) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		wd.LockChanges()
		attempt, cancel := context.WithTimeout(ctx, 90*time.Second)
		if err := controller.Reconcile(attempt); err != nil && ctx.Err() == nil {
			log.Print("Маршруты сервисов ожидают готовности локального контроллера.")
		}
		cancel()
		wd.UnlockChanges()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
