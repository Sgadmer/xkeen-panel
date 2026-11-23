package server

import (
	"context"
	"log"
	"time"

	"xkeen-panel/internal/cardcontroller"
	"xkeen-panel/internal/monitor"
)

// The pool worker probes its servers every 2 minutes; checking its verdicts
// every minute replaces a silent server within one round of noticing it.
const silentCheckEvery = time.Minute

func replaceSilentPoolMembers(ctx context.Context, cards *cardcontroller.Controller, watchdog *monitor.Watchdog) {
	ticker := time.NewTicker(silentCheckEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		check, cancel := context.WithTimeout(ctx, 90*time.Second)
		n, err := cards.ReplaceSilentPoolMembers(check)
		cancel()
		switch {
		case err != nil:
			log.Printf("Не удалось заменить молчащие серверы пула: %v", err)
		case n > 0 && watchdog != nil:
			watchdog.Log("[MIHOMO] Роутер не получил ответа от серверов пула «Все локации» (%d) — заменил их следующими по скорости на 30 минут", n)
		}
	}
}
