package server

import (
	"context"
	"log"
	"time"

	"xkeen-panel/internal/cardcontroller"
	"xkeen-panel/internal/monitor"
)

// Reading the pool worker's verdicts is local and cheap, so the panel looks
// often: a server the worker found silent is replaced within seconds of its
// probe round, not a whole round later.
const silentCheckEvery = 15 * time.Second

func replaceSilentPoolMembers(ctx context.Context, cards *cardcontroller.Controller, watchdog *monitor.Watchdog) {
	ticker := time.NewTicker(silentCheckEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		check, cancel := context.WithTimeout(ctx, 60*time.Second)
		n, err := cards.ReplaceSilentPoolMembers(check)
		cancel()
		switch {
		case err != nil:
			log.Printf("Не удалось заменить молчащие серверы пула: %v", err)
		case n > 0 && watchdog != nil:
			watchdog.Log("[MIHOMO] Роутер не получил ответа от серверов пула «Все локации» (%d) — заменил их следующими по скорости на 30 минут, открытые соединения не прерывал", n)
		}
	}
}
