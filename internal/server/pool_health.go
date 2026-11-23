package server

import (
	"context"
	"log"
	"time"

	"xkeen-panel/internal/cardcontroller"
	"xkeen-panel/internal/monitor"
)

// Reading the pool workers' measurements is local and cheap, so the panel
// looks often: a new answer reaches every screen and the pool's choice within
// seconds of the worker's probe, not a whole round later.
const poolLoopEvery = 15 * time.Second

func maintainPools(ctx context.Context, cards *cardcontroller.Controller, watchdog *monitor.Watchdog) {
	ticker := time.NewTicker(poolLoopEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		check, cancel := context.WithTimeout(ctx, 60*time.Second)
		n, err := cards.MaintainPools(check)
		cancel()
		switch {
		case err != nil:
			log.Printf("Не удалось заменить молчащие серверы пула: %v", err)
		case n == 1 && watchdog != nil:
			watchdog.Log("[MIHOMO] Роутер дважды подряд не получил ответа от сервера пула «Все локации» — заменил его следующим по скорости на 30 минут, открытые соединения не прерывал")
		case n > 1 && watchdog != nil:
			watchdog.Log("[MIHOMO] Роутер дважды подряд не получил ответа от %d серверов пула «Все локации» — заменил их следующими по скорости на 30 минут, открытые соединения не прерывал", n)
		}
	}
}
