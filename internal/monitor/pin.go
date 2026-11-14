package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

// PinServer sends all traffic through server. A pool member is pinned by its
// tag; anything else goes into the manual slot first, since the owner may need
// one particular country that the pool's fastest nodes do not cover.
func (w *Watchdog) PinServer(server models.Server, manual bool, note string) (string, error) {
	w.changeMu.Lock()
	defer w.changeMu.Unlock()
	return w.pinServerLocked(server, manual, note)
}

func (w *Watchdog) pinServerLocked(server models.Server, manual bool, note string) (string, error) {
	if w.poolStore == nil {
		return "", fmt.Errorf("состояние пула недоступно")
	}

	top := w.detector.Topology()
	if top.Mode != xkeen.TopologyPool {
		return "", fmt.Errorf("пул не включён")
	}
	rt := w.detector.Runtime()
	path := w.config.OutboundsFile
	identity := xkeen.NodeKeyOfServer(server)
	if identity == "" || !xkeen.CanBuildServer(server) {
		return "", fmt.Errorf("выбранный сервер не поддерживается Xray")
	}
	// The subscription may have refreshed while the request waited for the
	// mutation lock. Resolve the requested identity again before changing files.
	fresh, found := xkeen.ServerForNode(w.subscription.GetServers(), identity)
	if !found {
		return "", fmt.Errorf("выбранного сервера больше нет в подписке; обновите список")
	}
	server = fresh
	selectionFiles, err := xkeen.CaptureSelectionFiles(rt, path)
	if err != nil {
		return "", err
	}
	hadProfile := xkeen.HasActiveProfile(path)
	policyChange := len(server.RawProfile) > 0 || hadProfile
	oldState := w.poolStore.Get()
	oldActive := w.subscription.GetActiveServer()
	manualChanged := false
	runtimeChanged := false
	rollback := func(cause error) (string, error) {
		_ = w.poolStore.Set(oldState)
		if oldActive != nil {
			_, _ = w.subscription.SetActiveByRawURI(oldActive.RawURI)
		}
		if manualChanged {
			if err := selectionFiles.Restore(); err != nil {
				w.writeLog("[PIN] Не удалось восстановить конфигурацию после ошибки выбора")
				return "", fmt.Errorf("%w; восстановление конфигурации не подтверждено", cause)
			}
			w.detector.InvalidateTopology()
		}
		if runtimeChanged {
			if policyChange {
				if err := w.restartAndRepinTargetLocked(rt, top, oldState.PinnedTag); err != nil {
					return "", fmt.Errorf("%w; восстановление ядра не подтверждено", cause)
				}
				return "", cause
			}
			if err := w.restorePinRuntime(rt, top, oldState, manualChanged); err != nil {
				w.writeLog("[PIN] Предыдущий выбор сохранён; восстановление ядра не подтверждено")
				return "", fmt.Errorf("%w; прежний выбор сохранён, состояние ядра не подтверждено", cause)
			}
		}
		return "", cause
	}

	tag := ""
	if nodes, err := xkeen.PoolNodes(path, top.Selector(), []models.Server{server}); err == nil {
		for _, node := range nodes {
			if node.Server != nil {
				tag = node.Tag
				break
			}
		}
	}

	restart := false
	if len(server.RawProfile) > 0 && hadProfile && xkeen.NodeKeyForTag(path, top.Selector(), xkeen.ManualTag) == identity {
		tag = xkeen.ManualTag
	}
	cleanupProfile := hadProfile && len(server.RawProfile) == 0
	if tag == "" || cleanupProfile {
		if err := xkeen.SetManualOutbound(rt, path, server); err != nil {
			return "", err
		}
		manualChanged = true
		w.detector.InvalidateTopology()
		if tag == "" {
			tag = xkeen.ManualTag
		}

		runtimeChanged = true // a failed replacement may already have removed the old slot
		if policyChange {
			restart = true
		} else if err := xkeen.ApplyManualLive(rt, w.config.XrayAPIAddr, path); err != nil {
			w.writeLog("[PIN] Горячая замена недоступна (%v) — перезапускаю ядро", err)
			restart = true
		}
	}

	node := xkeen.NodeKeyForTag(path, top.Selector(), tag)
	if node == "" {
		return rollback(fmt.Errorf("выбранного сервера нет в конфигурации"))
	}

	if restart {
		if err := w.restartAndRepinTargetLocked(rt, top, tag); err != nil {
			return rollback(err)
		}
	} else {
		runtimeChanged = true
		if err := xkeen.OverrideBalancerTarget(rt, w.config.XrayAPIAddr, top.BalancerTag, tag); err != nil {
			return rollback(fmt.Errorf("Xray не подтвердил закрепление выбранного сервера"))
		}
	}
	// Commit only after the running core accepted the choice. A failed override
	if len(server.RawProfile) > 0 && (restart || !hadProfile) {
		proxy := w.proxyURL()
		if proxy == nil {
			return rollback(fmt.Errorf("проверочный вход профиля недоступен"))
		}
		if _, err := fetchLatency(w.config.CheckURL, proxy, 15*time.Second); err != nil {
			return rollback(fmt.Errorf("профиль не прошёл HTTPS-проверку; прежний выбор восстановлен"))
		}
	}
	// must not be retried automatically later as if the owner had selected it.
	if err := w.poolStore.SetPinnedServer(tag, node, manual, xkeen.ServerCountry(server), note); err != nil {
		return rollback(fmt.Errorf("не удалось сохранить выбранный сервер"))
	}
	if _, err := w.subscription.SetActiveByRawURI(server.RawURI); err != nil {
		return rollback(fmt.Errorf("не удалось сохранить активный сервер подписки"))
	}

	w.NodePinned(tag)
	w.writeLog("[PIN] Трафик закреплён за %s (%s)", server.Name, tag)

	return tag, nil
}

// RestartCore applies a config change made outside the watchdog without losing the pin.
func (w *Watchdog) RestartCore() {
	w.changeMu.Lock()
	defer w.changeMu.Unlock()
	if err := w.restartAndRepinLocked(w.detector.Runtime(), w.detector.Topology()); err != nil {
		w.writeLog("[PIN] Не удалось восстановить выбор после перезапуска: %v", err)
	}
}

// ReapplySelection restores the saved choice after a config reload. Reading the
// preference and applying it share one lock, so a delayed reload cannot replace
// a newer manual choice made by the owner.
func (w *Watchdog) ReapplySelection() error {
	w.changeMu.Lock()
	defer w.changeMu.Unlock()
	return w.ReapplySelectionLocked()
}

// ProbeAddress is the runtime probe setting restored with a config transaction.
func (w *Watchdog) ProbeAddress() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.probeAddr
}

// ReapplySelectionLocked is for a config transaction already holding
// LockChanges. It never substitutes an unknown manual choice with a random node.
func (w *Watchdog) ReapplySelectionLocked() error {
	if w.poolStore == nil || w.detector.Topology().Mode != xkeen.TopologyPool {
		return nil
	}
	state := w.poolStore.Get()
	if state.PinnedNode != "" {
		if preferred, ok := xkeen.ServerForNode(w.subscription.GetServers(), state.PinnedNode); ok {
			_, err := w.pinServerLocked(preferred, state.PinManual, state.PinNote)
			return err
		}
	}
	if state.PinManual {
		return fmt.Errorf("выбранного вручную сервера больше нет в подписке")
	}
	_, err := w.pinBest(w.detector.Runtime(), w.detector.Topology())
	return err
}

// ReapplyPreferredLocked applies a uniquely matched replacement of a manual
// server after the provider rotates its access parameters. The caller holds
// LockChanges and commits or rolls back the surrounding config transaction.
func (w *Watchdog) ReapplyPreferredLocked(server models.Server, note string) error {
	_, err := w.pinServerLocked(server, true, note)
	return err
}

// restartAndRepin restarts the core and puts the stored pin back, since the
// override lives only in the core's memory.
func (w *Watchdog) restartAndRepin(rt xkeen.Runtime, top xkeen.Topology) {
	w.changeMu.Lock()
	defer w.changeMu.Unlock()
	if err := w.restartAndRepinLocked(rt, top); err != nil {
		w.writeLog("[PIN] Не удалось восстановить выбор после перезапуска: %v", err)
	}
}

func (w *Watchdog) restartAndRepinLocked(rt xkeen.Runtime, top xkeen.Topology) error {
	wanted := ""
	if w.poolStore != nil {
		wanted = w.poolStore.Get().PinnedTag
	}
	return w.restartAndRepinTargetLocked(rt, top, wanted)
}

func (w *Watchdog) restartAndRepinTargetLocked(rt xkeen.Runtime, top xkeen.Topology, wanted string) error {
	if rt.Dispatcher == "" {
		return fmt.Errorf("перезапуск Xray недоступен")
	}
	if _, err := xkeen.RestartAndWait(rt.Dispatcher); err != nil {
		return fmt.Errorf("не удалось перезапустить Xray")
	}

	deadline := time.Now().Add(20 * time.Second)
	if wanted != "" && top.Mode == xkeen.TopologyPool {
		for time.Now().Before(deadline) {
			if _, err := xkeen.EnsurePinned(rt, w.config.XrayAPIAddr, top, wanted); err == nil {
				w.publishPool()
				return nil
			}
			time.Sleep(250 * time.Millisecond)
		}
		return fmt.Errorf("Xray не подтвердил закрепление после перезапуска")
	}
	w.publishPool()
	return nil
}

func restorePinConfig(path string, data []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".pin-rollback-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (w *Watchdog) restorePinRuntime(rt xkeen.Runtime, top xkeen.Topology, oldState xkeen.PoolState, manualChanged bool) error {
	if manualChanged {
		if xkeen.HasManualOutbound(w.config.OutboundsFile) {
			if err := xkeen.ApplyManualLive(rt, w.config.XrayAPIAddr, w.config.OutboundsFile); err != nil {
				return w.restartAndRepinTargetLocked(rt, top, oldState.PinnedTag)
			}
		} else {
			_ = xkeen.RemoveOutbounds(rt, w.config.XrayAPIAddr, []string{xkeen.ManualTag})
		}
	}
	if oldState.PinnedTag == "" {
		return w.restartAndRepinTargetLocked(rt, top, "")
	}
	if _, err := xkeen.EnsurePinned(rt, w.config.XrayAPIAddr, top, oldState.PinnedTag); err != nil {
		return w.restartAndRepinTargetLocked(rt, top, oldState.PinnedTag)
	}
	return nil
}

// sameCountryReplacement finds the fastest live server of the given country,
// other than the one that just failed.
func (w *Watchdog) sameCountryReplacement(country, failedURI string) (*models.Server, error) {
	var candidates []models.Server
	for _, s := range w.subscription.GetServers() {
		if s.RawURI == failedURI || w.isBlacklisted(s.RawURI) {
			continue
		}
		if !xkeen.CanBuildServer(s) {
			continue
		}
		if xkeen.ServerCountry(s) != country {
			continue
		}
		candidates = append(candidates, s)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("других серверов страны %s в подписке нет", country)
	}

	checked, err := w.checkCandidates(candidates)
	if err != nil {
		return nil, err
	}
	w.subscription.UpdateLatencies(checked)

	var live []models.Server
	for _, s := range checked {
		if s.Latency >= 0 {
			live = append(live, s)
		}
	}
	if len(live) == 0 {
		return nil, fmt.Errorf("ни один сервер страны %s не ответил", country)
	}

	sort.SliceStable(live, func(i, j int) bool { return live[i].Latency < live[j].Latency })
	return &live[0], nil
}

// replaceManualPick keeps a failed manual choice inside its country. Returns
// false when there is no such replacement and the pool has to take over.
func (w *Watchdog) replaceManualPick(state xkeen.PoolState) bool {
	if state.PinCountry == "" {
		return false
	}

	failed, known := xkeen.ServerForNode(w.subscription.GetServers(), state.PinnedNode)
	failedName := state.PinnedTag
	if known {
		failedName = failed.Name
		w.blacklistServer(failed.RawURI)
	}

	next, err := w.sameCountryReplacement(state.PinCountry, failed.RawURI)
	if err != nil {
		w.writeLog("[PIN] Замены для %s нет: %v", failedName, err)
		return false
	}

	note := fmt.Sprintf("%s перестал работать — выбран %s той же страны", failedName, next.Name)
	if _, err := w.pinServerLocked(*next, true, note); err != nil {
		w.writeLog("[PIN] Не удалось закрепить %s: %v", next.Name, err)
		return false
	}

	w.writeLog("[PIN] %s", note)
	return true
}
