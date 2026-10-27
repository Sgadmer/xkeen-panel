package api

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"xkeen-panel/internal/models"
	"xkeen-panel/internal/xkeen"
)

type managedFileSnapshot struct {
	exists    bool
	canRemove bool
	mode      os.FileMode
	data      []byte
}

type subscriptionApplySnapshot struct {
	files          map[string]managedFileSnapshot
	runtime        xkeen.Runtime
	data           models.SubscriptionData
	pool           xkeen.PoolState
	probeAddr      string
	runtimeTouched bool
}

func (h *Handlers) withSubscriptionTransaction(apply func(*subscriptionApplySnapshot) (map[string]interface{}, error)) (map[string]interface{}, error) {
	h.watchdog.LockChanges()
	defer h.watchdog.UnlockChanges()
	transaction, err := h.snapshotSubscriptionApply()
	if err != nil {
		return nil, err
	}
	response, err := apply(transaction)
	if err == nil {
		return response, nil
	}
	if rollbackErr := transaction.restore(h); rollbackErr != nil {
		return nil, fmt.Errorf("%w; восстановление прежнего подключения не подтверждено", err)
	}
	return nil, err
}

func (h *Handlers) snapshotSubscriptionApply() (*subscriptionApplySnapshot, error) {
	rt := h.detector.Runtime()
	snapshot := &subscriptionApplySnapshot{files: map[string]managedFileSnapshot{}, runtime: rt, data: h.subscription.GetData(), pool: h.pool.Get(), probeAddr: h.watchdog.ProbeAddress()}
	// These are the only paths this transaction may create. An absent file is
	// recorded only from this explicit set; rollback never scans for deletions.
	paths := []string{h.config.OutboundsFile, rt.RoutingFile, snapshot.pool.RoutingFile,
		xkeen.ExclusionsConfigPath(rt), xkeen.ExclusionsPath(h.config.DataDir),
		xkeen.RoutingPolicyPath(rt),
		xkeen.ProfileStatePath(h.config.OutboundsFile),
		filepath.Join(rt.XrayConfDir, "00_api.json"), filepath.Join(rt.XrayConfDir, "00_panel_probe.json"),
		filepath.Join(h.config.DataDir, "pool.json"), filepath.Join(h.config.DataDir, "subscription.json")}
	// Existing JSON documents can carry routing outside its usual file name.
	existing, err := filepath.Glob(filepath.Join(rt.XrayConfDir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("не удалось подготовить снимок конфигурации")
	}
	paths = append(paths, existing...)
	// Xray writes one .bak beside a changed document. Keep that recovery state
	// in the same transaction so a later restore cannot resurrect a rejected pool.
	backups := make([]string, 0, len(paths))
	for _, path := range paths {
		if path != "" && strings.HasSuffix(path, ".json") {
			backups = append(backups, path+".bak")
		}
	}
	paths = append(paths, backups...)
	deletionAllowed := map[string]bool{}
	for _, path := range paths {
		if path != "" {
			deletionAllowed[filepath.Clean(path)] = true
		}
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		path = filepath.Clean(path)
		if _, seen := snapshot.files[path]; seen {
			continue
		}
		file := managedFileSnapshot{canRemove: deletionAllowed[path]}
		info, statErr := os.Stat(path)
		if statErr != nil && !os.IsNotExist(statErr) {
			return nil, fmt.Errorf("не удалось подготовить снимок конфигурации")
		}
		if statErr == nil {
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("файл конфигурации не является обычным файлом")
			}
			file.exists = true
			file.mode = info.Mode().Perm()
			file.data, err = os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("не удалось подготовить снимок конфигурации")
			}
		}
		snapshot.files[path] = file
	}
	return snapshot, nil
}

func (snapshot *subscriptionApplySnapshot) restore(h *Handlers) error {
	var failures []error
	if !reflect.DeepEqual(h.subscription.GetData(), snapshot.data) {
		if err := h.subscription.RestoreData(snapshot.data); err != nil {
			failures = append(failures, err)
		}
	}
	if h.pool.Get() != snapshot.pool {
		if err := h.pool.Set(snapshot.pool); err != nil {
			failures = append(failures, err)
		}
	}
	for path, file := range snapshot.files {
		if !file.exists {
			if !file.canRemove {
				continue
			}
			// Every absent entry was explicitly named before the apply. New,
			// unrelated JSON documents are not part of this map or removed.
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				failures = append(failures, err)
			}
			continue
		}
		current, readErr := os.ReadFile(path)
		info, statErr := os.Stat(path)
		if readErr == nil && statErr == nil && bytes.Equal(current, file.data) && info.Mode().Perm() == file.mode {
			continue
		}
		if err := restoreManagedFile(path, file.data, file.mode); err != nil {
			failures = append(failures, err)
		}
	}
	h.detector.InvalidateTopology()
	h.watchdog.SetProbeAddr(snapshot.probeAddr)
	if len(failures) == 0 && snapshot.runtimeTouched && snapshot.runtime.Installed {
		if err := h.restartManaged(snapshot.runtime.Dispatcher); err != nil {
			failures = append(failures, err)
		} else if err := h.waitForBalancer(snapshot.runtime); err != nil {
			failures = append(failures, err)
		} else if err := h.watchdog.ReapplySelectionLocked(); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func restoreManagedFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".subscription-rollback-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (snapshot *subscriptionApplySnapshot) manualPreference(fresh []models.Server) (*models.Server, error) {
	if !snapshot.pool.PinManual {
		return nil, nil
	}
	if same, ok := xkeen.ServerForNode(fresh, snapshot.pool.PinnedNode); ok {
		return &same, nil
	}
	previous, ok := xkeen.ServerForNode(snapshot.data.Servers, snapshot.pool.PinnedNode)
	if !ok {
		return nil, fmt.Errorf("не удалось восстановить ранее выбранный вручную сервер")
	}
	var matching *models.Server
	for _, candidate := range fresh {
		if !strings.EqualFold(strings.TrimSpace(candidate.Name), strings.TrimSpace(previous.Name)) ||
			!strings.EqualFold(xkeen.ServerCountry(candidate), xkeen.ServerCountry(previous)) ||
			!strings.EqualFold(candidate.Protocol, previous.Protocol) {
			continue
		}
		if matching != nil && xkeen.NodeKeyOfServer(*matching) != xkeen.NodeKeyOfServer(candidate) {
			return nil, fmt.Errorf("для выбранного вручную сервера найдено несколько замен; прежняя подписка сохранена")
		}
		value := candidate
		matching = &value
	}
	if matching == nil {
		return nil, fmt.Errorf("выбранный вручную сервер исчез из подписки; прежняя подписка сохранена")
	}
	if matching.ProbeKind == "https" && matching.Latency < 0 {
		return nil, fmt.Errorf("обновлённый ручной сервер не прошёл HTTPS-проверку; прежняя подписка сохранена")
	}
	return matching, nil
}

func (h *Handlers) restartManaged(dispatcher string) error {
	restart := h.restartCore
	if restart == nil {
		restart = xkeen.RestartAndWait
	}
	if _, err := restart(dispatcher); err != nil {
		return fmt.Errorf("не удалось перезапустить Xray; изменение не применено")
	}
	return nil
}

func (h *Handlers) waitForBalancer(rt xkeen.Runtime) error {
	h.detector.InvalidateTopology()
	top := h.detector.Topology()
	if top.Mode != xkeen.TopologyPool {
		return nil
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := xkeen.BalancerStatus(rt, h.config.XrayAPIAddr, top.BalancerTag); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("API Xray не подтвердило готовность пула")
}
