package components

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

type pendingOperation struct {
	BackupID   string `json:"backup_id"`
	Job        Job    `json:"job"`
	WasRunning bool   `json:"was_running"`
}

func (m *Manager) pendingPath() string {
	return filepath.Join(m.opts.DataDir, "component-operation.json")
}
func (m *Manager) writePending(p pendingOperation) error {
	b, e := json.Marshal(p)
	if e != nil {
		return e
	}
	return atomicWrite(m.pendingPath(), b, 0600)
}
func (m *Manager) readPending() (pendingOperation, error) {
	var p pendingOperation
	b, e := os.ReadFile(m.pendingPath())
	if e != nil {
		return p, e
	}
	if len(b) > 32<<10 || json.Unmarshal(b, &p) != nil || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(p.BackupID) || p.Job.ID == "" {
		return p, fmt.Errorf("повреждён журнал восстановления")
	}
	return p, nil
}

// Recover finishes an interrupted transaction after a panel/router restart.
// The marker names a previously verified local snapshot, never a network URL.
func (m *Manager) Recover(ctx context.Context) {
	p, e := m.readPending()
	if os.IsNotExist(e) {
		return
	}
	if e != nil {
		if m.opts.Log != nil {
			m.opts.Log("[COMPONENTS] Журнал восстановления повреждён; требуется управляемое восстановление")
		}
		return
	}
	m.opts.Lock()
	defer m.opts.Unlock()
	m.setPhase(p.Job.ID, "recovering")
	backup, e := m.readBackup(p.BackupID)
	if e == nil {
		e = m.restoreBackup(backup)
	}
	if e == nil {
		e = m.validateCurrent(ctx)
	}
	if e == nil && p.WasRunning {
		e = m.opts.Restart(ctx)
	}
	if e == nil {
		_ = os.Remove(m.pendingPath())
		m.finish(p.Job.ID, fmt.Errorf("прерванная операция отменена; прежнее состояние восстановлено"), p.BackupID, true)
		return
	}
	m.finish(p.Job.ID, fmt.Errorf("прерванная операция требует восстановления из резервной копии %s", p.BackupID), p.BackupID, false)
}
