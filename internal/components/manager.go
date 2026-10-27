package components

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"xkeen-panel/internal/xkeen"
)

type Options struct {
	DataDir   string
	Root      string // test installation prefix, empty on the router
	Runtime   func() xkeen.Runtime
	Firmware  func() string
	APIBase   string
	Client    *http.Client
	GOOS      string
	GOARCH    string
	TestHTTP  bool // injectable httptest transport; never read from client/YAML input
	Lock      func()
	Unlock    func()
	Validate  func(context.Context, string) error // optional deterministic test runner
	Restart   func(context.Context) error         // restart, readiness and saved selection together
	Running   func() bool
	FreeBytes func(string) (uint64, error)
	Log       func(string, ...interface{})
}

type Artifact struct {
	Name       string `json:"name"`
	URL        string `json:"-"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	Target     string `json:"target"`
	Version    string `json:"version"`
	Repository string `json:"repository"`
}

type PlanRequest struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Setting   string `json:"setting,omitempty"`
	Enabled   *bool  `json:"enabled,omitempty"`
}

type Plan struct {
	ID            string         `json:"id"`
	Component     string         `json:"component"`
	Version       string         `json:"version"`
	Expires       time.Time      `json:"expires"`
	Artifacts     []Artifact     `json:"artifacts"`
	Warnings      []string       `json:"warnings"`
	RequiredBytes int64          `json:"required_bytes"`
	Change        *SettingChange `json:"change,omitempty"`
	fingerprint   string
	setting       string
	enabled       bool
}

type Job struct {
	ID         string     `json:"id"`
	Component  string     `json:"component"`
	Version    string     `json:"version"`
	Phase      string     `json:"phase"`
	Started    time.Time  `json:"started"`
	Finished   *time.Time `json:"finished,omitempty"`
	Error      string     `json:"error,omitempty"`
	BackupID   string     `json:"backup_id,omitempty"`
	RolledBack bool       `json:"rolled_back"`
}

type GeoSettings struct {
	Sources     []string `json:"sources"`
	Auto        bool     `json:"auto"`
	Day         int      `json:"day"` // -1 daily; 0 Sunday through 6 Saturday
	Hour        int      `json:"hour"`
	Minute      int      `json:"minute"`
	LastAttempt string   `json:"last_attempt,omitempty"`
}

type State struct {
	Supported    bool        `json:"supported"`
	Reason       string      `json:"reason,omitempty"`
	Architecture string      `json:"architecture"`
	XKeenVersion string      `json:"xkeen_version"`
	XrayVersion  string      `json:"xray_version"`
	Core         string      `json:"core"`
	RouterTime   string      `json:"router_time"`
	Geodata      GeoSettings `json:"geodata"`
	Sources      []GeoSource `json:"sources"`
	Job          *Job        `json:"job,omitempty"`
	Backups      []Backup    `json:"backups"`
	Notes        []string    `json:"notes"`
	Settings     []Setting   `json:"settings"`
	Mode         string      `json:"mode"`
}

type catalogCache struct {
	at       time.Time
	releases []Release
}
type Manager struct {
	opts    Options
	client  *http.Client
	apiBase string
	mu      sync.Mutex
	plans   map[string]Plan
	catalog map[string]catalogCache
	job     *Job
	geo     GeoSettings
}

func New(opts Options) *Manager {
	if opts.GOOS == "" {
		opts.GOOS = runtime.GOOS
	}
	if opts.GOARCH == "" {
		opts.GOARCH = runtime.GOARCH
	}
	if opts.FreeBytes == nil {
		opts.FreeBytes = freeBytes
	}
	if opts.Running == nil {
		opts.Running = func() bool { return true }
	}
	if opts.Lock == nil {
		opts.Lock = func() {}
	}
	if opts.Unlock == nil {
		opts.Unlock = func() {}
	}
	m := &Manager{opts: opts, apiBase: strings.TrimSuffix(opts.APIBase, "/"), plans: map[string]Plan{}, catalog: map[string]catalogCache{}, geo: GeoSettings{Sources: []string{}, Day: -1, Hour: 4}}
	if m.apiBase == "" {
		m.apiBase = "https://api.github.com"
	}
	c := http.Client{Timeout: 3 * time.Minute}
	if opts.Client != nil {
		c = *opts.Client
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || !m.allowedURL(req.URL) {
			return fmt.Errorf("перенаправление загрузки отклонено")
		}
		req.Header.Del("Authorization")
		req.Header.Del("Cookie")
		return nil
	}
	m.client = &c
	var saved GeoSettings
	if b, e := os.ReadFile(m.settingsPath()); e == nil && json.Unmarshal(b, &saved) == nil && validateGeo(saved) == nil {
		m.geo = saved
	}
	if pending, e := m.readPending(); e == nil {
		job := pending.Job
		job.Phase = "recovering"
		job.Finished = nil
		m.job = &job
	}
	return m
}

func (m *Manager) path(path string) string {
	if m.opts.Root == "" {
		return path
	}
	return filepath.Join(m.opts.Root, path)
}
func (m *Manager) settingsPath() string { return filepath.Join(m.opts.DataDir, "components.json") }
func (m *Manager) backupRoot() string   { return filepath.Join(m.opts.DataDir, "component-backups") }
func randomID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
func (m *Manager) runtime() xkeen.Runtime {
	if m.opts.Runtime == nil {
		return xkeen.Runtime{}
	}
	return m.opts.Runtime()
}

func (m *Manager) support() string {
	rt := m.runtime()
	if m.opts.GOOS != "linux" && !m.opts.TestHTTP {
		return "управление компонентами доступно только на Linux-роутере"
	}
	if m.opts.GOARCH != "arm64" && m.opts.GOARCH != "mipsle" {
		return "для этой архитектуры нет проверенного адаптера"
	}
	if !rt.Installed || rt.Core != xkeen.CoreXray {
		return "нужен установленный XKeen с активным Xray"
	}
	if rt.Generation != 2 {
		return "управление версиями поддерживается для XKeen 2.x"
	}
	if m.opts.Restart == nil {
		return "не настроен безопасный перезапуск и восстановление выбора сервера"
	}
	return ""
}

func (m *Manager) State() State {
	rt := m.runtime()
	reason := m.support()
	state := State{Supported: reason == "", Reason: reason, Architecture: m.opts.GOARCH, XKeenVersion: rt.Version, XrayVersion: m.binaryVersion(rt.CoreBin), Core: rt.Core, RouterTime: time.Now().Format(time.RFC3339), Sources: GeoSources(), Backups: []Backup{}, Notes: []string{"Версии XKeen/Xray и обновления панели — отдельные операции.", "Перед изменением создаётся локальная резервная копия; конфигурация, подписка и исключения сохраняются.", "GeoIPSET исключает адреса до Xray. Управляйте этими исключениями осознанно в расширенных настройках."}}
	state.Settings = m.Settings()
	state.Mode = rt.Mode
	m.mu.Lock()
	state.Geodata = m.geo
	state.Geodata.Sources = append([]string{}, m.geo.Sources...)
	if m.job != nil {
		j := *m.job
		state.Job = &j
	}
	m.mu.Unlock()
	backups, _ := m.backups()
	state.Backups = backups
	return state
}

func (m *Manager) binaryVersion(bin string) string {
	if bin == "" {
		return "не определена"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, bin, "version").Output()
	if e != nil {
		return "не определена"
	}
	match := regexp.MustCompile(`(?i)Xray\s+([0-9][A-Za-z0-9.+-]*)`).FindSubmatch(b)
	if len(match) == 2 {
		return string(match[1])
	}
	return "не определена"
}

func (m *Manager) fingerprint() (string, error) {
	return configFingerprint(m.runtime(), m.settingsPath())
}

func (m *Manager) Preview(ctx context.Context, req PlanRequest) (Plan, error) {
	if _, e := os.Stat(m.pendingPath()); e == nil {
		return Plan{}, fmt.Errorf("сначала дождитесь восстановления прерванной операции или выполните управляемое восстановление из резервной копии")
	}
	if reason := m.support(); reason != "" {
		return Plan{}, fmt.Errorf("%s", reason)
	}
	m.mu.Lock()
	busy := m.job != nil && m.job.Finished == nil
	m.mu.Unlock()
	if busy {
		return Plan{}, fmt.Errorf("другая операция ещё выполняется")
	}
	plan := Plan{ID: randomID(), Component: req.Component, Version: req.Version, Expires: time.Now().Add(10 * time.Minute), Artifacts: []Artifact{}, Warnings: []string{"Если VPN запущен, он кратко перезапустится. Выбранный сервер и правила будут восстановлены."}}
	if plan.ID == "" {
		return Plan{}, fmt.Errorf("не удалось подготовить операцию")
	}
	if req.Component == "settings" {
		if req.Enabled == nil {
			return Plan{}, fmt.Errorf("укажите новое состояние")
		}
		setting, ok := m.setting(req.Setting)
		if ok && setting.ID == "native_geodata_schedule" && *req.Enabled {
			return Plan{}, fmt.Errorf("через панель можно только отключить штатное расписание XKeen; для автообновления используйте расписание геобаз панели")
		}
		if !ok || !setting.Supported {
			return Plan{}, fmt.Errorf("параметр не поддерживается этой версией XKeen")
		}
		plan.Version = setting.Name
		if *req.Enabled {
			plan.Version += " — включить"
		} else {
			plan.Version += " — выключить"
		}
		plan.setting = req.Setting
		plan.enabled = *req.Enabled
		change := DescribeSettingChange(setting, *req.Enabled)
		plan.Change = &change
		if req.Setting == "ipv6" {
			plan.Warnings = append(plan.Warnings, "IPv6 изменится для всего роутера. Это может повлиять на другие устройства домашней сети.")
		}
	} else if req.Component == "geodata" {
		m.mu.Lock()
		sources := append([]string{}, m.geo.Sources...)
		m.mu.Unlock()
		if len(sources) == 0 {
			return Plan{}, fmt.Errorf("сначала выберите источники геобаз")
		}
		plan.Version = "выбранные источники"
		for _, id := range sources {
			source, _ := geoSource(id)
			release, e := m.latestRelease(ctx, source.Repository)
			if e != nil {
				return Plan{}, e
			}
			artifact, e := m.resolveArtifact(ctx, source.Repository, release, source.Asset, source.Filename)
			if e != nil {
				return Plan{}, e
			}
			plan.Artifacts = append(plan.Artifacts, artifact)
			if source.Kind == "GeoIPSET" {
				plan.Warnings = append(plan.Warnings, "Выбран GeoIPSET: российские адреса будут обходить Xray и его доменные VPN-правила на уровне перехвата XKeen.")
			}
		}
		plan.Warnings = append(plan.Warnings, "Обновляются только выбранные базы. Другие установленные базы не удаляются.")
	} else {
		repo, e := officialRepo(req.Component)
		if e != nil {
			return Plan{}, e
		}
		release, e := m.release(ctx, repo, req.Version)
		if e != nil {
			return Plan{}, e
		}
		name, target := "xkeen.tar.gz", "xkeen"
		if req.Component == "xray" {
			target = "xray"
			name = "Xray-linux-arm64-v8a.zip"
			if m.opts.GOARCH == "mipsle" {
				name = "Xray-linux-mips32le.zip"
			}
		}
		if req.Component == "xkeen" {
			if !supportedXkeenTag(req.Version) {
				return Plan{}, fmt.Errorf("для выбранной версии XKeen нет проверенного адаптера обновления (поддерживаются ветки 2.0 и 2.1)")
			}
			firmware := ""
			if m.opts.Firmware != nil {
				firmware = m.opts.Firmware()
			}
			if !xkeenHasTokenSupport(req.Version) {
				if firmware == "" {
					return Plan{}, fmt.Errorf("не удалось определить KeeneticOS; установка XKeen ниже 2.1 не разрешена без проверки совместимости")
				}
				if firmwareNeedsToken(firmware) {
					return Plan{}, fmt.Errorf("KeeneticOS 5.2 и новее требует XKeen 2.1 или новее с поддержкой RCI-токена")
				}
			}
			plan.Warnings = append(plan.Warnings, "Канал Dev без опубликованного релиза и контрольной суммы не устанавливается; выберите проверяемый релиз или prerelease.")
		}
		artifact, e := m.resolveArtifact(ctx, repo, release, name, target)
		if e != nil {
			return Plan{}, e
		}
		plan.Artifacts = append(plan.Artifacts, artifact)
		if release.Prerelease {
			plan.Warnings = append(plan.Warnings, "Вы выбрали предварительную версию. Она может содержать ошибки.")
		}
	}
	for _, a := range plan.Artifacts {
		plan.RequiredBytes += a.Size * 5
	}
	existing, e := m.snapshotBytes(req.Component)
	if e != nil {
		return Plan{}, fmt.Errorf("не удалось оценить размер резервной копии")
	}
	plan.RequiredBytes += existing * 2
	plan.RequiredBytes += 32 << 20
	free, e := m.opts.FreeBytes(m.opts.DataDir)
	if e != nil {
		return Plan{}, fmt.Errorf("не удалось проверить свободное место")
	}
	if free < uint64(plan.RequiredBytes) {
		return Plan{}, fmt.Errorf("недостаточно места: нужно не менее %d МБ с учётом загрузки и отката", (plan.RequiredBytes+(1<<20)-1)>>20)
	}
	plan.fingerprint, e = m.fingerprint()
	if e != nil {
		return Plan{}, fmt.Errorf("не удалось сохранить состояние конфигурации")
	}
	m.mu.Lock()
	for id, p := range m.plans {
		if time.Now().After(p.Expires) {
			delete(m.plans, id)
		}
	}
	m.plans[plan.ID] = plan
	m.mu.Unlock()
	return plan, nil
}

func supportedXkeenTag(version string) bool {
	return regexp.MustCompile(`^v?2\.[01](?:\.[0-9]+)?(?:[._+-][A-Za-z0-9.-]+)?$`).MatchString(version)
}
func xkeenHasTokenSupport(version string) bool {
	v := strings.TrimPrefix(version, "v")
	var major, minor int
	_, _ = fmt.Sscanf(v, "%d.%d", &major, &minor)
	return major > 2 || major == 2 && minor >= 1
}
func firmwareNeedsToken(version string) bool {
	var major, minor int
	_, _ = fmt.Sscanf(version, "%d.%d", &major, &minor)
	return major > 5 || major == 5 && minor >= 2
}

func (m *Manager) Apply(id string) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.job != nil && m.job.Finished == nil {
		return Job{}, fmt.Errorf("другая операция ещё выполняется")
	}
	plan, ok := m.plans[id]
	if !ok || time.Now().After(plan.Expires) {
		return Job{}, fmt.Errorf("предпросмотр устарел; проверьте операцию снова")
	}
	delete(m.plans, id)
	job := Job{ID: randomID(), Component: plan.Component, Version: plan.Version, Phase: "queued", Started: time.Now()}
	m.job = &job
	go m.apply(plan, job.ID)
	return job, nil
}

func (m *Manager) setPhase(id, phase string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.job != nil && m.job.ID == id {
		m.job.Phase = phase
	}
}
func (m *Manager) finish(id string, err error, backup string, rolledBack bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.job == nil || m.job.ID != id {
		return
	}
	now := time.Now()
	m.job.Finished = &now
	m.job.Phase = "complete"
	m.job.BackupID = backup
	m.job.RolledBack = rolledBack
	if err != nil {
		m.job.Phase = "failed"
		m.job.Error = err.Error()
	}
}

func (m *Manager) apply(plan Plan, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	m.opts.Lock()
	defer m.opts.Unlock()
	wasRunning := m.opts.Running()
	var err error
	backupID := ""
	rolledBack := false
	var transactionBackup *Backup
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("операция прервана внутренней ошибкой; проверьте состояние и резервную копию")
			if transactionBackup != nil {
				restoreErr := m.restoreBackup(*transactionBackup)
				if restoreErr == nil && wasRunning {
					restoreErr = m.opts.Restart(context.Background())
				}
				rolledBack = restoreErr == nil
				if rolledBack {
					_ = os.Remove(m.pendingPath())
				}
			}
		}
		m.finish(id, err, backupID, rolledBack)
	}()
	if time.Now().After(plan.Expires) {
		err = fmt.Errorf("предпросмотр устарел во время ожидания; повторите проверку")
		return
	}
	current, e := m.fingerprint()
	if e != nil || current != plan.fingerprint {
		err = fmt.Errorf("настройки изменились после предпросмотра; повторите проверку")
		return
	}
	if reason := m.support(); reason != "" {
		err = fmt.Errorf("%s", reason)
		return
	}
	work, e := os.MkdirTemp(m.opts.DataDir, ".component-stage-")
	if e != nil {
		err = fmt.Errorf("не удалось подготовить загрузку")
		return
	}
	defer os.RemoveAll(work)
	m.setPhase(id, "download")
	for i, a := range plan.Artifacts {
		if e = m.download(ctx, a, filepath.Join(work, fmt.Sprint(i))); e != nil {
			err = e
			return
		}
	}
	m.setPhase(id, "validate")
	if e = m.preparePayload(ctx, plan, work); e != nil {
		err = e
		return
	}
	backup, e := m.captureBackup(plan.Component, plan.Version)
	if e != nil {
		err = fmt.Errorf("не удалось создать резервную копию")
		return
	}
	backupID = backup.ID
	transactionBackup = &backup
	m.mu.Lock()
	pendingJob := *m.job
	m.mu.Unlock()
	if e = m.writePending(pendingOperation{BackupID: backup.ID, Job: pendingJob, WasRunning: wasRunning}); e != nil {
		err = fmt.Errorf("не удалось сохранить журнал восстановления; файлы не изменены")
		return
	}
	m.setPhase(id, "apply")
	if e = m.installPayload(ctx, plan, work); e == nil {
		if plan.Component == "xkeen" {
			e = m.verifyXkeenPreserved(backup)
		}
	}
	if e == nil {
		e = m.validateCurrent(ctx)
	}
	if e == nil && wasRunning {
		m.setPhase(id, "restart")
		e = m.opts.Restart(ctx)
	}
	if e != nil {
		m.setPhase(id, "rollback")
		restoreErr := m.restoreBackup(backup)
		if restoreErr == nil && wasRunning {
			restoreErr = m.opts.Restart(ctx)
		}
		rolledBack = restoreErr == nil
		if rolledBack {
			_ = os.Remove(m.pendingPath())
		}
		if rolledBack {
			err = fmt.Errorf("обновление не прошло проверку; прежняя версия и настройки восстановлены")
		} else {
			err = fmt.Errorf("обновление не выполнено; автоматическое восстановление не подтверждено, используйте резервную копию %s", backupID)
		}
		return
	}
	if plan.Component == "geodata" {
		m.mu.Lock()
		m.geo.LastAttempt = time.Now().Format("2006-01-02")
		_ = m.saveGeoLocked()
		m.mu.Unlock()
	}
	if e := m.markBackupCurrent(backupID); e != nil {
		err = fmt.Errorf("компонент установлен, но проверка доступности последующего отката не сохранена")
	}
	_ = os.Remove(m.pendingPath())
}

func (m *Manager) Rollback(id string) (Job, error) {
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(id) {
		return Job{}, fmt.Errorf("неверная резервная копия")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.job != nil && m.job.Finished == nil {
		return Job{}, fmt.Errorf("другая операция ещё выполняется")
	}
	backup, e := m.readBackup(id)
	if e != nil {
		return Job{}, fmt.Errorf("резервная копия не найдена")
	}
	current, checkErr := m.fingerprint()
	if checkErr != nil || backup.Fingerprint == "" || current != backup.Fingerprint {
		return Job{}, fmt.Errorf("после этой копии настройки изменились; автоматический откат может затереть новые изменения. Используйте свежую резервную копию или управляемое восстановление")
	}
	job := Job{ID: randomID(), Component: backup.Component, Version: backup.Version, Phase: "rollback", Started: time.Now(), BackupID: id}
	m.job = &job
	go func() {
		m.opts.Lock()
		defer m.opts.Unlock()
		wasRunning := m.opts.Running()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		current, e := m.captureBackup("rollback", backup.Version)
		if e != nil {
			m.finish(job.ID, fmt.Errorf("не удалось сохранить текущее состояние перед откатом"), "", false)
			return
		}
		if e = m.writePending(pendingOperation{BackupID: current.ID, Job: job, WasRunning: wasRunning}); e != nil {
			m.finish(job.ID, fmt.Errorf("журнал восстановления не сохранён; откат отменён"), current.ID, false)
			return
		}
		e = m.restoreBackup(backup)
		if e == nil {
			e = m.validateCurrent(ctx)
		}
		if e == nil && wasRunning {
			e = m.opts.Restart(ctx)
		}
		if e != nil {
			r := m.restoreBackup(current)
			if r == nil && wasRunning {
				r = m.opts.Restart(ctx)
			}
			m.finish(job.ID, fmt.Errorf("откат не прошёл проверку; проверьте резервную копию"), current.ID, r == nil)
			if r == nil {
				_ = os.Remove(m.pendingPath())
			}
			return
		}
		_ = m.markBackupCurrent(current.ID)
		_ = os.Remove(m.pendingPath())
		m.finish(job.ID, nil, current.ID, true)
	}()
	return job, nil
}

func atomicWrite(path string, body []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".component-next-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(body)
	}
	if e2 := f.Close(); e == nil {
		e = e2
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}

func (m *Manager) saveGeoLocked() error {
	b, e := json.MarshalIndent(m.geo, "", "  ")
	if e != nil {
		return e
	}
	return atomicWrite(m.settingsPath(), append(b, '\n'), 0600)
}

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	sort.Strings(result)
	return result
}
