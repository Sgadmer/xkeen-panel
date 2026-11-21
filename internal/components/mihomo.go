package components

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"xkeen-panel/internal/geoip"
	"xkeen-panel/internal/xkeen"
)

// Two things a router with the Mihomo core could not do from the panel:
// refresh the Re:filter block list and change the version of the core.
//
// Neither touches the running core. The block list is a pair of files the card
// controller already watches and imports on its own. A new core binary replaces
// the file on disk only after it has started and accepted the current
// configuration; the running process keeps the previous one until XKeen is
// restarted, and the previous binary stays next to it for a way back.

const (
	mihomoRepo        = "MetaCubeX/mihomo"
	refilterRepo      = "1andrevich/Re-filter-lists"
	refilterInterval  = 24 * time.Hour
	refilterRetry     = 6 * time.Hour
	mihomoMaxBinary   = 200 << 20
	mihomoPrevSuffix  = ".panel-prev"
	refilterMinSites  = 100
	refilterMinRanges = 10
)

var mihomoTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

type mihomoSaved struct {
	RefilterAuto    *bool  `json:"refilter_auto,omitempty"` // unset means on
	RefilterChecked string `json:"refilter_checked,omitempty"`
	RefilterUpdated string `json:"refilter_updated,omitempty"`
	RefilterVersion string `json:"refilter_version,omitempty"`
	RefilterError   string `json:"refilter_error,omitempty"`
	CoreLatest      string `json:"core_latest,omitempty"`
	CoreChecked     string `json:"core_checked,omitempty"`
	CorePrevious    string `json:"core_previous,omitempty"`
}

type mihomoTasks struct {
	saved        mihomoSaved
	loaded       bool
	refilterBusy bool
	coreBusy     bool
	corePhase    string
	coreError    string
}

// RefilterInfo describes the block list files and who refreshes them.
type RefilterInfo struct {
	Supported bool   `json:"supported"`
	Auto      bool   `json:"auto"`
	Busy      bool   `json:"busy"`
	CheckedAt string `json:"checked_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
	Version   string `json:"version,omitempty"`
	// When the files on the router last changed, whoever wrote them.
	FilesChangedAt string `json:"files_changed_at,omitempty"`
	Error          string `json:"error,omitempty"`
}

// CoreInfo describes the Mihomo binary on disk and the one that is running.
type CoreInfo struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	Installed string `json:"installed,omitempty"`
	Latest    string `json:"latest,omitempty"`
	CheckedAt string `json:"checked_at,omitempty"`
	// The file on disk was replaced: the running core is still the earlier one.
	Staged   bool   `json:"staged"`
	Previous string `json:"previous,omitempty"`
	Busy     bool   `json:"busy"`
	Phase    string `json:"phase,omitempty"`
	Error    string `json:"error,omitempty"`
}

func (m *Manager) mihomoPath() string { return filepath.Join(m.opts.DataDir, "mihomo-components.json") }

// The caller holds m.mu.
func (m *Manager) mihomoLoad() *mihomoTasks {
	if !m.tasks.loaded {
		m.tasks.loaded = true
		if raw, err := os.ReadFile(m.mihomoPath()); err == nil {
			_ = json.Unmarshal(raw, &m.tasks.saved)
		}
	}
	return &m.tasks
}

// The caller holds m.mu.
func (m *Manager) mihomoSave() {
	raw, err := json.MarshalIndent(m.tasks.saved, "", "  ")
	if err != nil {
		return
	}
	tmp := m.mihomoPath() + ".tmp"
	if os.WriteFile(tmp, append(raw, '\n'), 0600) == nil {
		_ = os.Rename(tmp, m.mihomoPath())
	}
}

func (m *Manager) mihomoReason() string {
	rt := m.runtime()
	if m.opts.GOOS != "linux" && !m.opts.TestHTTP {
		return "доступно только на роутере"
	}
	if !rt.Installed || rt.Core != xkeen.CoreMihomo {
		return "нужен установленный XKeen с ядром Mihomo"
	}
	return ""
}

func (m *Manager) logf(format string, args ...interface{}) {
	if m.opts.Log != nil {
		m.opts.Log(format, args...)
	}
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// ---- Re:filter ----

func (m *Manager) refilterSources() []GeoSource {
	var sources []GeoSource
	for _, id := range []string{"geosite-refilter", "geoip-refilter"} {
		if source, ok := geoSource(id); ok {
			sources = append(sources, source)
		}
	}
	return sources
}

func (m *Manager) RefilterInfo() RefilterInfo {
	m.mu.Lock()
	tasks := m.mihomoLoad()
	info := RefilterInfo{
		Supported: m.mihomoReason() == "", Auto: tasks.saved.RefilterAuto == nil || *tasks.saved.RefilterAuto, Busy: tasks.refilterBusy,
		CheckedAt: tasks.saved.RefilterChecked, UpdatedAt: tasks.saved.RefilterUpdated, Version: tasks.saved.RefilterVersion, Error: tasks.saved.RefilterError,
	}
	m.mu.Unlock()
	// The older of the two files tells how fresh the pair is.
	var oldest time.Time
	for _, source := range m.refilterSources() {
		file, err := os.Stat(m.geodataPath(source))
		if err != nil || !file.Mode().IsRegular() {
			return info
		}
		if oldest.IsZero() || file.ModTime().Before(oldest) {
			oldest = file.ModTime()
		}
	}
	if !oldest.IsZero() {
		info.FilesChangedAt = stamp(oldest)
	}
	return info
}

func (m *Manager) SetRefilterAuto(auto bool) RefilterInfo {
	m.mu.Lock()
	tasks := m.mihomoLoad()
	tasks.saved.RefilterAuto = &auto
	m.mihomoSave()
	m.mu.Unlock()
	return m.RefilterInfo()
}

// StartRefilterUpdate downloads the current block list in the background.
func (m *Manager) StartRefilterUpdate() (RefilterInfo, error) {
	if reason := m.mihomoReason(); reason != "" {
		return m.RefilterInfo(), errors.New(reason)
	}
	m.mu.Lock()
	tasks := m.mihomoLoad()
	if tasks.refilterBusy {
		m.mu.Unlock()
		return m.RefilterInfo(), nil
	}
	tasks.refilterBusy = true
	m.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		version, changed, err := m.refilterUpdate(ctx)
		m.mu.Lock()
		tasks := m.mihomoLoad()
		tasks.refilterBusy = false
		tasks.saved.RefilterChecked = stamp(time.Now())
		tasks.saved.RefilterError = ""
		if err != nil {
			tasks.saved.RefilterError = err.Error()
		} else {
			tasks.saved.RefilterVersion = version
			if changed {
				tasks.saved.RefilterUpdated = tasks.saved.RefilterChecked
			}
		}
		m.mihomoSave()
		m.mu.Unlock()
		switch {
		case err != nil:
			m.logf("[COMPONENTS] Список блокировок Re:filter не обновлён: %v", err)
		case changed:
			m.logf("[COMPONENTS] Список блокировок Re:filter обновлён до выпуска %s", version)
		}
	}()
	return m.RefilterInfo(), nil
}

// refilterUpdate replaces both files together, or neither.
func (m *Manager) refilterUpdate(ctx context.Context) (version string, changed bool, err error) {
	sources := m.refilterSources()
	if len(sources) != 2 {
		return "", false, errors.New("источник Re:filter не описан")
	}
	release, err := m.latestRelease(ctx, refilterRepo)
	if err != nil {
		return "", false, err
	}
	targets := make([]string, len(sources))
	for i, source := range sources {
		if targets[i], err = m.geodataWritePath(source); err != nil {
			return "", false, err
		}
	}
	dir := filepath.Dir(targets[0])
	if err = os.MkdirAll(dir, 0755); err != nil {
		return "", false, err
	}
	work, err := os.MkdirTemp(dir, ".panel-refilter-")
	if err != nil {
		return "", false, err
	}
	defer os.RemoveAll(work)
	fresh := make([]string, len(sources))
	same := true
	for i, source := range sources {
		artifact, err := m.resolveArtifact(ctx, refilterRepo, release, source.Asset, source.Filename)
		if err != nil {
			return "", false, err
		}
		fresh[i] = filepath.Join(work, source.Filename)
		if err = m.download(ctx, artifact, fresh[i]); err != nil {
			return "", false, err
		}
		same = same && fileSHA(targets[i]) == artifact.SHA256
	}
	if same {
		return release.Version, false, nil
	}
	// The files must be what the card controller can read, and not a fraction
	// of what is installed: a truncated upload must not shrink the list.
	for i, source := range sources {
		domains := source.Kind == "GeoSite"
		least := refilterMinRanges
		if domains {
			least = refilterMinSites
		}
		parsed, err := geoip.ReadRefilter(fresh[i], domains)
		if err != nil || parsed.Count < least {
			return "", false, errors.New("скачанный список Re:filter не читается; прежние файлы сохранены")
		}
		if current, err := geoip.ReadRefilter(targets[i], domains); err == nil && parsed.Count*2 < current.Count {
			return "", false, errors.New("скачанный список Re:filter вдвое короче установленного; прежние файлы сохранены")
		}
	}
	replaced := 0
	for i := range sources {
		if err = replaceKeeping(fresh[i], targets[i], targets[i]+mihomoPrevSuffix); err != nil {
			break
		}
		replaced++
	}
	if err != nil {
		// Put back what was already replaced: the pair must stay consistent.
		for i := 0; i < replaced; i++ {
			_ = os.Rename(targets[i]+mihomoPrevSuffix, targets[i])
		}
		return "", false, errors.New("не удалось заменить файлы Re:filter; прежние файлы сохранены")
	}
	return release.Version, true, nil
}

func fileSHA(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// replaceKeeping puts fresh in place of target in one step and leaves the
// previous content at kept. A reader never sees a missing or half-written file.
func replaceKeeping(fresh, target, kept string) error {
	_ = os.Remove(kept)
	if _, err := os.Lstat(target); err == nil {
		if err = os.Link(target, kept); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Chmod(fresh, 0644); err != nil {
		return err
	}
	return os.Rename(fresh, target)
}

// StartMihomo keeps the block list fresh while the owner allows it.
func (m *Manager) StartMihomo(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		m.refilterTick(time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *Manager) refilterTick(now time.Time) {
	if m.mihomoReason() != "" {
		return
	}
	m.mu.Lock()
	tasks := m.mihomoLoad()
	auto := tasks.saved.RefilterAuto == nil || *tasks.saved.RefilterAuto
	checked, _ := time.Parse(time.RFC3339, tasks.saved.RefilterChecked)
	wait := refilterInterval
	if tasks.saved.RefilterError != "" {
		wait = refilterRetry
	}
	due := auto && !tasks.refilterBusy && now.Sub(checked) >= wait
	m.mu.Unlock()
	if due {
		_, _ = m.StartRefilterUpdate()
	}
}

// ---- The Mihomo binary ----

func (m *Manager) coreBin() string { return m.runtime().CoreBin }

func (m *Manager) coreVersion(ctx context.Context, bin string) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-v").Output()
	if err != nil {
		return ""
	}
	return string(regexp.MustCompile(`v[0-9]+\.[0-9]+\.[0-9]+`).Find(out))
}

// coreStale reports whether the running core was started from a binary that
// has since been replaced on disk.
func coreStale(bin string) bool {
	entries, _ := filepath.Glob("/proc/[0-9]*/exe")
	for _, entry := range entries {
		if link, err := os.Readlink(entry); err == nil && link == bin+" (deleted)" {
			return true
		}
	}
	return false
}

func (m *Manager) CoreInfo(ctx context.Context) CoreInfo {
	reason := m.mihomoReason()
	if reason == "" && m.opts.GOARCH != "arm64" && m.opts.GOARCH != "mipsle" {
		reason = "для этой архитектуры выпуски Mihomo не подбираются"
	}
	info := CoreInfo{Supported: reason == "", Reason: reason}
	bin := m.coreBin()
	if reason == "" {
		info.Installed = m.coreVersion(ctx, bin)
		info.Staged = coreStale(bin)
	}
	m.mu.Lock()
	tasks := m.mihomoLoad()
	info.Latest, info.CheckedAt = tasks.saved.CoreLatest, tasks.saved.CoreChecked
	info.Busy, info.Phase, info.Error = tasks.coreBusy, tasks.corePhase, tasks.coreError
	previous := tasks.saved.CorePrevious
	m.mu.Unlock()
	if previous != "" && reason == "" {
		if file, err := os.Stat(bin + mihomoPrevSuffix); err == nil && file.Mode().IsRegular() {
			info.Previous = previous
		}
	}
	return info
}

// CoreCheck asks the official repository for its latest stable release.
func (m *Manager) CoreCheck(ctx context.Context) (CoreInfo, error) {
	if reason := m.mihomoReason(); reason != "" {
		return m.CoreInfo(ctx), errors.New(reason)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	release, err := m.latestRelease(ctx, mihomoRepo)
	if err == nil && (!mihomoTag.MatchString(release.Version) || release.Prerelease) {
		err = errors.New("последний выпуск Mihomo не является стабильной версией")
	}
	m.mu.Lock()
	tasks := m.mihomoLoad()
	if err == nil {
		tasks.saved.CoreLatest, tasks.saved.CoreChecked = release.Version, stamp(time.Now())
		tasks.coreError = ""
		m.mihomoSave()
	}
	m.mu.Unlock()
	return m.CoreInfo(ctx), err
}

func mihomoAsset(goarch, version string) string {
	switch goarch {
	case "arm64":
		return "mihomo-linux-arm64-" + version + ".gz"
	case "mipsle":
		return "mihomo-linux-mipsle-softfloat-" + version + ".gz"
	}
	return ""
}

// StartCoreInstall downloads, checks and puts a Mihomo release on disk in the
// background. The running core is not interrupted.
func (m *Manager) StartCoreInstall(version string) (CoreInfo, error) {
	ctx := context.Background()
	if info := m.CoreInfo(ctx); !info.Supported {
		return info, errors.New(info.Reason)
	}
	if !mihomoTag.MatchString(version) {
		return m.CoreInfo(ctx), errors.New("укажите версию вида v1.19.0")
	}
	m.mu.Lock()
	tasks := m.mihomoLoad()
	if tasks.coreBusy {
		m.mu.Unlock()
		return m.CoreInfo(ctx), errors.New("дождитесь завершения текущей операции")
	}
	tasks.coreBusy, tasks.corePhase, tasks.coreError = true, "download", ""
	m.mu.Unlock()
	go func() {
		work, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		previous, err := m.coreInstall(work, version)
		m.mu.Lock()
		tasks := m.mihomoLoad()
		tasks.coreBusy, tasks.corePhase = false, ""
		if err != nil {
			tasks.coreError = err.Error()
		} else {
			tasks.saved.CorePrevious = previous
			m.mihomoSave()
		}
		m.mu.Unlock()
		if err != nil {
			m.logf("[COMPONENTS] Mihomo %s не установлен: %v", version, err)
		} else {
			m.logf("[COMPONENTS] Mihomo %s записан на диск (был %s); начнёт работать после перезапуска XKeen", version, previous)
		}
	}()
	return m.CoreInfo(ctx), nil
}

func (m *Manager) corePhase(phase string) {
	m.mu.Lock()
	m.mihomoLoad().corePhase = phase
	m.mu.Unlock()
}

func (m *Manager) coreInstall(ctx context.Context, version string) (previous string, err error) {
	bin := m.coreBin()
	if info, statErr := os.Lstat(bin); statErr != nil || !info.Mode().IsRegular() {
		return "", errors.New("файл ядра Mihomo не найден или это не обычный файл")
	}
	previous = m.coreVersion(ctx, bin)
	if previous == version {
		return "", errors.New("эта версия уже установлена")
	}
	release, err := m.release(ctx, mihomoRepo, version)
	if err != nil {
		return "", err
	}
	if release.Prerelease {
		return "", errors.New("предварительные выпуски Mihomo не устанавливаются")
	}
	name := mihomoAsset(m.opts.GOARCH, version)
	artifact, err := m.resolveArtifact(ctx, mihomoRepo, release, name, filepath.Base(bin))
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(bin)
	// The archive, the unpacked binary and the kept previous one share the disk.
	if free, freeErr := m.opts.FreeBytes(dir); freeErr != nil || free < uint64(artifact.Size)*8+(64<<20) {
		return "", errors.New("на диске роутера недостаточно места для новой версии и резервной копии")
	}
	work, err := os.MkdirTemp(dir, ".panel-mihomo-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	archive, fresh := filepath.Join(work, name), filepath.Join(work, "mihomo")
	if err = m.download(ctx, artifact, archive); err != nil {
		return "", err
	}
	m.corePhase("validate")
	if err = gunzipFile(archive, fresh, mihomoMaxBinary); err != nil {
		return "", errors.New("архив Mihomo не распаковался")
	}
	if err = os.Chmod(fresh, 0755); err != nil {
		return "", err
	}
	if got := m.coreVersion(ctx, fresh); got != version {
		return "", fmt.Errorf("скачанный файл не запускается на этом роутере или сообщает другую версию (%q)", got)
	}
	if err = m.coreAccepts(ctx, fresh); err != nil {
		return "", err
	}
	m.corePhase("apply")
	if err = replaceKeeping(fresh, bin, bin+mihomoPrevSuffix); err != nil {
		return "", errors.New("не удалось заменить файл ядра; прежняя версия сохранена")
	}
	_ = os.Chmod(bin, 0755)
	return previous, nil
}

// coreAccepts runs the binary's own configuration test on the live profile.
func (m *Manager) coreAccepts(ctx context.Context, bin string) error {
	if m.opts.Validate != nil {
		return m.opts.Validate(ctx, bin)
	}
	config := m.runtime().MihomoConf
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if _, err := m.run(ctx, bin, "-t", "-d", filepath.Dir(config), "-f", config); err != nil {
		return errors.New("эта версия Mihomo не приняла текущую конфигурацию; прежняя версия сохранена")
	}
	return nil
}

func gunzipFile(archive, target string, limit int64) error {
	source, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer source.Close()
	reader, err := gzip.NewReader(source)
	if err != nil {
		return err
	}
	defer reader.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(out, io.LimitReader(reader, limit+1))
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil || written == 0 || written > limit {
		_ = os.Remove(target)
		return errors.New("архив повреждён или слишком велик")
	}
	return nil
}

// CoreRollback puts the kept previous binary back on disk. Like an install it
// takes effect at the next restart of XKeen.
func (m *Manager) CoreRollback(ctx context.Context) (CoreInfo, error) {
	info := m.CoreInfo(ctx)
	if !info.Supported {
		return info, errors.New(info.Reason)
	}
	if info.Busy {
		return info, errors.New("дождитесь завершения текущей операции")
	}
	bin := m.coreBin()
	kept := bin + mihomoPrevSuffix
	if info.Previous == "" {
		return info, errors.New("предыдущей версии Mihomo на диске нет")
	}
	if got := m.coreVersion(ctx, kept); got != info.Previous {
		return info, errors.New("сохранённая предыдущая версия не запускается; откат отменён")
	}
	if err := m.coreAccepts(ctx, kept); err != nil {
		return info, errors.New("предыдущая версия Mihomo не приняла текущую конфигурацию; откат отменён")
	}
	if err := os.Rename(kept, bin); err != nil {
		return info, errors.New("не удалось вернуть предыдущую версию")
	}
	m.mu.Lock()
	tasks := m.mihomoLoad()
	tasks.saved.CorePrevious, tasks.coreError = "", ""
	m.mihomoSave()
	m.mu.Unlock()
	m.logf("[COMPONENTS] На диск возвращён Mihomo %s; начнёт работать после перезапуска XKeen", info.Previous)
	return m.CoreInfo(ctx), nil
}
