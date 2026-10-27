package components

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"xkeen-panel/internal/xkeen"
)

type Backup struct {
	ID          string            `json:"id"`
	Component   string            `json:"component"`
	Version     string            `json:"version"`
	Created     time.Time         `json:"created"`
	Entries     []backupEntry     `json:"-"`
	Kernel      map[string]string `json:"-"`
	Fingerprint string            `json:"-"`
}
type backupEntry struct {
	Path      string            `json:"path"`
	Exists    bool              `json:"exists"`
	Mode      uint32            `json:"mode"`
	Directory bool              `json:"directory"`
	Hashes    map[string]string `json:"hashes"`
}
type backupDocument struct {
	ID          string            `json:"id"`
	Component   string            `json:"component"`
	Version     string            `json:"version"`
	Created     time.Time         `json:"created"`
	Entries     []backupEntry     `json:"entries"`
	Kernel      map[string]string `json:"kernel,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty"`
}

func (m *Manager) managedPaths(component string) []string {
	rt := m.runtime()
	paths := []string{rt.XrayConfDir, filepath.Join(m.opts.DataDir, "pool.json"), filepath.Join(m.opts.DataDir, "subscription.json"), filepath.Join(m.opts.DataDir, "routing-mode.json"), filepath.Join(m.opts.DataDir, "exclusions.json")}
	switch component {
	case "geodata":
		for _, source := range GeoSources() {
			paths = append(paths, m.geodataPath(source))
		}
	case "xray":
		paths = append(paths, rt.CoreBin)
	case "xkeen", "rollback", "settings":
		paths = append(paths, rt.CoreBin, rt.Dispatcher, filepath.Join(filepath.Dir(rt.Dispatcher), ".xkeen"), rt.InitScript, filepath.Dir(rt.XkeenJSON))
		for _, p := range []string{"/opt/etc/init.d/S24xray", "/opt/etc/init.d/S99xkeen", "/opt/etc/init.d/S99xkeenstart", "/opt/etc/init.d/S05crond", "/opt/var/spool/cron/crontabs/root", "/opt/lib/opkg/status", "/opt/lib/opkg/info/xkeen.control", "/opt/lib/opkg/info/xkeen.list", "/opt/etc/ndm/netfilter.d/proxy.sh", "/opt/etc/ndm/schedule.d/00-xkeen-hotspot-sync.sh"} {
			paths = append(paths, m.path(p))
		}
		for _, source := range GeoSources() {
			paths = append(paths, m.geodataPath(source))
		}
	}
	result := []string{}
	for _, p := range paths {
		if p != "" && p != "." {
			result = append(result, filepath.Clean(p))
		}
	}
	return sortedUnique(result)
}

func (m *Manager) snapshotBytes(component string) (int64, error) {
	var size int64
	for _, root := range m.managedPaths(component) {
		if _, e := os.Lstat(root); os.IsNotExist(e) {
			continue
		} else if e != nil {
			return 0, e
		}
		e := filepath.Walk(root, func(path string, info os.FileInfo, e error) error {
			if e != nil {
				return e
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("неподдерживаемая ссылка")
			}
			if !info.IsDir() {
				if !info.Mode().IsRegular() {
					return fmt.Errorf("необычный файл")
				}
				size += info.Size()
			}
			return nil
		})
		if e != nil {
			return 0, e
		}
	}
	return size, nil
}

func regularCopy(source, destination string) (map[string]string, error) {
	result := map[string]string{}
	info, e := os.Lstat(source)
	if e != nil {
		return nil, e
	}
	copyFile := func(src, dst, key string, info os.FileInfo) error {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("необычный файл в управляемой конфигурации")
		}
		b, e := os.ReadFile(src)
		if e != nil {
			return e
		}
		if e = atomicWrite(dst, b, info.Mode().Perm()); e != nil {
			return e
		}
		sum := sha256.Sum256(b)
		result[key] = hex.EncodeToString(sum[:])
		return nil
	}
	if !info.IsDir() {
		return result, copyFile(source, destination, ".", info)
	}
	if e = os.MkdirAll(destination, 0700); e != nil {
		return nil, e
	}
	e = filepath.Walk(source, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("символьная ссылка в управляемой конфигурации")
		}
		relative, e := filepath.Rel(source, path)
		if e != nil {
			return e
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		return copyFile(path, target, filepath.ToSlash(relative), info)
	})
	return result, e
}

func verifyBackupPayload(path string, entry backupEntry) error {
	if !entry.Exists {
		return nil
	}
	for relative, wanted := range entry.Hashes {
		if relative != "." && (!safeRelative(relative) || strings.Contains(relative, ":")) {
			return fmt.Errorf("повреждена резервная копия")
		}
		target := path
		if relative != "." {
			target = filepath.Join(path, filepath.FromSlash(relative))
		}
		b, e := os.ReadFile(target)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != wanted {
			return fmt.Errorf("резервная копия повреждена")
		}
	}
	return nil
}

func (m *Manager) captureBackup(component, version string) (Backup, error) {
	b := Backup{ID: randomID(), Component: component, Version: version, Created: time.Now(), Entries: []backupEntry{}}
	if b.ID == "" {
		return b, fmt.Errorf("не удалось создать идентификатор резервной копии")
	}
	dir := filepath.Join(m.backupRoot(), b.ID)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return b, e
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(dir)
		}
	}()
	for i, path := range m.managedPaths(component) {
		entry := backupEntry{Path: path, Hashes: map[string]string{}}
		info, e := os.Lstat(path)
		if e != nil && !os.IsNotExist(e) {
			return b, e
		}
		if e == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return b, fmt.Errorf("символьная ссылка вместо управляемого файла")
			}
			entry.Exists = true
			entry.Mode = uint32(info.Mode().Perm())
			entry.Directory = info.IsDir()
			entry.Hashes, e = regularCopy(path, filepath.Join(dir, fmt.Sprint(i)))
			if e != nil {
				return b, e
			}
		}
		b.Entries = append(b.Entries, entry)
	}
	b.Kernel = m.kernelIPv6()
	doc := backupDocument{ID: b.ID, Component: b.Component, Version: b.Version, Created: b.Created, Entries: b.Entries, Kernel: b.Kernel}
	raw, e := json.MarshalIndent(doc, "", "  ")
	if e != nil {
		return b, e
	}
	if e = atomicWrite(filepath.Join(dir, "manifest.json"), raw, 0600); e != nil {
		return b, e
	}
	for i, entry := range b.Entries {
		if e = verifyBackupPayload(filepath.Join(dir, fmt.Sprint(i)), entry); e != nil {
			return b, e
		}
	}
	success = true
	return b, nil
}

func (m *Manager) readBackup(id string) (Backup, error) {
	raw, e := os.ReadFile(filepath.Join(m.backupRoot(), id, "manifest.json"))
	if e != nil {
		return Backup{}, e
	}
	var doc backupDocument
	if json.Unmarshal(raw, &doc) != nil || doc.ID != id || len(doc.Entries) > 100 {
		return Backup{}, fmt.Errorf("резервная копия повреждена")
	}
	allowed := map[string]bool{}
	for _, p := range m.managedPaths("rollback") {
		allowed[p] = true
	}
	seen := map[string]bool{}
	for _, entry := range doc.Entries {
		if !allowed[entry.Path] || seen[entry.Path] {
			return Backup{}, fmt.Errorf("резервная копия содержит неизвестный путь")
		}
		seen[entry.Path] = true
	}
	return Backup{ID: doc.ID, Component: doc.Component, Version: doc.Version, Created: doc.Created, Entries: doc.Entries, Kernel: doc.Kernel, Fingerprint: doc.Fingerprint}, nil
}

func (m *Manager) markBackupCurrent(id string) error {
	b, e := m.readBackup(id)
	if e != nil {
		return e
	}
	fingerprint, e := m.fingerprint()
	if e != nil {
		return e
	}
	doc := backupDocument{ID: b.ID, Component: b.Component, Version: b.Version, Created: b.Created, Entries: b.Entries, Kernel: b.Kernel, Fingerprint: fingerprint}
	raw, e := json.MarshalIndent(doc, "", "  ")
	if e != nil {
		return e
	}
	return atomicWrite(filepath.Join(m.backupRoot(), id, "manifest.json"), raw, 0600)
}

func (m *Manager) backups() ([]Backup, error) {
	dirs, e := os.ReadDir(m.backupRoot())
	if os.IsNotExist(e) {
		return []Backup{}, nil
	}
	if e != nil {
		return nil, e
	}
	result := []Backup{}
	for _, dir := range dirs {
		if dir.IsDir() && len(dir.Name()) == 32 {
			if b, e := m.readBackup(dir.Name()); e == nil {
				result = append(result, b)
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Created.After(result[j].Created) })
	if len(result) > 10 {
		result = result[:10]
	}
	return result, nil
}

func (m *Manager) restoreBackup(backup Backup) error {
	// All targets are recorded before mutation and checked against the fixed
	// managed allowlist. Never derive a deletion path from a browser parameter.
	validated, e := m.readBackup(backup.ID)
	if e != nil {
		return e
	}
	dir := filepath.Join(m.backupRoot(), backup.ID)
	for i, entry := range validated.Entries {
		if e = verifyBackupPayload(filepath.Join(dir, fmt.Sprint(i)), entry); e != nil {
			return e
		}
	}
	for i, entry := range validated.Entries {
		if entry.Directory && entry.Exists {
			if info, e := os.Lstat(entry.Path); e == nil && info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("путь изменился после резервирования")
			}
			if e = os.RemoveAll(entry.Path); e != nil {
				return e
			}
			if _, e = regularCopy(filepath.Join(dir, fmt.Sprint(i)), entry.Path); e != nil {
				return e
			}
			_ = os.Chmod(entry.Path, os.FileMode(entry.Mode))
		} else if entry.Exists {
			body, e := os.ReadFile(filepath.Join(dir, fmt.Sprint(i)))
			if e != nil {
				return e
			}
			if e = atomicWrite(entry.Path, body, os.FileMode(entry.Mode)); e != nil {
				return e
			}
		} else {
			if info, e := os.Lstat(entry.Path); e == nil {
				if info.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("путь изменился после резервирования")
				}
				if e = os.RemoveAll(entry.Path); e != nil {
					return e
				}
			}
		}
	}
	return m.restoreKernelIPv6(validated.Kernel)
}

func configFingerprint(rt xkeen.Runtime, settings string) (string, error) {
	h := sha256.New()
	files := xkeen.ConfigFiles(rt)
	files = append(files, settings, rt.Dispatcher, rt.CoreBin, rt.InitScript)
	for _, path := range sortedUnique(files) {
		if path == "" {
			continue
		}
		body, e := os.ReadFile(path)
		if os.IsNotExist(e) {
			h.Write([]byte(path + "\x00missing\x00"))
			continue
		}
		if e != nil {
			return "", e
		}
		h.Write([]byte(path + "\x00"))
		h.Write(body)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func safeRelative(name string) bool {
	return name != "" && !strings.Contains(name, "\\") && !strings.HasPrefix(name, "/") && filepath.Clean(filepath.FromSlash(name)) != ".." && !strings.HasPrefix(filepath.Clean(filepath.FromSlash(name)), ".."+string(filepath.Separator))
}

func (m *Manager) preparePayload(ctx context.Context, plan Plan, work string) error {
	if plan.Component == "settings" {
		return nil
	}
	if plan.Component == "geodata" {
		for i, a := range plan.Artifacts {
			st, e := os.Stat(filepath.Join(work, fmt.Sprint(i)))
			if e != nil || st.Size() != a.Size {
				return fmt.Errorf("геобаза повреждена")
			}
			if source, ok := sourceForFilename(a.Target); ok && source.Kind == "GeoIPSET" {
				body, e := os.ReadFile(filepath.Join(work, fmt.Sprint(i)))
				if e != nil {
					return e
				}
				valid := 0
				for _, line := range strings.Split(string(body), "\n") {
					value := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
					if value == "" {
						continue
					}
					var address netip.Addr
					if prefix, e := netip.ParsePrefix(value); e == nil {
						address = prefix.Addr()
					} else if a, e := netip.ParseAddr(value); e == nil {
						address = a
					} else {
						return fmt.Errorf("GeoIPSET содержит неверный IP или подсеть")
					}
					if source.ID == "geoipset-ru4" && !address.Is4() || source.ID == "geoipset-ru6" && !address.Is6() {
						return fmt.Errorf("семейство адресов GeoIPSET не совпало")
					}
					valid++
				}
				if valid == 0 {
					return fmt.Errorf("список GeoIPSET пуст")
				}
			}
		}
		return nil
	}
	if plan.Component == "xray" {
		archive, e := zip.OpenReader(filepath.Join(work, "0"))
		if e != nil {
			return fmt.Errorf("архив Xray повреждён")
		}
		defer archive.Close()
		found := false
		wanted := "xray"
		if m.opts.GOARCH == "mipsle" {
			for _, f := range archive.File {
				if f.Name == "xray_softfloat" {
					wanted = f.Name
					break
				}
			}
		}
		for _, f := range archive.File {
			if !safeRelative(f.Name) || f.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("небезопасный архив Xray")
			}
			if f.Name == wanted {
				if found || f.UncompressedSize64 > maxArtifact {
					return fmt.Errorf("некорректный архив Xray")
				}
				found = true
				r, e := f.Open()
				if e != nil {
					return e
				}
				body, e := io.ReadAll(io.LimitReader(r, maxArtifact+1))
				r.Close()
				if e != nil || len(body) > maxArtifact {
					return fmt.Errorf("некорректный файл Xray")
				}
				if e = atomicWrite(filepath.Join(work, "xray"), body, 0700); e != nil {
					return e
				}
			}
		}
		if !found {
			return fmt.Errorf("в архиве нет Xray")
		}
		candidateVersion := m.binaryVersion(filepath.Join(work, "xray"))
		if candidateVersion != strings.TrimPrefix(plan.Version, "v") {
			return fmt.Errorf("файл Xray не запускается на роутере или не подтверждает выбранную версию")
		}
		return m.validateBinary(ctx, filepath.Join(work, "xray"))
	}
	f, e := os.Open(filepath.Join(work, "0"))
	if e != nil {
		return e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return fmt.Errorf("архив XKeen повреждён")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var total int64
	count := 0
	hasDispatcher, hasPostUpdate := false, false
	for {
		header, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return fmt.Errorf("архив XKeen повреждён")
		}
		name := strings.TrimPrefix(header.Name, "./")
		if !safeRelative(name) || strings.Contains(name, ":") || header.Size < 0 || header.Size > 16<<20 {
			return fmt.Errorf("небезопасный архив XKeen")
		}
		if name != "xkeen" && name != "_xkeen" && !strings.HasPrefix(name, "_xkeen/") {
			return fmt.Errorf("неизвестный файл в архиве XKeen")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return fmt.Errorf("ссылки в архиве XKeen не разрешены")
		}
		total += header.Size
		count++
		if total > 64<<20 || count > 1500 {
			return fmt.Errorf("архив XKeen слишком большой")
		}
		body, e := io.ReadAll(io.LimitReader(tr, header.Size+1))
		if e != nil || int64(len(body)) != header.Size {
			return fmt.Errorf("файл XKeen повреждён")
		}
		if name == "xkeen" {
			hasDispatcher = true
			hasPostUpdate = strings.Contains(string(body), "-uk_post_update)")
		}
		if e = atomicWrite(filepath.Join(work, "payload", filepath.FromSlash(name)), body, 0700); e != nil {
			return e
		}
	}
	if !hasDispatcher || !hasPostUpdate {
		return fmt.Errorf("у этой версии нет проверенного этапа применения; файлы роутера не изменены")
	}
	return nil
}

func (m *Manager) installPayload(ctx context.Context, plan Plan, work string) error {
	rt := m.runtime()
	switch plan.Component {
	case "settings":
		setting, ok := m.setting(plan.setting)
		if !ok || !setting.Supported {
			return fmt.Errorf("параметр больше не поддерживается")
		}
		state := "off"
		if plan.enabled {
			state = "on"
		}
		if setting.ID == "native_geodata_schedule" && plan.enabled {
			return fmt.Errorf("используйте расписание выбранных геобаз в панели")
		}
		args := []string{setting.flag, state}
		if setting.ID == "native_geodata_schedule" {
			args = []string{setting.flag}
		}
		_, e := m.run(ctx, rt.Dispatcher, args...)
		if e != nil {
			return fmt.Errorf("XKeen не применил параметр")
		}
		current, found := m.setting(plan.setting)
		if !found || current.Enabled != plan.enabled {
			return fmt.Errorf("XKeen не подтвердил новое значение параметра")
		}
		return nil
	case "xray":
		body, e := os.ReadFile(filepath.Join(work, "xray"))
		if e != nil {
			return e
		}
		return atomicWrite(rt.CoreBin, body, 0755)
	case "geodata":
		for i, a := range plan.Artifacts {
			body, e := os.ReadFile(filepath.Join(work, fmt.Sprint(i)))
			if e != nil {
				return e
			}
			source, ok := sourceForFilename(a.Target)
			if !ok {
				return fmt.Errorf("неизвестный файл геобазы")
			}
			if e = atomicWrite(m.geodataPath(source), body, 0644); e != nil {
				return e
			}
		}
		return nil
	case "xkeen":
		modules := filepath.Join(filepath.Dir(rt.Dispatcher), ".xkeen")
		next := modules + ".panel-next"
		if _, e := os.Lstat(next); !os.IsNotExist(e) {
			return fmt.Errorf("осталась незавершённая установка XKeen")
		}
		if _, e := regularCopy(filepath.Join(work, "payload", "_xkeen"), next); e != nil {
			return e
		}
		if e := os.RemoveAll(modules); e != nil {
			return e
		}
		if e := os.Rename(next, modules); e != nil {
			return e
		}
		body, e := os.ReadFile(filepath.Join(work, "payload", "xkeen"))
		if e != nil {
			return e
		}
		if e = atomicWrite(rt.Dispatcher, body, 0755); e != nil {
			return e
		}
		// The upstream 2.1 post-update calls new_features(), which installs RU
		// GeoIPSET automatically when this directory does not exist. An empty
		// directory preserves a deliberate all-through-VPN policy without
		// downloading or enabling an unrequested bypass list.
		if e = os.MkdirAll(filepath.Join(filepath.Dir(rt.XkeenJSON), "ipset"), 0700); e != nil {
			return e
		}
		_, e = m.run(ctx, rt.Dispatcher, "-uk_post_update")
		if e != nil {
			return fmt.Errorf("этап регистрации XKeen завершился ошибкой")
		}
		return nil
	}
	return fmt.Errorf("неизвестный компонент")
}

func (m *Manager) verifyXkeenPreserved(backup Backup) error {
	rt := m.runtime()
	protected := map[string]bool{rt.XrayConfDir: true, filepath.Join(m.opts.DataDir, "pool.json"): true, filepath.Join(m.opts.DataDir, "subscription.json"): true, filepath.Join(m.opts.DataDir, "routing-mode.json"): true, filepath.Join(m.opts.DataDir, "exclusions.json"): true, m.path("/opt/var/spool/cron/crontabs/root"): true}
	for _, source := range GeoSources() {
		protected[m.geodataPath(source)] = true
	}
	for _, entry := range backup.Entries {
		if !protected[entry.Path] {
			continue
		}
		if !entry.Exists {
			if _, e := os.Lstat(entry.Path); !os.IsNotExist(e) {
				return fmt.Errorf("регистрация XKeen создала незапрошенные настройки или геобазы")
			}
			continue
		}
		for relative, wanted := range entry.Hashes {
			target := entry.Path
			if relative != "." {
				target = filepath.Join(target, filepath.FromSlash(relative))
			}
			body, e := os.ReadFile(target)
			if e != nil {
				return fmt.Errorf("регистрация XKeen изменила рабочую конфигурацию")
			}
			sum := sha256.Sum256(body)
			if hex.EncodeToString(sum[:]) != wanted {
				return fmt.Errorf("регистрация XKeen изменила рабочую конфигурацию, расписание или геобазы")
			}
		}
		if entry.Directory {
			count := 0
			e := filepath.Walk(entry.Path, func(_ string, info os.FileInfo, e error) error {
				if e == nil && !info.IsDir() {
					count++
				}
				return e
			})
			if e != nil || count != len(entry.Hashes) {
				return fmt.Errorf("регистрация XKeen изменила состав конфигурации")
			}
		}
	}
	return nil
}

func (m *Manager) run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "XKEEN_FOREGROUND=1")
	cmd.Stdin = strings.NewReader("")
	// Private raw diagnostics remain on the router and are never returned to a
	// browser: upstream commands can print full configured endpoints.
	out, e := os.CreateTemp(m.opts.DataDir, ".component-command-")
	if e != nil {
		return nil, e
	}
	defer os.Remove(out.Name())
	defer out.Close()
	_ = out.Chmod(0600)
	cmd.Stdout = out
	cmd.Stderr = out
	e = cmd.Run()
	return nil, e
}

func (m *Manager) validateBinary(ctx context.Context, bin string) error {
	if m.opts.Validate != nil {
		return m.opts.Validate(ctx, bin)
	}
	rt := m.runtime()
	cmd := exec.CommandContext(ctx, bin, "run", "-test", "-confdir", rt.XrayConfDir)
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "XRAY_LOCATION_CONFDIR=") && !strings.HasPrefix(env, "XRAY_LOCATION_CONFIG=") && !strings.HasPrefix(env, "XRAY_LOCATION_ASSET=") {
			cmd.Env = append(cmd.Env, env)
		}
	}
	cmd.Env = append(cmd.Env, "XRAY_LOCATION_ASSET="+filepath.Join(filepath.Dir(rt.XrayConfDir), "dat"))
	if e := cmd.Run(); e != nil {
		return fmt.Errorf("Xray отклонил конфигурацию")
	}
	return nil
}
func (m *Manager) validateCurrent(ctx context.Context) error {
	return m.validateBinary(ctx, m.runtime().CoreBin)
}
