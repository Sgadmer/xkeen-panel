package trafficjournal

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const minimumFree = int64(16 << 20)

type Volume struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	MountPath     string `json:"mount_path"`
	FreeBytes     int64  `json:"free_bytes"`
	TotalBytes    int64  `json:"total_bytes"`
	Available     bool   `json:"available"`
	SuggestedPath string `json:"suggested_path"`
	Reason        string `json:"reason,omitempty"`
	device        string
}

func mountUnescape(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}

// DiscoverVolumes lists mounted block storage. Root/internal flash, tmpfs and
// network filesystems are deliberately ineligible for the optional journal.
func DiscoverVolumes() []Volume {
	raw, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return []Volume{}
	}
	byDevice := map[string]Volume{}
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		device, path, fs := mountUnescape(parts[0]), mountUnescape(parts[1]), parts[2]
		if !strings.HasPrefix(device, "/dev/sd") && !strings.HasPrefix(device, "/dev/mapper/") || path == "/" {
			continue
		}
		if path != "/opt" && !strings.HasPrefix(path, "/tmp/mnt/") && !strings.HasPrefix(path, "/mnt/") && !strings.HasPrefix(path, "/media/") && !strings.HasPrefix(path, "/run/media/") {
			continue
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			continue
		}
		free, total, err := volumeSpace(path)
		if err != nil {
			continue
		}
		supported := fs == "ext4" || fs == "ext3" || fs == "ext2" || fs == "btrfs" || fs == "xfs" || fs == "f2fs"
		writable := strings.Contains(","+parts[3]+",", ",rw,")
		v := Volume{MountPath: resolved, FreeBytes: free, TotalBytes: total, Available: supported && writable && free >= minimumFree, device: device}
		v.ID = fmt.Sprintf("%x", sha256.Sum256([]byte(device+"\x00"+resolved)))[:24]
		v.Label = fmt.Sprintf("%s · %s · %.1f ГиБ", filepath.Base(device), fs, float64(total)/(1<<30))
		v.SuggestedPath = filepath.Join(resolved, "xkeen-panel-logs")
		switch {
		case !supported:
			v.Reason = "Для журнала нужна локальная файловая система с поддержкой блокировок, например ext4."
		case !writable:
			v.Reason = "Накопитель подключён только для чтения."
		case free < minimumFree:
			v.Reason = "На накопителе недостаточно свободного места."
		}
		// A bind mount of /opt must not appear as a second physical disk.
		if old, ok := byDevice[device]; !ok || len(resolved) < len(old.MountPath) {
			byDevice[device] = v
		}
	}
	result := make([]Volume, 0, len(byDevice))
	for _, volume := range byDevice {
		result = append(result, volume)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Label < result[j].Label })
	return result
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

// resolveDestination also resolves existing ancestors of a not-yet-created
// leaf. A symlink cannot redirect the selected folder onto internal storage.
func resolveDestination(volume Volume, path string) (string, error) {
	if !volume.Available {
		return "", fmt.Errorf("выбранный накопитель недоступен для записи")
	}
	if path == "" {
		path = volume.SuggestedPath
	}
	if len(path) > 1024 || strings.ContainsAny(path, "\x00\r\n") {
		return "", fmt.Errorf("недопустимое имя папки журнала")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(volume.MountPath, path)
	}
	path = filepath.Clean(path)
	if !within(volume.MountPath, path) || path == filepath.Clean(volume.MountPath) {
		return "", fmt.Errorf("выберите отдельную папку внутри выбранного накопителя")
	}
	ancestor := path
	var missing []string
	for {
		_, err := os.Lstat(ancestor)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) || ancestor == filepath.Dir(ancestor) {
			return "", fmt.Errorf("не удалось проверить папку журнала")
		}
		missing = append(missing, filepath.Base(ancestor))
		ancestor = filepath.Dir(ancestor)
	}
	resolved, err := filepath.EvalSymlinks(ancestor)
	if err != nil || !within(volume.MountPath, resolved) {
		return "", fmt.Errorf("папка журнала ссылается за пределы выбранного накопителя")
	}
	for i := len(missing) - 1; i >= 0; i-- {
		resolved = filepath.Join(resolved, missing[i])
	}
	if len(missing) > 1 {
		return "", fmt.Errorf("родительская папка должна существовать; выберите папку непосредственно на накопителе")
	}
	return resolved, nil
}
