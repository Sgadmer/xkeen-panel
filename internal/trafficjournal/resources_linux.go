//go:build linux

package trafficjournal

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func volumeSpace(path string) (int64, int64, error) {
	var value unix.Statfs_t
	err := unix.Statfs(path, &value)
	return int64(value.Bavail) * int64(value.Bsize), int64(value.Blocks) * int64(value.Bsize), err
}

func memoryBytes() (int64, int64) {
	raw, _ := os.ReadFile("/proc/meminfo")
	var total, available int64
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, _ := strconv.ParseInt(fields[1], 10, 64)
		if fields[0] == "MemTotal:" {
			total = n * 1024
		}
		if fields[0] == "MemAvailable:" {
			available = n * 1024
		}
	}
	return total, available
}
