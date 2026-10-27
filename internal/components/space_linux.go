//go:build linux

package components

import "syscall"

func freeBytes(path string) (uint64, error) {
	var s syscall.Statfs_t
	if e := syscall.Statfs(path, &s); e != nil {
		return 0, e
	}
	return s.Bavail * uint64(s.Bsize), nil
}
