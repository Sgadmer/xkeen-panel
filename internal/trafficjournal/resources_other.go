//go:build !linux

package trafficjournal

import "errors"

func volumeSpace(string) (int64, int64, error) {
	return 0, 0, errors.New("mounted Linux storage required")
}
func memoryBytes() (int64, int64) { return 0, 0 }
