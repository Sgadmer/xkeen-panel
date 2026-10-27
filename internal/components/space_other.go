//go:build !linux

package components

import "fmt"

func freeBytes(path string) (uint64, error) {
	return 0, fmt.Errorf("проверка места доступна на Linux")
}
