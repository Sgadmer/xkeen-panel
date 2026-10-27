//go:build !windows

package updater

import "syscall"

func detachedProcessAttrs() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }
