//go:build !windows

package xkeen

import "syscall"

func detachedProcessAttrs() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }
