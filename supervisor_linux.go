package main

import "syscall"

const superviseSupported = true

// The panel stops with its supervisor, so the init script never loses it.
func childProcAttrs() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
