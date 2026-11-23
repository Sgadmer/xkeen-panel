//go:build !linux

package main

import "syscall"

const superviseSupported = false

func childProcAttrs() *syscall.SysProcAttr { return nil }
