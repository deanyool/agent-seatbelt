//go:build !windows

package main

import "syscall"

// detached starts a process in a new session, without a controlling terminal.
func detached() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
