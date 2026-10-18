package main

import "syscall"

// detached is unused on Windows, where the test that needs it is skipped.
func detached() *syscall.SysProcAttr {
	return nil
}
