//go:build !windows

package shell

import (
	"os/exec"
	"syscall"
)

// isolate runs cmd in its own process group, so a timeout also kills the background
// jobs and subshells a generated script started, not just bash itself.
func isolate(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}

// reap kills whatever is still running in cmd's process group.
func reap(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
