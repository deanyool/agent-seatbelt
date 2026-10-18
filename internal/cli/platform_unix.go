//go:build !windows

package cli

import (
	"io"
	"os"
	"syscall"
)

// shimsSupported is false where a process can't replace itself with another.
const shimsSupported = true

func openTTY() (io.ReadWriteCloser, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

// shellPath is the shell that runs `run -c` and plan entries.
func shellPath() (string, error) {
	return "/bin/sh", nil
}

func execProcess(path string, argv, env []string) error {
	return syscall.Exec(path, argv, env)
}
