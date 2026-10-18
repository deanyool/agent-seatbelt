package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// Windows has no exec that replaces the running process, and a shim needs one to
// keep the real program's exit status, streams and signals.
const shimsSupported = false

// console reads from the console input buffer and writes to the console screen,
// the Windows counterpart of /dev/tty.
type console struct {
	in, out *os.File
}

func (c console) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c console) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c console) Close() error {
	return errors.Join(c.in.Close(), c.out.Close())
}

func openTTY() (io.ReadWriteCloser, error) {
	in, err := os.Open("CONIN$")
	if err != nil {
		return nil, err
	}
	out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		in.Close()
		return nil, err
	}
	return console{in: in, out: out}, nil
}

// shellPath finds sh on PATH. Commands come from Claude Code's Bash tool, which
// runs Git Bash on Windows, so they are run by the same kind of shell.
func shellPath() (string, error) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		return "", fmt.Errorf("running a shell command needs sh on PATH, such as the one Git for Windows installs: %w", err)
	}
	return sh, nil
}

func execProcess(string, []string, []string) error {
	return errors.New("shims are not supported on Windows")
}
