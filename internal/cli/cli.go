// Package cli implements the seatbelt command.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/deanyool/agent-seatbelt/internal/policy"
	"github.com/deanyool/agent-seatbelt/internal/version"
)

// Exit codes. check reports its decision through these, so scripts can use it.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
	exitConfirm = 3
	exitDeny    = 4
)

const usage = `seatbelt puts a policy between AI agents and dangerous CLIs.

Usage:
  seatbelt check [--json] [--policy FILE] 'COMMAND'     check a shell command
  seatbelt check [--json] [--policy FILE] -- ARGV...    check an argument list
  seatbelt hook claude-code [--policy FILE]             Claude Code PreToolUse hook
  seatbelt version

The policy comes from --policy, then $SEATBELT_POLICY, then ./.seatbelt.yaml, then
~/.config/seatbelt/policy.yaml, then the built-in default (every preset).
`

// App holds everything the commands touch in the outside world.
type App struct {
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Getenv  func(string) string
	Getwd   func() (string, error)
	// Color forces terminal colors on or off for output to Stdout.
	Color bool
}

// New returns an App wired to the real process.
func New() *App {
	return &App{
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		Getenv:     os.Getenv,
		Getwd:      os.Getwd,
		Color:      os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout),
	}
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// Main runs the command line and returns the exit code. A name other than seatbelt
// in args[0] means this process was started through a shim.
func (a *App) Main(args []string) int {
	if len(args) < 2 {
		fmt.Fprint(a.Stderr, usage)
		return exitUsage
	}
	cmd, rest := args[1], args[2:]
	var run func([]string) int
	switch cmd {
	case "check":
		run = a.check
	case "hook":
		run = a.hook
	case "version", "--version", "-V":
		fmt.Fprintf(a.Stdout, "seatbelt %s\n", version.Version)
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprint(a.Stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(a.Stderr, "seatbelt: unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
	return run(rest)
}

func (a *App) fail(err error) int {
	fmt.Fprintf(a.Stderr, "seatbelt: %v\n", err)
	return exitFailure
}

func (a *App) usageError(format string, args ...any) int {
	fmt.Fprintf(a.Stderr, "seatbelt: "+format+"\n", args...)
	return exitUsage
}

// flags returns a FlagSet that reports problems on Stderr.
func (a *App) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	return fs
}

// parseFlags runs fs and turns a parse failure into an exit code.
func parseFlags(fs *flag.FlagSet, args []string) (int, bool) {
	err := fs.Parse(args)
	switch {
	case err == nil:
		return 0, true
	case errors.Is(err, flag.ErrHelp):
		return exitOK, false
	}
	return exitUsage, false
}

func userPolicyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "seatbelt", "policy.yaml"), nil
}

// loadPolicy resolves the policy.
func (a *App) loadPolicy(explicit string) (*policy.Policy, error) {
	if explicit != "" {
		return policy.Load(explicit)
	}
	if v := a.Getenv("SEATBELT_POLICY"); v != "" {
		return policy.Load(v)
	}
	if _, err := os.Stat(".seatbelt.yaml"); err == nil {
		return policy.Load(".seatbelt.yaml")
	}
	path, err := userPolicyPath()
	if err == nil {
		if _, statErr := os.Stat(path); statErr == nil {
			return policy.Load(path)
		}
	}
	return policy.Default()
}

func (a *App) cwd() string {
	dir, err := a.Getwd()
	if err != nil {
		return ""
	}
	return dir
}

func (a *App) colorize(d policy.Decision) string {
	tag := strings.ToUpper(d.String())
	if !a.Color {
		return fmt.Sprintf("%-7s", tag)
	}
	code := map[policy.Decision]string{policy.Allow: "32", policy.Confirm: "33", policy.Deny: "31"}[d]
	return fmt.Sprintf("\x1b[1;%sm%-7s\x1b[0m", code, tag)
}
