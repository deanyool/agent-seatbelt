package cli

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/deanyool/agent-seatbelt/internal/policy"
	"github.com/deanyool/agent-seatbelt/internal/shim"
)

func (a *App) shim(args []string) int {
	if len(args) == 0 {
		return a.usageError("shim needs a subcommand: install or list")
	}
	flags := a.flags("shim " + args[0])
	dir := flags.String("dir", "", "shim directory (default ~/.seatbelt/shims)")
	if code, ok := parseFlags(flags, args[1:]); !ok {
		return code
	}
	if *dir == "" {
		d, err := shim.DefaultDir()
		if err != nil {
			return a.fail(err)
		}
		*dir = d
	}
	self, err := a.Executable()
	if err != nil {
		return a.fail(err)
	}
	switch args[0] {
	case "install":
		names := flags.Args()
		if len(names) == 0 {
			return a.usageError("shim install needs program names")
		}
		if err := shim.Install(*dir, self, names); err != nil {
			return a.fail(err)
		}
		fmt.Fprintf(a.Stdout, "installed %d shim(s) in %s\nAdd this to the agent's environment:\n  export PATH=%q:\"$PATH\"\n", len(names), *dir, *dir)
		return exitOK
	case "list":
		names, err := shim.List(*dir, self)
		if err != nil {
			return a.fail(err)
		}
		for _, n := range names {
			fmt.Fprintln(a.Stdout, n)
		}
		return exitOK
	}
	return a.usageError("unknown shim subcommand %q", args[0])
}

// shimMain runs when seatbelt was started under another program's name. The real
// program's exit status and streams stay intact because this process becomes it.
func (a *App) shimMain(name string, args []string) int {
	self, err := a.Executable()
	if err != nil {
		return a.blockShim(name, err)
	}
	target, err := shim.Resolve(name, self, a.Getenv("PATH"))
	if err != nil {
		return a.blockShim(name, err)
	}
	p, err := a.loadPolicy("")
	if err != nil {
		return a.blockShim(name, err)
	}
	cwd := a.cwd()
	argv := append([]string{name}, args...)
	rep := p.EvaluateArgv(argv, policy.Options{CWD: cwd})
	a.recordReport(p, "shim", cwd, "", rep)
	if code, proceed := a.gate(p, rep, "shim", cwd); !proceed {
		return code
	}
	return a.fail(a.Exec(target, argv, a.Environ()))
}

func (a *App) blockShim(name string, err error) int {
	fmt.Fprintf(a.Stderr, "seatbelt: refusing to run %s: %v\n", filepath.Base(name), err)
	if errors.Is(err, shim.ErrNotFound) {
		return 127
	}
	return exitBlocked
}
