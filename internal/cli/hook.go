package cli

import (
	"fmt"

	"github.com/deanyool/agent-seatbelt/internal/hook"
)
func (a *App) hook(args []string) int {
	if len(args) == 0 {
		return a.usageError("hook needs a subcommand: claude-code, print or install")
	}
	switch args[0] {
	case "claude-code":
		return a.hookRun(args[1:])
	}
	return a.usageError("unknown hook subcommand %q", args[0])
}

// hookRun is the hook itself. Every path that can't reach a decision exits 2: Claude
// Code treats any other nonzero code as a hook failure and runs the tool anyway.
func (a *App) hookRun(args []string) int {
	flags := a.flags("hook claude-code")
	policyPath := flags.String("policy", "", "policy file")
	if _, ok := parseFlags(flags, args); !ok {
		return exitUsage
	}
	p, err := a.loadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(a.Stderr, "seatbelt: cannot load the policy, refusing everything: %v\n", err)
		return exitUsage
	}
	result := hook.Run(a.Stdin, hook.Options{
		Policy:      p,
	})
	fmt.Fprint(a.Stdout, result.Stdout)
	fmt.Fprint(a.Stderr, result.Stderr)
	return result.Code
}
