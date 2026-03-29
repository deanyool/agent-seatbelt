package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/deanyool/agent-seatbelt/internal/presets"
)

func (a *App) preset(args []string) int {
	if len(args) == 0 {
		return a.usageError("preset needs a subcommand: list or show")
	}
	switch args[0] {
	case "list":
		for _, name := range presets.Names() {
			data, err := presets.Get(name)
			if err != nil {
				return a.fail(err)
			}
			fmt.Fprintf(a.Stdout, "%-10s %s\n", name, presetDescription(string(data)))
		}
		return exitOK
	case "show":
		if len(args) != 2 {
			return a.usageError("preset show needs a preset name")
		}
		data, err := presets.Get(args[1])
		if err != nil {
			return a.fail(err)
		}
		if _, err := a.Stdout.Write(data); err != nil {
			return a.fail(err)
		}
		return exitOK
	}
	return a.usageError("unknown preset subcommand %q", args[0])
}

func presetDescription(src string) string {
	for _, line := range strings.Split(src, "\n") {
		if rest, ok := strings.CutPrefix(line, "description: "); ok {
			return rest
		}
	}
	return ""
}

func (a *App) policyCmd(args []string) int {
	if len(args) == 0 {
		return a.usageError("policy needs a subcommand: show or validate")
	}
	flags := a.flags("policy " + args[0])
	policyPath := flags.String("policy", "", "policy file")
	if code, ok := parseFlags(flags, args[1:]); !ok {
		return code
	}
	path := *policyPath
	if flags.NArg() > 0 {
		path = flags.Arg(0)
	}
	p, err := a.loadPolicy(path)
	if err != nil {
		return a.fail(err)
	}
	switch args[0] {
	case "validate":
		fmt.Fprintf(a.Stdout, "%s is valid\n", p.Source)
		return exitOK
	case "show":
		s := p.Settings
		fmt.Fprintf(a.Stdout, "source:           %s\n", p.Source)
		fmt.Fprintf(a.Stdout, "presets:          %s\n", strings.Join(p.Presets, ", "))
		fmt.Fprintf(a.Stdout, "default:          %s\n", s.Default)
		fmt.Fprintf(a.Stdout, "unknown_commands: %s\n", s.UnknownCommands)
		fmt.Fprintf(a.Stdout, "unknown_tools:    %s\n", s.UnknownTools)
		fmt.Fprintf(a.Stdout, "unparsed:         %s\n", s.Unparsed)
		fmt.Fprintf(a.Stdout, "dynamic:          %s\n", s.Dynamic)
		fmt.Fprintf(a.Stdout, "confirm_mode:     %s\n", s.ConfirmMode)
		return exitOK
	}
	return a.usageError("unknown policy subcommand %q", args[0])
}

const starterPolicy = `# seatbelt policy. Reference: docs/policy.md in the project.
version: 1

# Built-in rule sets. "seatbelt preset list" shows them all, and "all" loads them all.
presets: [git, gh, rm, kubectl, terraform, aws, psql, mysql, sf, mcp]

settings:
  # A command in a preset's territory that no rule covers.
  default: deny
  # A program no preset or rule mentions, like npm or ls.
  unknown_commands: allow
  # Commands that can't be read with confidence. Can be confirm, never allow.
  unparsed: deny
  # Allowed commands whose arguments hold shell expansions like $X.
  dynamic: deny
  # What confirm means: "ask" a person now, or "plan" to queue the command.
  confirm_mode: ask

# Turn off a preset rule by id. "seatbelt preset show git" lists the ids.
disable: []

# Your own rules. Deny always wins, then your rules beat presets, and within a
# layer confirm beats allow.
rules: []
#  - id: commit-freely
#    command: git
#    subcommand: [add, commit]
#    decision: allow
`

func (a *App) init(args []string) int {
	flags := a.flags("init")
	policyPath := flags.String("policy", "", "where to write the policy")
	if code, ok := parseFlags(flags, args); !ok {
		return code
	}
	path := *policyPath
	if path == "" {
		p, err := userPolicyPath()
		if err != nil {
			return a.fail(err)
		}
		path = p
	}
	if _, err := os.Stat(path); err == nil {
		return a.fail(fmt.Errorf("%s already exists", path))
	} else if !errors.Is(err, fs.ErrNotExist) {
		return a.fail(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return a.fail(err)
	}
	if err := os.WriteFile(path, []byte(starterPolicy), 0o644); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Stdout, "wrote %s\n", path)
	return exitOK
}
