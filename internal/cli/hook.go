package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/deanyool/agent-seatbelt/internal/audit"
	"github.com/deanyool/agent-seatbelt/internal/hook"
	"github.com/deanyool/agent-seatbelt/internal/policy"
)

// hookMatcher is every tool the hook has something to say about.
const hookMatcher = "Bash|Edit|MultiEdit|Write|NotebookEdit|mcp__.*"

func auditConfirmed(source, cwd string, rep policy.Report) audit.Entry {
	w := rep.Worst()
	return audit.Entry{
		Source:   source,
		Command:  rep.Input,
		Decision: policy.Allow,
		Rule:     w.Rule,
		Reason:   "confirmed by a person: " + w.Reason,
		CWD:      cwd,
	}
}

func (a *App) hook(args []string) int {
	if len(args) == 0 {
		return a.usageError("hook needs a subcommand: claude-code, print or install")
	}
	switch args[0] {
	case "claude-code":
		return a.hookRun(args[1:])
	case "print":
		return a.hookPrint(args[1:])
	case "install":
		return a.hookInstall(args[1:])
	}
	return a.usageError("unknown hook subcommand %q", args[0])
}

// hookRun is the hook itself. Every path that can't reach a decision exits 2: Claude
// Code treats any other nonzero code as a hook failure and runs the tool anyway.
func (a *App) hookRun(args []string) int {
	flags := a.flags("hook claude-code")
	policyPath := flags.String("policy", "", "policy file")
	autoApprove := flags.Bool("auto-approve", false, "answer allow instead of deferring to the normal permission flow")
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
		AutoApprove: *autoApprove,
		Observe: func(v hook.Verdict) {
			a.recordReport(p, "hook", v.Input.CWD, v.Input.SessionID, v.Report)
		},
		Queue: func(v hook.Verdict) (string, error) {
			return a.queue(v.Command, v.Input.CWD, "hook", v.Report)
		},
	})
	fmt.Fprint(a.Stdout, result.Stdout)
	fmt.Fprint(a.Stderr, result.Stderr)
	return result.Code
}

// hookCommand builds the command line for settings.json. Paths are quoted for the
// shell, since Claude Code runs the command through one.
func hookCommand(self, policyPath string) string {
	command := shellQuote(self) + " hook claude-code"
	if policyPath != "" {
		command += " --policy " + shellQuote(policyPath)
	}
	return command
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_./~+-]+$`)

func shellQuote(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func hookGroup(command string) map[string]any {
	return map[string]any{
		"matcher": hookMatcher,
		"hooks": []any{map[string]any{
			"type":    "command",
			"command": command,
		}},
	}
}

func (a *App) hookPrint(args []string) int {
	flags := a.flags("hook print")
	policyPath := flags.String("policy", "", "policy file to name in the hook")
	if code, ok := parseFlags(flags, args); !ok {
		return code
	}
	self, err := a.Executable()
	if err != nil {
		return a.fail(err)
	}
	snippet := map[string]any{"hooks": map[string]any{"PreToolUse": []any{hookGroup(hookCommand(self, *policyPath))}}}
	enc := json.NewEncoder(a.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(snippet); err != nil {
		return a.fail(err)
	}
	return exitOK
}

func (a *App) hookInstall(args []string) int {
	flags := a.flags("hook install")
	policyPath := flags.String("policy", "", "policy file to name in the hook")
	project := flags.Bool("project", false, "write .claude/settings.json in this directory instead of your user settings")
	if code, ok := parseFlags(flags, args); !ok {
		return code
	}
	self, err := a.Executable()
	if err != nil {
		return a.fail(err)
	}
	var path string
	if *project {
		path = filepath.Join(a.cwd(), ".claude", "settings.json")
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return a.fail(err)
		}
		path = filepath.Join(home, ".claude", "settings.json")
	}
	added, err := installHook(path, hookCommand(self, *policyPath))
	if err != nil {
		return a.fail(err)
	}
	if added {
		fmt.Fprintf(a.Stdout, "added the seatbelt hook to %s\n", path)
	} else {
		fmt.Fprintf(a.Stdout, "%s already has the seatbelt hook\n", path)
	}
	return exitOK
}

// installHook adds the hook to a settings file, keeping everything else in it.
func installHook(path, command string) (bool, error) {
	settings := map[string]any{}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &settings); err != nil {
			return false, fmt.Errorf("%s: %w", path, err)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return false, err
	}
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		if settings["hooks"] != nil {
			return false, fmt.Errorf("%s: hooks is not an object", path)
		}
		hooks = map[string]any{}
	}
	groups, ok := hooks["PreToolUse"].([]any)
	if !ok && hooks["PreToolUse"] != nil {
		return false, fmt.Errorf("%s: hooks.PreToolUse is not a list", path)
	}
	for _, g := range groups {
		if data, err := json.Marshal(g); err == nil && strings.Contains(string(data), "hook claude-code") {
			return false, nil
		}
	}
	hooks["PreToolUse"] = append(groups, hookGroup(command))
	settings["hooks"] = hooks
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	tmp := path + ".seatbelt-tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o600); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, path)
}
