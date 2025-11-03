package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/deanyool/agent-seatbelt/internal/policy"
)

func exitFor(d policy.Decision) int {
	switch d {
	case policy.Allow:
		return exitOK
	case policy.Confirm:
		return exitConfirm
	}
	return exitDeny
}

func (a *App) check(args []string) int {
	fs := a.flags("check")
	policyPath := fs.String("policy", "", "policy file")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	cwd := fs.String("cwd", "", "directory to resolve relative paths against")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	rest := fs.Args()
	dashes := len(args) > len(rest) && args[len(args)-len(rest)-1] == "--"
	if len(rest) == 0 {
		return a.usageError("check needs a command")
	}
	p, err := a.loadPolicy(*policyPath)
	if err != nil {
		return a.fail(err)
	}
	o := policy.Options{CWD: *cwd}
	if o.CWD == "" {
		o.CWD = a.cwd()
	}
	var rep policy.Report
	switch {
	case dashes:
		rep = p.EvaluateArgv(rest, o)
	case len(rest) == 1 && rest[0] == "-":
		data, err := io.ReadAll(a.Stdin)
		if err != nil {
			return a.fail(err)
		}
		rep = p.Evaluate(string(data), o)
	default:
		rep = p.Evaluate(strings.Join(rest, " "), o)
	}
	if *asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return a.fail(err)
		}
		return exitFor(rep.Decision)
	}
	a.printReport(rep)
	return exitFor(rep.Decision)
}

func (a *App) printReport(rep policy.Report) {
	if len(rep.Findings) == 0 {
		fmt.Fprintf(a.Stdout, "%s (nothing to run)\n", a.colorize(rep.Decision))
		return
	}
	for _, f := range rep.Findings {
		fmt.Fprintf(a.Stdout, "%s %s\n", a.colorize(f.Decision), oneLine(f.Command))
		note := f.Reason
		if f.Rule != "" {
			note = f.Rule + ": " + note
		}
		fmt.Fprintf(a.Stdout, "        %s\n", note)
	}
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 100 {
		return s[:97] + "..."
	}
	return s
}
