package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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

// run checks a command and, if the policy lets it through, runs it.
func (a *App) run(args []string) int {
	fs := a.flags("run")
	policyPath := fs.String("policy", "", "policy file")
	shellCmd := fs.String("c", "", "run this string through sh")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	argv := fs.Args()
	if (*shellCmd == "") == (len(argv) == 0) {
		return a.usageError("run needs either -c 'COMMAND' or -- ARGV...")
	}
	p, err := a.loadPolicy(*policyPath)
	if err != nil {
		return a.fail(err)
	}
	cwd := a.cwd()
	o := policy.Options{CWD: cwd}
	var rep policy.Report
	if *shellCmd != "" {
		rep = p.Evaluate(*shellCmd, o)
		argv = []string{"/bin/sh", "-c", *shellCmd}
	} else {
		rep = p.EvaluateArgv(argv, o)
	}
	a.recordReport(p, "run", cwd, "", rep)
	if code, proceed := a.gate(p, rep, "run", cwd); !proceed {
		return code
	}
	return a.spawn(argv)
}

// gate turns a decision into go or no-go, prompting a person where needed.
func (a *App) gate(p *policy.Policy, rep policy.Report, source, cwd string) (code int, proceed bool) {
	switch rep.Decision {
	case policy.Allow:
		return 0, true
	case policy.Deny:
		fmt.Fprintf(a.Stderr, "seatbelt: denied: %s\n", rep.Reason())
		return exitBlocked, false
	}
	ok, err := a.confirm(rep)
	if err != nil {
		fmt.Fprintf(a.Stderr, "seatbelt: denied: %s, and there is no terminal to ask on (%v)\n", rep.Reason(), err)
		return exitBlocked, false
	}
	if !ok {
		fmt.Fprintln(a.Stderr, "seatbelt: not confirmed")
		return exitBlocked, false
	}
	a.record(p, auditConfirmed(source, cwd, rep))
	return 0, true
}

func (a *App) confirm(rep policy.Report) (bool, error) {
	tty, err := a.OpenTTY()
	if err != nil {
		return false, err
	}
	defer tty.Close()
	fmt.Fprintf(tty, "seatbelt: %s\n  %s\nRun it? [y/N] ", rep.Reason(), rep.Input)
	line, err := readLine(tty)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

func readLine(r io.Reader) (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				return sb.String(), nil
			}
			sb.WriteByte(buf[0])
		}
		if err != nil {
			return sb.String(), err
		}
	}
}

// spawn runs a program as a child, passing through its streams and exit code.
func (a *App) spawn(argv []string) int {
	return a.spawnIn("", argv)
}

func (a *App) spawnIn(dir string, argv []string) int {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = a.Stdin, a.Stdout, a.Stderr
	cmd.Env = a.Environ()
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &exit):
		return exit.ExitCode()
	case errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound):
		fmt.Fprintf(a.Stderr, "seatbelt: %v\n", err)
		return 127
	}
	return a.fail(err)
}
