package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/deanyool/agent-seatbelt/internal/audit"
	"github.com/deanyool/agent-seatbelt/internal/plan"
	"github.com/deanyool/agent-seatbelt/internal/policy"
)

func (a *App) plan(args []string) int {
	if len(args) == 0 {
		return a.usageError("plan needs a subcommand: add, list, show, approve, apply or clear")
	}
	path, err := a.planPath()
	if err != nil {
		return a.fail(err)
	}
	rest := args[1:]
	switch args[0] {
	case "add":
		return a.planAdd(path, rest)
	case "list", "show":
		return a.planShow(path)
	case "approve":
		return a.planApprove(path)
	case "apply":
		return a.planApply(path, rest)
	case "clear":
		n, err := plan.Clear(path)
		if err != nil {
			return a.fail(err)
		}
		fmt.Fprintf(a.Stdout, "marked %d pending entries as failed; none of them will run\n", n)
		return exitOK
	}
	return a.usageError("unknown plan subcommand %q", args[0])
}

func (a *App) planAdd(path string, args []string) int {
	flags := a.flags("plan add")
	policyPath := flags.String("policy", "", "policy file")
	if code, ok := parseFlags(flags, args); !ok {
		return code
	}
	if flags.NArg() == 0 {
		return a.usageError("plan add needs a command")
	}
	command := strings.Join(flags.Args(), " ")
	p, err := a.loadPolicy(*policyPath)
	if err != nil {
		return a.fail(err)
	}
	cwd := a.cwd()
	rep := p.Evaluate(command, policy.Options{CWD: cwd})
	if rep.Decision == policy.Deny {
		fmt.Fprintf(a.Stderr, "seatbelt: denied, not queued: %s\n", rep.Reason())
		return exitDeny
	}
	w := rep.Worst()
	e, err := plan.Add(path, plan.Entry{Command: command, CWD: cwd, Source: "cli", Rule: w.Rule, Reason: w.Reason, AddedAt: a.Now()})
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Stdout, "queued %s\n", e.ID)
	return exitOK
}

func (a *App) planShow(path string) int {
	p, err := plan.Load(path)
	if err != nil {
		return a.fail(err)
	}
	pending := p.Pending()
	if len(pending) == 0 {
		fmt.Fprintln(a.Stdout, "nothing pending")
		return exitOK
	}
	state := "not approved"
	if p.Approval != nil && p.Approval.Digest == p.Digest() {
		state = "approved"
	}
	fmt.Fprintf(a.Stdout, "%d pending, %s, digest %s\n", len(pending), state, p.Digest()[:12])
	for _, e := range pending {
		fmt.Fprintf(a.Stdout, "%s  %s\n", e.ID, e.Command)
		if e.CWD != "" {
			fmt.Fprintf(a.Stdout, "          in %s\n", e.CWD)
		}
		if e.Reason != "" {
			fmt.Fprintf(a.Stdout, "          %s\n", e.Reason)
		}
	}
	return exitOK
}

// planApprove only talks to the terminal. There is no flag that skips the question,
// because anything a flag can do, an agent with a shell can do too.
func (a *App) planApprove(path string) int {
	p, err := plan.Load(path)
	if err != nil {
		return a.fail(err)
	}
	pending := p.Pending()
	if len(pending) == 0 {
		fmt.Fprintln(a.Stdout, "nothing pending")
		return exitOK
	}
	tty, err := a.OpenTTY()
	if err != nil {
		return a.fail(fmt.Errorf("approving a plan needs a terminal: %w", err))
	}
	defer tty.Close()
	digest := p.Digest()
	for _, e := range pending {
		fmt.Fprintf(tty, "  %s  %s\n", e.ID, e.Command)
		if e.CWD != "" {
			fmt.Fprintf(tty, "            in %s\n", e.CWD)
		}
	}
	code := digest[:6]
	fmt.Fprintf(tty, "Type %s to approve these %d command(s): ", code, len(pending))
	line, err := readLine(tty)
	if err != nil && !errors.Is(err, io.EOF) {
		return a.fail(err)
	}
	if strings.TrimSpace(line) != code {
		fmt.Fprintln(a.Stderr, "seatbelt: not approved")
		return exitFailure
	}
	if err := plan.Approve(path, digest, a.Now()); err != nil {
		return a.fail(err)
	}
	fmt.Fprintln(a.Stdout, "approved. Run `seatbelt plan apply` to execute it.")
	return exitOK
}

func (a *App) planApply(path string, args []string) int {
	flags := a.flags("plan apply")
	policyPath := flags.String("policy", "", "policy file")
	if code, ok := parseFlags(flags, args); !ok {
		return code
	}
	p, err := a.loadPolicy(*policyPath)
	if err != nil {
		return a.fail(err)
	}
	check := func(e plan.Entry) error {
		if strings.HasPrefix(e.Command, "#") {
			return errors.New("MCP tool calls can't be run from a plan yet")
		}
		rep := p.Evaluate(e.Command, policy.Options{CWD: e.CWD})
		if rep.Decision == policy.Deny {
			return fmt.Errorf("the policy now denies this: %s", rep.Reason())
		}
		return nil
	}
	run := func(e plan.Entry) error {
		fmt.Fprintf(a.Stdout, "+ %s\n", e.Command)
		sh, err := shellPath()
		if err != nil {
			return err
		}
		code := a.spawnIn(e.CWD, []string{sh, "-c", e.Command})
		a.record(p, audit.Entry{
			Source:   "plan",
			Command:  e.Command,
			Decision: policy.Allow,
			Rule:     e.Rule,
			Reason:   fmt.Sprintf("applied from an approved plan, exit %d", code),
			CWD:      e.CWD,
		})
		if code != 0 {
			return fmt.Errorf("exit status %d", code)
		}
		return nil
	}
	ran, err := plan.Apply(path, check, run)
	if err != nil {
		return a.fail(fmt.Errorf("stopped after %d command(s): %w", ran, err))
	}
	fmt.Fprintf(a.Stdout, "applied %d command(s)\n", ran)
	return exitOK
}
