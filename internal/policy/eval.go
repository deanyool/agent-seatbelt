// Package policy loads seatbelt policies and decides what happens to a command.
package policy

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/deanyool/agent-seatbelt/internal/shell"
)

// Confirm modes.
const (
	ConfirmAsk  = "ask"
	ConfirmPlan = "plan"
)

// Settings are the policy-wide fallbacks.
type Settings struct {
	Default         Decision
	UnknownCommands Decision
	UnknownTools    Decision
	Unparsed        Decision
	Dynamic         Decision
	ConfirmMode     string
	AuditLog        string
	ProtectedPaths  []string
}

type protectedPath struct {
	source string
	pat    pattern
}

// Policy is a compiled policy, ready to evaluate commands.
type Policy struct {
	// Source says where the policy came from.
	Source string
	// Presets lists the presets that were loaded.
	Presets  []string
	Settings Settings

	specs        map[string]*CommandSpec
	aliases      map[string]string
	rules        map[string][]*Rule
	anyRules     []*Rule
	tools        []*ToolRule
	protected    []protectedPath
	dangerousEnv []string
	home         string
}

// Options carry the context of one evaluation.
type Options struct {
	// CWD resolves relative paths. Empty means relative paths are only matched as
	// written.
	CWD string
}

// Finding is the result for one command in a chain.
type Finding struct {
	Command  string   `json:"command"`
	Decision Decision `json:"decision"`
	Rule     string   `json:"rule,omitempty"`
	Reason   string   `json:"reason"`
}

// Report is the result of evaluating one input.
type Report struct {
	Input    string    `json:"input"`
	Decision Decision  `json:"decision"`
	Findings []Finding `json:"findings"`
}

func (r *Report) add(f Finding) {
	r.Findings = append(r.Findings, f)
	if f.Decision > r.Decision {
		r.Decision = f.Decision
	}
}

// Worst returns the finding that set the report's decision.
func (r *Report) Worst() Finding {
	for _, f := range r.Findings {
		if f.Decision == r.Decision {
			return f
		}
	}
	return Finding{Decision: r.Decision}
}

// Reason returns a one-line explanation of the decision.
func (r *Report) Reason() string {
	f := r.Worst()
	if f.Rule == "" {
		return f.Reason
	}
	return f.Reason + " (rule " + f.Rule + ")"
}

// Evaluate checks a shell command string. Anything that can't be read with
// confidence gets the unparsed decision, which is deny unless configured to
// confirm.
func (p *Policy) Evaluate(src string, o Options) Report {
	rep := Report{Input: src}
	script, err := shell.Parse(src)
	if err != nil {
		rep.add(p.unparsed(src, err))
		return rep
	}
	cmds, err := shell.Flatten(script)
	if err != nil {
		rep.add(p.unparsed(src, err))
		return rep
	}
	for _, c := range cmds {
		p.evalCommand(&rep, c, o)
	}
	return rep
}

// EvaluateArgv checks a command that has already been split into arguments, as a
// shim sees it. No shell parsing happens, but wrappers are still looked through.
func (p *Policy) EvaluateArgv(argv []string, o Options) Report {
	rep := Report{Input: strings.Join(argv, " ")}
	if len(argv) == 0 {
		return rep
	}
	words := make([]shell.Word, len(argv))
	for i, a := range argv {
		words[i] = shell.Literal(a)
	}
	cmds, err := shell.Flatten(&shell.Script{Commands: []shell.Command{{Args: words}}})
	if err != nil {
		rep.add(p.unparsed(rep.Input, err))
		return rep
	}
	for _, c := range cmds {
		p.evalCommand(&rep, c, o)
	}
	return rep
}

func (p *Policy) unparsed(src string, err error) Finding {
	return Finding{
		Command:  src,
		Decision: p.Settings.Unparsed,
		Rule:     "seatbelt/unparsed",
		Reason:   "cannot read this command with confidence: " + err.Error(),
	}
}

// opaquePrograms change what later commands mean, or run a command line in a form
// that isn't unpacked here, so nothing about what they run can be checked.
var opaquePrograms = []string{
	"source", ".", "trap", "alias", "enable", "hash", "bind", "let", "repeat", "foreach", "autoload", "zmodload",
	"at", "batch", "crontab", "parallel", "script", "strace", "ltrace", "gdb", "lldb", "valgrind",
	"expect", "tmux", "screen", "nsenter", "unshare", "systemd-run", "flock",
}

// declaringBuiltins take NAME=value arguments.
var declaringBuiltins = []string{"export", "declare", "typeset", "readonly", "local"}

// fileWriters are checked against protected paths, since they change the files
// named on their command line.
var fileWriters = []string{"tee", "cp", "mv", "install", "ln", "sed", "truncate", "chmod", "chown", "touch", "dd", "rsync"}

func (p *Policy) evalCommand(rep *Report, c shell.Command, o Options) {
	p.checkEnv(rep, c)
	p.checkRedirects(rep, c, o)
	if len(c.Args) == 0 {
		return
	}
	name := c.Name()
	if slices.Contains(opaquePrograms, name) {
		rep.add(Finding{
			Command:  c.String(),
			Decision: p.Settings.Unparsed,
			Rule:     "seatbelt/opaque",
			Reason:   name + " runs code or redefines commands in a way that can't be inspected",
		})
		return
	}
	if slices.Contains(declaringBuiltins, name) {
		p.checkDeclared(rep, c)
	}
	if slices.Contains(fileWriters, name) {
		p.checkWrittenPaths(rep, c, o)
	}
	if f := p.evalRules(c, name); f != nil {
		rep.add(*f)
	}
}

func (p *Policy) canonical(name string) string {
	if c, ok := p.aliases[name]; ok {
		return c
	}
	return name
}

func (p *Policy) evalRules(c shell.Command, name string) *Finding {
	canon := p.canonical(name)
	spec := p.specs[canon]
	own := p.rules[canon]
	governed := spec != nil || len(own) > 0
	args := parseArgs(c.Args[1:], spec)
	display := c.String()

	if governed && !c.Wrapper && len(args.Pos) > 0 && args.Pos[0].Word.Dynamic {
		return &Finding{
			Command:  display,
			Decision: p.Settings.Dynamic,
			Rule:     "seatbelt/dynamic",
			Reason:   "the subcommand of " + name + " is only known at run time",
		}
	}

	var hit []*Rule
	for _, r := range own {
		if r.matches(args) {
			hit = append(hit, r)
		}
	}
	for _, r := range p.anyRules {
		if r.matches(args) {
			hit = append(hit, r)
		}
	}
	if best := strongest(hit); best != nil {
		f := &Finding{Command: display, Decision: *best.Decision, Rule: best.ID, Reason: best.Reason}
		if f.Reason == "" {
			f.Reason = "matched this rule"
		}
		// An allow is a claim about the whole command line. If an expansion could
		// add a flag or an argument, the rule hasn't really seen the command.
		if f.Decision == Allow && governed && len(args.Risky) > 0 {
			return &Finding{
				Command:  display,
				Decision: p.Settings.Dynamic,
				Rule:     "seatbelt/dynamic",
				Reason:   fmt.Sprintf("%s could expand to a flag or extra arguments at run time", args.Risky[0].Raw),
			}
		}
		return f
	}
	switch {
	case c.Wrapper:
		return nil
	case governed:
		return &Finding{
			Command:  display,
			Decision: p.Settings.Default,
			Rule:     "seatbelt/default",
			Reason:   "no rule covers this " + name + " command",
		}
	}
	return &Finding{
		Command:  display,
		Decision: p.Settings.UnknownCommands,
		Rule:     "seatbelt/unknown-command",
		Reason:   "no policy covers " + name,
	}
}

// strongest applies precedence: a deny from any layer wins, then the user's own
// rules beat presets, and within a layer confirm beats allow.
func strongest(hit []*Rule) *Rule {
	var deny, user, preset *Rule
	for _, r := range hit {
		switch {
		case *r.Decision == Deny:
			if deny == nil {
				deny = r
			}
		case r.user:
			if user == nil || *r.Decision > *user.Decision {
				user = r
			}
		default:
			if preset == nil || *r.Decision > *preset.Decision {
				preset = r
			}
		}
	}
	switch {
	case deny != nil:
		return deny
	case user != nil:
		return user
	}
	return preset
}

func (p *Policy) dangerousName(name string) bool {
	if slices.Contains(p.dangerousEnv, name) {
		return true
	}
	return strings.HasPrefix(name, "GIT_CONFIG_KEY_") || strings.HasPrefix(name, "GIT_CONFIG_VALUE_") || strings.HasPrefix(name, "BASH_FUNC_")
}

func (p *Policy) checkEnv(rep *Report, c shell.Command) {
	for _, a := range c.Assigns {
		if p.dangerousName(a.Name) {
			rep.add(p.envFinding(c, a.Name))
		}
	}
}

func (p *Policy) checkDeclared(rep *Report, c shell.Command) {
	for _, w := range c.Args[1:] {
		name, _, found := strings.Cut(w.Value, "=")
		if found && p.dangerousName(strings.TrimSuffix(name, "+")) {
			rep.add(p.envFinding(c, name))
		}
	}
}

func (p *Policy) envFinding(c shell.Command, name string) Finding {
	return Finding{
		Command:  c.String(),
		Decision: Deny,
		Rule:     "seatbelt/env",
		Reason:   "setting " + name + " can change what a command really runs",
	}
}

func (p *Policy) checkRedirects(rep *Report, c shell.Command, o Options) {
	for _, r := range c.Redirects {
		if !r.Writes() {
			continue
		}
		if r.Target.Dynamic {
			rep.add(Finding{
				Command:  c.String(),
				Decision: p.Settings.Dynamic,
				Rule:     "seatbelt/dynamic",
				Reason:   "the redirect target " + r.Target.Raw + " is only known at run time",
			})
			continue
		}
		if f := p.protectedFinding(c.String(), r.Target.Value, o); f != nil {
			rep.add(*f)
		}
	}
}

func (p *Policy) checkWrittenPaths(rep *Report, c shell.Command, o Options) {
	for _, w := range c.Args[1:] {
		v := w.Value
		if w.Dynamic || strings.HasPrefix(v, "-") {
			continue
		}
		if after, ok := strings.CutPrefix(v, "of="); ok {
			v = after
		}
		if f := p.protectedFinding(c.String(), v, o); f != nil {
			rep.add(*f)
		}
	}
}

func (p *Policy) protectedFinding(display, path string, o Options) *Finding {
	resolved := p.resolvePath(path, o.CWD)
	for _, pp := range p.protected {
		if pp.pat.match(resolved) {
			return &Finding{
				Command:  display,
				Decision: Deny,
				Rule:     "seatbelt/protected-path",
				Reason:   path + " is protected by " + pp.source,
			}
		}
	}
	return nil
}

// EvaluateWrite checks a direct file edit, as made by an agent's edit tools.
func (p *Policy) EvaluateWrite(path string, o Options) Report {
	rep := Report{Input: path}
	if f := p.protectedFinding(path, path, o); f != nil {
		rep.add(*f)
		return rep
	}
	rep.add(Finding{Command: path, Decision: Allow, Reason: "not a protected path"})
	return rep
}

// EvaluateTool checks a named tool call. A rule's pattern is tried against the
// full name and against the part after the last __, so the same rule covers
// mcp__server__drop_table from a hook and drop_table from the proxy.
func (p *Policy) EvaluateTool(name string, input map[string]any) Report {
	rep := Report{Input: name}
	short := name
	if i := strings.LastIndex(name, "__"); i >= 0 {
		short = name[i+2:]
	}
	flat := flattenInput(input)
	var deny, user, preset *ToolRule
	for _, t := range p.tools {
		strict := *t.Decision != Allow
		named := false
		for _, pat := range t.patterns {
			named = named || pat.match(name) || pat.match(short)
		}
		if !named || !t.matchesInput(flat, strict) {
			continue
		}
		switch {
		case *t.Decision == Deny:
			if deny == nil {
				deny = t
			}
		case t.user:
			if user == nil || *t.Decision > *user.Decision {
				user = t
			}
		default:
			if preset == nil || *t.Decision > *preset.Decision {
				preset = t
			}
		}
	}
	best := deny
	if best == nil {
		best = user
	}
	if best == nil {
		best = preset
	}
	if best == nil {
		rep.add(Finding{
			Command:  name,
			Decision: p.Settings.UnknownTools,
			Rule:     "seatbelt/unknown-tool",
			Reason:   "no policy covers tool " + name,
		})
		return rep
	}
	reason := best.Reason
	if reason == "" {
		reason = "matched this rule"
	}
	rep.add(Finding{Command: name, Decision: *best.Decision, Rule: best.ID, Reason: reason})
	return rep
}

func flattenInput(input map[string]any) map[string]string {
	out := make(map[string]string, len(input))
	for k, v := range input {
		if s, ok := v.(string); ok {
			out[k] = s
			continue
		}
		if data, err := json.Marshal(v); err == nil {
			out[k] = string(data)
		}
	}
	return out
}
