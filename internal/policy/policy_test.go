package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deanyool/agent-seatbelt/internal/shell"
)

func mustParse(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{"no version", "rules: []", "unsupported version"},
		{"bad version", "version: 2", "unsupported version"},
		{"unknown field", "version: 1\nrulez: []", "rulez"},
		{"unknown rule field", "version: 1\nrules:\n- {id: a, command: x, decison: deny}", "decison"},
		{"unknown flag field", "version: 1\nrules:\n- {id: a, command: x, decision: deny, flags: {anny: [-f]}}", "anny"},
		{"bad decision", "version: 1\nrules:\n- {id: a, command: x, decision: maybe}", "unknown decision"},
		{"no decision", "version: 1\nrules:\n- {id: a, command: x}", "missing decision"},
		{"no command", "version: 1\nrules:\n- {id: a, decision: deny}", "missing command"},
		{"no id", "version: 1\nrules:\n- {command: x, decision: deny}", "no id"},
		{"duplicate id", "version: 1\nrules:\n- {id: a, command: x, decision: deny}\n- {id: a, command: y, decision: deny}", "duplicate"},
		{"empty subcommand", "version: 1\nrules:\n- {id: a, command: x, subcommand: ' ', decision: deny}", "empty subcommand"},
		{"bad regex", "version: 1\nrules:\n- {id: a, command: x, args: ['re:(('], decision: deny}", "pattern"},
		{"empty pattern", "version: 1\nrules:\n- {id: a, command: x, args: [''], decision: deny}", "empty pattern"},
		{"unknown preset", "version: 1\npresets: [nope]", "unknown preset"},
		{"unknown disable", "version: 1\ndisable: [nope]", "no rule named"},
		{"unparsed allow", "version: 1\nsettings: {unparsed: allow}", "cannot be allow"},
		{"bad scalar", "version: 1\nrules:\n- {id: a, command: {x: y}, decision: deny}", "expected a string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.src))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(path, []byte("version: 1\npresets: [rm]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != path {
		t.Errorf("Source = %q", p.Source)
	}
	if got := p.Evaluate("rm x", Options{}).Decision; got != Deny {
		t.Errorf("rm = %s", got)
	}
	if got := p.Evaluate("git push --force", Options{}).Decision; got != Allow {
		t.Errorf("git without its preset = %s", got)
	}
	if _, err := Load(path + ".missing"); err == nil {
		t.Error("want an error for a missing file")
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: 9"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), bad) {
		t.Errorf("error should name the file: %v", err)
	}
}

func TestPrecedence(t *testing.T) {
	p := mustParse(t, `version: 1
presets: [git]
rules:
  - id: allow-commit
    command: git
    subcommand: commit
    decision: allow
  - id: try-to-allow-force
    command: git
    subcommand: push
    flags: [--force]
    decision: allow
  - id: tighten-log
    command: git
    subcommand: log
    decision: confirm
`)
	tests := []struct {
		cmd  string
		want Decision
		rule string
	}{
		{"git commit -m x", Allow, "allow-commit"},
		{"git push --force", Deny, "git/force-push"},
		{"git log", Confirm, "tighten-log"},
		{"git status", Allow, "git/read"},
	}
	for _, tt := range tests {
		rep := p.Evaluate(tt.cmd, Options{})
		if rep.Decision != tt.want || rep.Worst().Rule != tt.rule {
			t.Errorf("%q: got %s by %s, want %s by %s", tt.cmd, rep.Decision, rep.Worst().Rule, tt.want, tt.rule)
		}
	}
}

func TestMatchRules(t *testing.T) {
	p := mustParse(t, `version: 1
commands:
  tool:
    global_flags:
      value: [--ctx]
      bool: [--quiet]
    value_flags: [--out, -o]
  go-ish:
    single_dash: true
    value_flags: [-name]
rules:
  - {id: path, command: tool, subcommand: "a b", decision: allow}
  - {id: end, command: tool, subcommand: "c $", decision: allow}
  - {id: wild, command: tool, subcommand: "d *x", decision: allow}
  - {id: alt, command: tool, subcommand: [e, f], decision: allow}
  - {id: all, command: tool, subcommand: g, flags: {all: [-x, -y]}, decision: confirm}
  - {id: none, command: tool, subcommand: h, flags: {none: [-x]}, decision: allow}
  - {id: argany, command: tool, subcommand: i, args: {any: ["p*"]}, decision: confirm}
  - {id: argall, command: tool, subcommand: j, args: {all: [p, q]}, decision: confirm}
  - {id: argnone, command: tool, subcommand: k, args: {none: [p]}, decision: allow}
  - {id: re, command: tool, subcommand: l, args: ['re:^[0-9]+$'], decision: allow}
  - {id: star, command: "*", flags: [--nuke], decision: deny, reason: no}
  - {id: single, command: go-ish, flags: [-yes], decision: confirm}
  - {id: single-sub, command: go-ish, subcommand: run, decision: allow}
`)
	tests := []struct {
		cmd  string
		want Decision
		rule string
	}{
		{"tool a b", Allow, "path"},
		{"tool a b extra", Allow, "path"},
		{"tool a", Deny, "seatbelt/default"},
		{"tool c", Allow, "end"},
		{"tool c x", Deny, "seatbelt/default"},
		{"tool d yx", Allow, "wild"},
		{"tool d yz", Deny, "seatbelt/default"},
		{"tool e", Allow, "alt"},
		{"tool f", Allow, "alt"},
		{"tool g -x -y", Confirm, "all"},
		{"tool g -xy", Confirm, "all"},
		{"tool g -x", Deny, "seatbelt/default"},
		{"tool h", Allow, "none"},
		{"tool h -x", Deny, "seatbelt/default"},
		{"tool h -ax", Deny, "seatbelt/default"},
		{"tool i pz", Confirm, "argany"},
		{"tool i qz", Deny, "seatbelt/default"},
		{"tool i $X", Confirm, "argany"},
		{"tool j p q", Confirm, "all argall"[4:]},
		{"tool j p", Deny, "seatbelt/default"},
		{"tool k q", Allow, "argnone"},
		{"tool k p", Deny, "seatbelt/default"},
		{"tool l 123", Allow, "re"},
		{"tool l abc", Deny, "seatbelt/default"},
		{"tool a b --nuke", Deny, "star"},
		{"anything --nuke", Deny, "star"},
		{"go-ish -yes", Confirm, "single"},
		{"go-ish --yes", Confirm, "single"},
		{"go-ish -y", Deny, "seatbelt/default"},
		{"go-ish -name x run", Allow, "single-sub"},
		{"go-ish --name=x run", Allow, "single-sub"},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			rep := p.Evaluate(tt.cmd, Options{})
			if rep.Decision != tt.want || rep.Worst().Rule != tt.rule {
				t.Errorf("got %s by %s, want %s by %s", rep.Decision, rep.Worst().Rule, tt.want, tt.rule)
			}
		})
	}
}

func TestChainTakesStrictest(t *testing.T) {
	p := loadDefault(t)
	rep := p.Evaluate("git status && git push && rm x", Options{})
	if rep.Decision != Deny {
		t.Fatalf("decision = %s", rep.Decision)
	}
	if len(rep.Findings) != 3 {
		t.Fatalf("findings = %+v", rep.Findings)
	}
	got := []Decision{rep.Findings[0].Decision, rep.Findings[1].Decision, rep.Findings[2].Decision}
	if got[0] != Allow || got[1] != Confirm || got[2] != Deny {
		t.Errorf("decisions = %v", got)
	}
	if w := rep.Worst(); w.Rule != "rm/delete" {
		t.Errorf("Worst = %+v", w)
	}
	if r := rep.Reason(); !strings.Contains(r, "rm/delete") {
		t.Errorf("Reason = %q", r)
	}
}

func TestUnparsedReports(t *testing.T) {
	p := loadDefault(t)
	rep := p.Evaluate("echo 'open", Options{})
	if rep.Decision != Deny || rep.Worst().Rule != "seatbelt/unparsed" {
		t.Errorf("rep = %+v", rep)
	}
	rep = p.Evaluate("$X", Options{})
	if rep.Decision != Deny || !strings.Contains(rep.Reason(), "run time") {
		t.Errorf("rep = %+v", rep)
	}
}

func TestDecisionText(t *testing.T) {
	for _, d := range []Decision{Allow, Confirm, Deny} {
		got, err := ParseDecision(d.String())
		if err != nil || got != d {
			t.Errorf("round trip %s: %v %v", d, got, err)
		}
		data, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		var back Decision
		if err := json.Unmarshal(data, &back); err != nil || back != d {
			t.Errorf("json round trip %s: %v %v", d, back, err)
		}
	}
	var d Decision
	if err := json.Unmarshal([]byte(`"nope"`), &d); err == nil {
		t.Error("want an error")
	}
	if err := json.Unmarshal([]byte(`3`), &d); err == nil {
		t.Error("want an error")
	}
	if got := Decision(9).String(); got != "Decision(9)" {
		t.Errorf("String = %q", got)
	}
}

func TestPatterns(t *testing.T) {
	tests := []struct {
		pattern, input string
		want           bool
	}{
		{"a*", "abc", true},
		{"a*", "a/b/c", true},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a.c", "abc", false},
		{"a.c", "a.c", true},
		{"(x)", "(x)", true},
		{"re:^a", "abc", true},
		{"re:c$", "abc", true},
		{"re:b", "abc", true},
		{"re:^b", "abc", false},
		{"re:a.c", "a\nc", true},
	}
	for _, tt := range tests {
		p, err := compilePattern(tt.pattern)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.match(tt.input); got != tt.want {
			t.Errorf("%q on %q = %v", tt.pattern, tt.input, got)
		}
	}
}

func TestParseArgsCluster(t *testing.T) {
	spec := &CommandSpec{ValueFlags: []string{"-o"}}
	a := parseArgs([]shell.Word{shell.Literal("-xo"), shell.Literal("val"), shell.Literal("pos")}, spec)
	if !a.has("-x", false) || !a.has("-o", false) || !a.has("-xo", false) {
		t.Errorf("flags = %+v", a.Flags)
	}
	if len(a.Pos) != 1 || a.Pos[0].Word.Value != "pos" {
		t.Errorf("pos = %+v", a.Pos)
	}
}
