package policy

import (
	"strings"
	"testing"
)

// FuzzEvaluate feeds arbitrary strings to the whole engine. Whatever the input, a
// destructive command placed in front of it must still be caught, and the report
// must be consistent.
func FuzzEvaluate(f *testing.F) {
	for _, s := range []string{
		"", "ls", "git status", "git push --force", "rm -rf /", "sudo rm x", "a | b && c; d",
		"bash -c 'rm x'", "$(rm x)", "`rm x`", "cat <<EOF\n$(rm x)\nEOF", "echo 'open", `echo "open`,
		"{rm,-rf,/}", "/bin/r?", "find . -exec rm {} ;", "x=1 y=2 z", "FOO=$(rm x) ls", "(((", "))))",
		"${a:-$(b)}", "$((1+1))", "a\\\nb", "\\", "'", "\"", "`", "$", "#", "<<", "<<<", "&", "|", ";",
	} {
		f.Add(s)
	}
	p, err := Default()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, src string) {
		rep := p.Evaluate(src, Options{CWD: "/work"})
		worst := Allow
		for _, fd := range rep.Findings {
			if fd.Decision > worst {
				worst = fd.Decision
			}
		}
		if worst != rep.Decision {
			t.Fatalf("report decision %s, strictest finding %s, for %q", rep.Decision, worst, src)
		}
		if again := p.Evaluate(src, Options{CWD: "/work"}); again.Decision != rep.Decision {
			t.Fatalf("not deterministic for %q", src)
		}
		if got := p.Evaluate("rm -rf /; "+src, Options{}).Decision; got != Deny {
			t.Fatalf("rm in front of %q gave %s", src, got)
		}
		if got := p.Evaluate("rm -rf /\n"+src, Options{}).Decision; got != Deny {
			t.Fatalf("rm on the line before %q gave %s", src, got)
		}
		_ = p.EvaluateArgv(strings.Fields(src), Options{})
		_ = p.EvaluateTool(src, map[string]any{"q": src})
	})
}
