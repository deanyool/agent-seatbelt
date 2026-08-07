package policy

import (
	"fmt"
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
		_ = p.EvaluateWrite(src, Options{CWD: "/work"})
		_ = p.EvaluateTool(src, map[string]any{"q": src})
	})
}

// bytesource hands out choices from fuzz input.
type bytesource struct {
	data []byte
	i    int
}

func (b *bytesource) next(n int) int {
	if len(b.data) == 0 {
		return 0
	}
	v := b.data[b.i%len(b.data)]
	b.i++
	return int(v) % n
}

// scramble writes one word in a random but equivalent shell spelling.
func scramble(b *bytesource, word string) string {
	var sb strings.Builder
	for i := 0; i < len(word); i++ {
		c := word[i]
		plain := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.IndexByte("-_/.+:=", c) >= 0
		if !plain {
			fmt.Fprintf(&sb, "'%c'", c)
			continue
		}
		switch b.next(6) {
		case 0:
			fmt.Fprintf(&sb, `\%c`, c)
		case 1:
			fmt.Fprintf(&sb, "'%c'", c)
		case 2:
			fmt.Fprintf(&sb, `"%c"`, c)
		case 3:
			fmt.Fprintf(&sb, "%c\\\n", c)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func scrambleLine(b *bytesource, words []string) string {
	parts := make([]string, len(words))
	for i, w := range words {
		parts[i] = scramble(b, w)
	}
	return strings.Join(parts, " ")
}

var wrappersForFuzz = []string{
	"sudo ", "sudo -u root ", "sudo -E ", "doas ", "env ", "env -i ", "env FOO=1 ", "command ", "exec ",
	"nohup ", "time ", "time -p ", "timeout 5 ", "timeout -s KILL 5 ", "nice ", "nice -n 5 ", "stdbuf -oL ",
	"setsid ", "/usr/bin/env ", "/usr/bin/sudo ", "busybox ", "noglob ", "builtin ",
}

// embed places a command somewhere it will really run.
func embed(b *bytesource, cmd string) string {
	switch b.next(16) {
	case 0:
		return "ls && " + cmd
	case 1:
		return cmd + " && ls"
	case 2:
		return "ls | " + cmd
	case 3:
		return "ls; " + cmd + "; ls"
	case 4:
		return "(" + cmd + ")"
	case 5:
		return "{ " + cmd + "; }"
	case 6:
		return "if true; then " + cmd + "; fi"
	case 7:
		return "for x in a b; do " + cmd + "; done"
	case 8:
		return "echo $(" + cmd + ")"
	case 9:
		return `echo "$(` + cmd + `)"`
	case 10:
		return "cat <(" + cmd + ")"
	case 11:
		return "cat <<EOF\n$(" + cmd + ")\nEOF\n"
	case 12:
		return "x=$(" + cmd + ")"
	case 13:
		return "ls\n" + cmd
	case 14:
		return "while false; do " + cmd + "; done"
	}
	return cmd
}

var destructive = [][]string{
	{"rm", "-rf", "/"},
	{"rm", "x"},
	{"rmdir", "x"},
	{"shred", "x"},
	{"git", "push", "--force"},
	{"git", "push", "-f", "origin", "main"},
	{"git", "reset", "--hard"},
	{"git", "clean", "-fdx"},
	{"git", "branch", "-D", "x"},
	{"kubectl", "delete", "pod", "x"},
	{"terraform", "destroy"},
	{"aws", "s3", "rm", "s3://b/k"},
	{"aws", "ec2", "terminate-instances"},
	{"gh", "repo", "delete", "o/r"},
	{"sf", "data", "delete", "record"},
	{"psql", "-c", "drop table t"},
	{"mysql", "-e", "drop table t"},
}

// FuzzDisguises takes destructive commands and hides them behind quoting, wrappers,
// control flow and nested shells. The decision must always be deny.
func FuzzDisguises(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Add([]byte{200, 100, 50, 25, 12, 6, 3, 1})
	p, err := Default()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		b := &bytesource{data: data}
		words := append([]string(nil), destructive[b.next(len(destructive))]...)
		switch b.next(4) {
		case 0:
			words[0] = "/usr/bin/" + words[0]
		case 1:
			words[0] = strings.ToUpper(words[0])
		case 2:
			words[0] = "./" + words[0]
		}
		cmd := scrambleLine(b, words)
		for range b.next(4) {
			cmd = wrappersForFuzz[b.next(len(wrappersForFuzz))] + cmd
		}
		if b.next(4) == 0 {
			cmd = "FOO=1 BAR=2 " + cmd
		}
		for range b.next(3) {
			cmd = embed(b, cmd)
		}
		if b.next(3) == 0 {
			nested := strings.ReplaceAll(cmd, `'`, `'"'"'`)
			cmd = []string{"bash -c '" + nested + "'", "sh -c '" + nested + "'", "eval '" + nested + "'"}[b.next(3)]
		}
		if got := p.Evaluate(cmd, Options{}); got.Decision != Deny {
			t.Fatalf("disguised %q as %q and got %s: %s", words, cmd, got.Decision, got.Reason())
		}
	})
}

// FuzzGlobalFlags puts declared flags in front of the subcommand, where they can
// push it out of position.
func FuzzGlobalFlags(f *testing.F) {
	f.Add([]byte{0, 1, 2})
	cases := []struct {
		program string
		flags   []string
		rest    []string
	}{
		{"git", []string{"-C /tmp", "--no-pager", "--git-dir=.git", "--work-tree=/tmp", "-P"}, []string{"push", "--force"}},
		{"kubectl", []string{"-n prod", "--context=x", "--namespace prod", "--kubeconfig /tmp/c", "--insecure-skip-tls-verify"}, []string{"delete", "pod", "x"}},
		{"terraform", []string{"-chdir=infra", "-chdir infra"}, []string{"destroy"}},
		{"aws", []string{"--region us-east-1", "--profile x", "--debug", "--no-verify-ssl", "--output json"}, []string{"s3", "rm", "s3://b/k"}},
	}
	p, err := Default()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		b := &bytesource{data: data}
		c := cases[b.next(len(cases))]
		parts := []string{c.program}
		for range b.next(5) {
			parts = append(parts, c.flags[b.next(len(c.flags))])
		}
		parts = append(parts, c.rest...)
		cmd := strings.Join(parts, " ")
		if got := p.Evaluate(cmd, Options{}); got.Decision != Deny {
			t.Fatalf("%q got %s: %s", cmd, got.Decision, got.Reason())
		}
	})
}
