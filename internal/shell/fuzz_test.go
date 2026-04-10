package shell

import (
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"", "a", "a b", "a && b", "a | b; c &", "(a)", "{ a; }", "$(a)", "`a`", "'a'", `"a"`,
		"cat <<EOF\nx\nEOF\n", "cat <<'EOF'\n$(x)\nEOF", "a <<< b", "a > b 2>&1", "A=1 a",
		"if a; then b; fi", "for x in a; do b; done", "while a; do b; done", "[[ a ]]",
		"${a}", "$((1+2))", "$'a'", "a\\\nb", "sudo -u root env A=1 rm -rf /",
		"bash -c 'rm x'", `find . -exec rm {} \;`, "a | xargs -I{} rm {}", "{a,b}", "/bin/r?",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		s, err := Parse(src)
		if err != nil {
			return
		}
		for _, c := range s.Commands {
			if len(c.Args) == 0 && len(c.Assigns) == 0 && len(c.Redirects) == 0 {
				t.Fatalf("empty command from %q", src)
			}
			for _, w := range c.Args {
				if strings.Contains(w.Value, Hole) && !w.Dynamic {
					t.Fatalf("hole in a non-dynamic word from %q", src)
				}
			}
		}
		cmds, err := Flatten(s)
		if err != nil {
			return
		}
		for _, c := range cmds {
			if len(c.Args) > 0 && !c.Args[0].Fixed() {
				if c.Args[0].Value != "[" {
					t.Fatalf("Flatten passed a computed program name from %q: %+v", src, c.Args[0])
				}
			}
		}
	})
}
