package shell

import (
	"reflect"
	"strings"
	"testing"
)

// argvs flattens src and renders each non-wrapper command as space-joined values,
// with holes shown as $.
func argvs(t *testing.T, src string) []string {
	t.Helper()
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	cmds, err := Flatten(s)
	if err != nil {
		t.Fatalf("Flatten(%q): %v", src, err)
	}
	var out []string
	for _, c := range cmds {
		if c.Wrapper || len(c.Args) == 0 {
			continue
		}
		var parts []string
		for _, w := range c.Args {
			parts = append(parts, strings.ReplaceAll(w.Value, Hole, "$"))
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

func TestParseCommands(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"plain", "git status", []string{"git status"}},
		{"extra spaces", "  git \t status  ", []string{"git status"}},
		{"and", "a && b", []string{"a", "b"}},
		{"or", "a || b", []string{"a", "b"}},
		{"pipe", "a | b", []string{"a", "b"}},
		{"pipe stderr", "a |& b", []string{"a", "b"}},
		{"semicolon", "a; b", []string{"a", "b"}},
		{"background", "a & b", []string{"a", "b"}},
		{"newline", "a\nb", []string{"a", "b"}},
		{"no spaces around ops", "a&&b||c;d|e", []string{"a", "b", "c", "d", "e"}},
		{"newline after and", "a &&\n b", []string{"a", "b"}},
		{"newline after pipe", "a |\n\n b", []string{"a", "b"}},
		{"subshell", "(a; b)", []string{"a", "b"}},
		{"nested subshell", "( (a) ; b) 2>/dev/null", []string{"a", "b"}},
		{"keyword as arg", "echo if then fi", []string{"echo if then fi"}},
		{"test bracket", "[ -f a ] && b", []string{"[ -f a ]", "b"}},

		{"single quote", "echo 'a b'", []string{"echo a b"}},
		{"double quote", `echo "a b"`, []string{"echo a b"}},
		{"backslash space", `echo a\ b`, []string{"echo a b"}},
		{"joined pieces", `e"c"'h'\o hi`, []string{"echo hi"}},
		{"operators in quotes", `echo "a && b" 'c; d'`, []string{"echo a && b c; d"}},
		{"dq escapes", `echo "a\"b\\c\$d\e"`, []string{`echo a"b\c$d\e`}},
		{"sq keeps backslash", `echo 'a\b'`, []string{`echo a\b`}},
		{"empty quotes", `echo "" ''`, []string{"echo  "}},

		{"comment", "a # b; c", []string{"a"}},
		{"comment line", "# a\nb", []string{"b"}},
		{"hash in word", "a b#c", []string{"a b#c"}},

		{"env prefix", "FOO=1 BAR='x y' git status", []string{"git status"}},
		{"var", "echo $HOME ${HOME} ${HOME:-x} ${#HOME}", []string{"echo $ $ $ $"}},
		{"special vars", "echo $? $$ $1 $@", []string{"echo $ $ $ $"}},
		{"literal dollar", "echo $ a$", []string{"echo $ a$"}},
		{"command subst", "echo $(a)", []string{"a", "echo $"}},
		{"backtick", "echo `a`", []string{"a", "echo $"}},
		{"backtick nested", "echo `a \\`b\\``", []string{"b", "a $", "echo $"}},
		{"subst in dq", `echo "x $(a) y"`, []string{"a", "echo x $ y"}},
		{"backtick in dq", "echo \"x `a` y\"", []string{"a", "echo x $ y"}},
		{"nested subst", "echo $(a $(b))", []string{"b", "a $", "echo $"}},
		{"subst with quotes", `echo "$(a "b c")"`, []string{"a b c", "echo $"}},
		{"procsub in", "diff <(a) <(b)", []string{"a", "b", "diff $ $"}},
		{"procsub out", "tee >(a)", []string{"a", "tee $"}},
		{"arithmetic", "echo $((1 + 2))", []string{"echo $"}},
		{"ansi c", `echo $'a\'b'`, []string{"echo $"}},
		{"locale", `echo $"a"`, []string{"echo a"}},
		{"assignment subst", "x=$(a)", []string{"a"}},

		{"redirect out", "a > b c", []string{"a c"}},
		{"redirect fd", "a 2>&1", []string{"a"}},
		{"redirect fd no space", "a 2>b", []string{"a"}},
		{"digit word", "a 2 > b", []string{"a 2"}},
		{"both", "a &> b", []string{"a"}},
		{"append both", "a &>> b", []string{"a"}},
		{"clobber", "a >| b", []string{"a"}},
		{"read write", "a <> b", []string{"a"}},
		{"here string", "a <<< b", []string{"a"}},
		{"here string subst", "a <<< $(b)", []string{"b", "a"}},
		{"leading redirect", "> b a", []string{"a"}},
		{"redirect subst", "a > $(b)", []string{"b", "a"}},

	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := argvs(t, tt.src)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse(%q)\n got %q\nwant %q", tt.src, got, tt.want)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"open single quote", "echo 'a"},
		{"open double quote", `echo "a`},
		{"open subst", "echo $(a"},
		{"open backtick", "echo `a"},
		{"open param", "echo ${a"},
		{"open subshell", "(a"},
		{"stray close", "a)"},
		{"trailing backslash", `a \`},
		{"trailing and", "a &&"},
		{"trailing pipe", "a |"},
		{"leading operator", "&& a"},
		{"leading pipe", "| a"},
		{"double semicolon", "a;; b"},
		{"redirect target missing", "a >"},
		{"redirect into operator", "a > ; b"},
		{"nul", "a\x00b"},
		{"invalid utf8", "a \xff"},
		{"function", "f() { a; }"},
		{"array", "a=(1 2)"},
		{"arith command", "((x++))"},
		{"arith name", "echo $((x))"},
		{"arith substitution", "echo $(( $(a) ))"},
		{"arith var", "echo $(( $x ))"},
		{"ambiguous arith", "echo $((a) (b))"},
		{"param subst", "echo ${a:-$(b)}"},
		{"param backtick", "echo ${a:-`b`}"},
		{"param prompt transform", "echo ${a@P}"},
		{"param indirection", "echo ${!a}"},
		{"param subscript", "echo ${a[$(b)]}"},
		{"param quotes", `echo ${a:-"b"}`},
		{"word after subshell", "(a) b"},
		{"too deep", strings.Repeat("(", maxDepth+2) + "a" + strings.Repeat(")", maxDepth+2)},
		{"too deep substitution", strings.Repeat("$(", maxDepth+2) + "a" + strings.Repeat(")", maxDepth+2)},
		{"too long", strings.Repeat("a", maxSource+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if s, err := Parse(tt.src); err == nil {
				t.Errorf("Parse(%q) = %+v, want an error", tt.src, s)
			}
		})
	}
}

func TestWordFlags(t *testing.T) {
	tests := []struct {
		src     string
		dynamic bool
		split   bool
		glob    bool
		quoted  bool
		prefix  string
	}{
		{src: "a", prefix: "a"},
		{src: `"a"`, quoted: true, prefix: "a"},
		{src: `\a`, quoted: true, prefix: "a"},
		{src: "$a", dynamic: true, split: true},
		{src: `"$a"`, dynamic: true, quoted: true},
		{src: "b$a", dynamic: true, split: true, prefix: "b"},
		{src: `"b$a"`, dynamic: true, quoted: true, prefix: "b"},
		{src: "*.go", glob: true, prefix: "*.go"},
		{src: "a?", glob: true, prefix: "a?"},
		{src: "[ab]", glob: true, prefix: "[ab]"},
		{src: `"*"`, quoted: true, prefix: "*"},
		{src: `\*`, quoted: true, prefix: "*"},
		{src: "{a,b}", dynamic: true, split: true, prefix: "{a,b}"},
		{src: "{1..3}", dynamic: true, split: true, prefix: "{1..3}"},
		{src: "a{b,c}d", dynamic: true, split: true, prefix: "a{b,c}d"},
		{src: "{}", prefix: "{}"},
		{src: "{a}", prefix: "{a}"},
		{src: `{a\,b}`, quoted: true, prefix: "{a,b}"},
		{src: "'{a,b}'", quoted: true, prefix: "{a,b}"},
		{src: "$'a'", dynamic: true, quoted: true},
	}
	for _, tt := range tests {
		t.Run(tt.src, func(t *testing.T) {
			s, err := Parse("x " + tt.src)
			if err != nil {
				t.Fatal(err)
			}
			w := s.Commands[0].Args[1]
			if w.Dynamic != tt.dynamic || w.Split != tt.split || w.Glob != tt.glob || w.Quoted != tt.quoted {
				t.Errorf("flags: %+v", w)
			}
			if w.Prefix() != tt.prefix {
				t.Errorf("prefix = %q, want %q", w.Prefix(), tt.prefix)
			}
		})
	}
}

func TestAssignments(t *testing.T) {
	s, err := Parse(`A=1 B+=2 C="x y" D=$(a) git status`)
	if err != nil {
		t.Fatal(err)
	}
	last := s.Commands[len(s.Commands)-1]
	var names []string
	for _, a := range last.Assigns {
		names = append(names, a.Name)
	}
	if want := []string{"A", "B", "C", "D"}; !reflect.DeepEqual(names, want) {
		t.Errorf("names = %q, want %q", names, want)
	}
	if got := last.Assigns[2].Value.Value; got != "x y" {
		t.Errorf("C = %q", got)
	}
	if !last.Assigns[3].Value.Dynamic {
		t.Error("D should be dynamic")
	}

	// A quoted name is a program, not an assignment, and an assignment split by a
	// line continuation is still an assignment.
	s, err = Parse(`"A"=1 rm`)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRedirects(t *testing.T) {
	tests := []struct {
		src    string
		op     string
		target string
		writes bool
	}{
		{"a > f", ">", "f", true},
		{"a >> f", ">>", "f", true},
		{"a >| f", ">|", "f", true},
		{"a <> f", "<>", "f", true},
		{"a &> f", "&>", "f", true},
		{"a &>> f", "&>>", "f", true},
		{"a >& f", ">&", "f", true},
		{"a 2>&1", ">&", "1", false},
		{"a >&-", ">&", "-", false},
		{"a < f", "<", "f", false},
		{"a <&3", "<&", "3", false},
		{"a <<< f", "<<<", "f", false},
		{"a >&$x", ">&", Hole, true},
	}
	for _, tt := range tests {
		t.Run(tt.src, func(t *testing.T) {
			s, err := Parse(tt.src)
			if err != nil {
				t.Fatal(err)
			}
			r := s.Commands[0].Redirects[0]
			if r.Op != tt.op || r.Target.Value != tt.target || r.Writes() != tt.writes {
				t.Errorf("got %+v writes=%v", r, r.Writes())
			}
		})
	}
}

func TestCommandName(t *testing.T) {
	tests := map[string]string{
		"git":          "git",
		"/usr/bin/git": "git",
		"./git":        "git",
		"../x/git":     "git",
		`g\it`:         "git",
		`"git"`:        "git",
		`g'i't`:        "git",
	}
	for src, want := range tests {
		s, err := Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		if got := s.Commands[0].Name(); got != want {
			t.Errorf("Name(%q) = %q, want %q", src, got, want)
		}
	}
}

func TestCommandString(t *testing.T) {
	s, err := Parse(`FOO=1 git log "a b" 2>/dev/null`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := s.Commands[0].String(), `FOO=1 git log "a b" 2>/dev/null`; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
