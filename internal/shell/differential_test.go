package shell

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This file checks the parser against a real bash. The property under test is the
// one the whole tool rests on: every command bash actually runs must be in the
// list Parse returned, or Parse must have refused the input.
//
// Inputs are built only from the tokens below. The only programs they can name
// are the stub functions a, b and c, and PATH is empty, so generated scripts
// cannot touch anything outside a temp directory no matter how they parse.
var tokens = []string{
	"a", "b", "c", "a", "b", " ", " ", " ", "\t", ";", "&", "|", "&&", "||",
	"'", "\"", "\\", "\n", "\\\n", "$", "$x", "(", ")", "$(", "`", "{", "}",
	"{ ", " }", "<", ">", "#", "=", "x=", "*", "?", "[", "]", "if ", " then ",
	" fi", "for x in ", " do ", " done", "while ", "<<", "<<-", "<<<", "EOF",
	",", "..", "<(", ">(", "! ", "[[ ", " ]]", "2>", "\"$(", "${x:-", "$((",
	"))", "1", "+", "-",
}

// Pipelines run concurrently, so each stub builds its whole record first and
// appends it in one write. \3 separates arguments and \4 ends a record. \1 is out:
// bash uses it internally and it can leak into values. Newlines become \5, because
// printf flushes at each one, which would split the write.
const bashPrelude = `rec() { local r; printf -v r '%s\3' "$@"; r=${r//$'\n'/$'\5'}; printf '%s\4' "$r" >> "$SEATBELT_LOG"; }
a() { rec a "$@"; }
b() { rec b "$@"; return 1; }
c() { rec c "$@"; }
`

// generator builds mostly valid scripts, then damages some of them, so that the
// run reaches deep into the grammar instead of dying on syntax errors.
type generator struct {
	rng *rand.Rand
}

func (g *generator) pick(options ...string) string {
	return options[g.rng.Intn(len(options))]
}

func (g *generator) name() string {
	n := g.pick("a", "b", "c")
	return g.pick(n, n, n, "'"+n+"'", `\`+n, "\\\n"+n, n+"\\\n", `"`+n+`"`)
}

func (g *generator) word(depth int) string {
	switch g.rng.Intn(16) {
	case 0:
		return "'a b'"
	case 1:
		return "\"a b\""
	case 2:
		return "a\\ b"
	case 3:
		return "$x"
	case 4:
		return "\"$x\""
	case 5:
		return "{a,b}"
	case 6:
		return "*"
	case 7:
		if depth > 0 {
			return "$(" + g.list(depth-1) + ")"
		}
	case 8:
		if depth > 0 {
			return "\"$(" + g.list(depth-1) + ")\""
		}
	case 9:
		if depth > 0 {
			return "`" + strings.ReplaceAll(g.simple(0), "\\", "\\\\") + "`"
		}
	case 10:
		if depth > 0 {
			return g.pick("<(", ">(") + g.simple(depth-1) + ")"
		}
	case 11:
		return "\\$(a)"
	case 12:
		return "'$(a)'"
	}
	return g.pick("a", "b", "x", "1", "-x", "--y=z", "a#b", "a=b")
}

func (g *generator) simple(depth int) string {
	var sb strings.Builder
	if g.rng.Intn(5) == 0 {
		sb.WriteString("x=" + g.word(depth) + " ")
	}
	sb.WriteString(g.name())
	for range g.rng.Intn(4) {
		sb.WriteString(" " + g.word(depth))
	}
	switch g.rng.Intn(10) {
	case 0:
		sb.WriteString(" > a")
	case 1:
		sb.WriteString(" 2>&1")
	case 2:
		sb.WriteString(" < a")
	case 3:
		sb.WriteString(" <<< " + g.word(depth))
	}
	return sb.String()
}

func (g *generator) command(depth int) string {
	if depth == 0 {
		return g.simple(0)
	}
	inner := func() string { return g.list(depth - 1) }
	switch g.rng.Intn(14) {
	case 0:
		return "(" + inner() + ")"
	case 1:
		return "{ " + inner() + "; }"
	case 2:
		return "if " + inner() + "; then " + inner() + "; else " + inner() + "; fi"
	case 3:
		return "for x in " + g.word(depth) + " b; do " + inner() + "; done"
	case 4:
		return "! " + g.simple(depth)
	case 5:
		return g.name() + " <<EOF\n" + g.word(depth) + " x\nEOF\n"
	case 6:
		return g.name() + " <<'EOF'\n$(a)\nEOF\n"
	case 7:
		return "while b; do " + inner() + "; done"
	case 8:
		return "[[ " + g.word(depth) + " == a ]]"
	}
	return g.simple(depth)
}

func (g *generator) list(depth int) string {
	var sb strings.Builder
	sb.WriteString(g.command(depth))
	for range g.rng.Intn(3) {
		sb.WriteString(g.pick(" | ", " && ", " || ", "; ", " & ", "\n", " &&\n", " |\n"))
		sb.WriteString(g.command(depth))
	}
	return sb.String()
}

func (g *generator) script() string {
	s := g.list(2)
	for g.rng.Intn(3) == 0 {
		at := g.rng.Intn(len(s) + 1)
		s = s[:at] + tokens[g.rng.Intn(len(tokens))] + s[at:]
	}
	return s
}

func script(selectors []byte) string {
	var sb strings.Builder
	for _, s := range selectors {
		sb.WriteString(tokens[int(s)%len(tokens)])
	}
	return sb.String()
}

// bashRuns executes src under bash and returns the argv of each stub call.
func bashRuns(t testing.TB, bash, parent, src string) [][]string {
	t.Helper()
	// Each run gets its own directory: a background job from an earlier script may
	// still be writing, and leftover files would change what globs expand to.
	dir, err := os.MkdirTemp(parent, "run")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	log := filepath.Join(parent, filepath.Base(dir)+".log")
	if err := os.WriteFile(log, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, "--noprofile", "--norc", "-c", bashPrelude+src)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/nonexistent", "HOME=" + dir, "SEATBELT_LOG=" + log}
	cmd.WaitDelay = time.Second
	_ = cmd.Run()
	time.Sleep(5 * time.Millisecond) // let background jobs finish writing
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	var runs [][]string
	text := strings.ReplaceAll(string(data), "\x05", "\n")
	for _, rec := range strings.Split(text, "\x04") {
		if rec != "" {
			runs = append(runs, strings.Split(strings.TrimSuffix(rec, "\x03"), "\x03"))
		}
	}
	return runs
}

// sees reports whether the flattened list accounts for one real invocation.
func sees(cmds []Command, argv []string) bool {
	for _, c := range cmds {
		if c.Wrapper || len(c.Args) == 0 || c.Args[0].Value != argv[0] {
			continue
		}
		fixed := true
		values := make([]string, 0, len(c.Args))
		for _, w := range c.Args {
			fixed = fixed && w.Fixed()
			values = append(values, w.Value)
		}
		if !fixed || slices.Equal(values, argv) {
			return true
		}
	}
	return false
}

var parsedScripts, observedRuns atomic.Int64

func checkAgainstBash(t testing.TB, bash, dir, src string) {
	t.Helper()
	s, err := Parse(src)
	if err != nil {
		return
	}
	cmds, err := Flatten(s)
	if err != nil {
		return
	}
	parsedScripts.Add(1)
	for _, argv := range bashRuns(t, bash, dir, src) {
		observedRuns.Add(1)
		if !sees(cmds, argv) {
			t.Errorf("bash ran %q but the parser did not list it\nscript: %q\nparsed: %v", argv, src, cmds)
		}
	}
}

// scratchDir is like t.TempDir, except that failing to clean up isn't an error. A
// background job from a generated script may still be writing when the test ends.
func scratchDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "seatbelt-diff")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func findBash(t testing.TB) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	return bash
}

// TestAgainstBash runs a small sample by default. Set SEATBELT_DIFF_RUNS for a
// long soak and SEATBELT_DIFF_SEED to repeat a run.
func TestAgainstBash(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns bash")
	}
	bash := findBash(t)
	runs := 1500
	if v, err := strconv.Atoi(os.Getenv("SEATBELT_DIFF_RUNS")); err == nil {
		runs = v
	}
	seed := time.Now().UnixNano()
	if v, err := strconv.ParseInt(os.Getenv("SEATBELT_DIFF_SEED"), 10, 64); err == nil {
		seed = v
	}
	t.Logf("seed %d, %d runs", seed, runs)

	var wg sync.WaitGroup
	workers := 8
	for w := range workers {
		dir := scratchDir(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(w)))
			gen := &generator{rng: rng}
			for range runs / workers {
				if rng.Intn(4) == 0 {
					sel := make([]byte, 1+rng.Intn(10))
					for i := range sel {
						sel[i] = byte(rng.Intn(256))
					}
					checkAgainstBash(t, bash, dir, script(sel))
					continue
				}
				checkAgainstBash(t, bash, dir, gen.script())
			}
		}()
	}
	wg.Wait()
	t.Logf("%d scripts parsed, %d real commands checked", parsedScripts.Load(), observedRuns.Load())
}

// knownScripts are shapes the random generator is unlikely to hit on its own.
var knownScripts = []string{
	"a\\\n b",
	"$\\\n(a)",
	"\"$\\\n(a)\"",
	"x=a\\\n=b c",
	"cat <<EOF\n$\\\n(a)\nEOF\n",
	"a <<EOF\nb\\\nEOF\nEOF\nc",
	"a <<-EOF\n\tb\n\tEOF\nc",
	"a <<EOF && b\nc\nEOF\n",
	"if a; then b; fi; c",
	"for x in a b; do c $x; done",
	"(a; b) | c",
	"{ a; b; } > /dev/null; c",
	"a `b` $(c)",
	"a \"`b`\"",
	"a `b \\`c\\``",
	"! a",
	"a # b\nc",
	"a#b",
	"[[ a == $(b) ]] && c",
	"a {1..2}",
	"a {b,c}",
	"a{b,c}",
	"x=b; a $x",
	"a '$(b)'",
	"a \\$(b)",
	"a \\`b\\`",
	"a \"\\$(b)\"",
	"a \"\\`b\\`\"",
	"a <(b) >(c)",
	"a <<< $(b)",
	"a $(b) \"$[1]\"",
}

func TestKnownScriptsAgainstBash(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns bash")
	}
	bash := findBash(t)
	dir := scratchDir(t)
	for i, src := range knownScripts {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			checkAgainstBash(t, bash, dir, src)
		})
	}
}

func FuzzAgainstBash(f *testing.F) {
	bash := findBash(f)
	f.Add([]byte{0, 8, 1})
	f.Add([]byte{7, 20, 1, 21})
	dir := scratchDir(f)
	f.Fuzz(func(t *testing.T, sel []byte) {
		if len(sel) > 24 {
			t.Skip()
		}
		checkAgainstBash(t, bash, dir, script(sel))
	})
}
