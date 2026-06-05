package shell

import "strings"

// Hole marks a run-time expansion inside Word.Value. It is a NUL byte, which
// Parse rejects in its input, so a hole can never be confused with real text.
const Hole = "\x00"

// Word is one shell word after quote removal.
type Word struct {
	// Raw is the source text as written, with line continuations removed.
	Raw string
	// Value is the text after quote removal. Each expansion is replaced by Hole.
	Value string
	// Quoted reports that some part of the word was quoted or escaped.
	Quoted bool
	// Dynamic reports that the value is only known at run time.
	Dynamic bool
	// Split reports an expansion outside double quotes, so the word may become
	// zero or several arguments.
	Split bool
	// Glob reports unquoted pathname-expansion characters.
	Glob bool
}

// Literal returns a word with a fixed value that needed no quoting.
func Literal(s string) Word {
	return Word{Raw: s, Value: s}
}

// Prefix returns the literal text before the first expansion.
func (w Word) Prefix() string {
	if i := strings.Index(w.Value, Hole); i >= 0 {
		return w.Value[:i]
	}
	return w.Value
}

// Fixed reports whether the word's text is fully known before the shell runs it.
func (w Word) Fixed() bool {
	return !w.Dynamic && !w.Glob
}

// wordBuilder accumulates one word while the parser walks its pieces.
type wordBuilder struct {
	val    strings.Builder
	word   Word
	brace  braceState
	opened bool // the builder saw any source text at all
}

// braceState decides whether unquoted text may be a brace expansion such as
// {a,b} or {1..3}. It deliberately over-approximates: bash expands odd shapes like
// {a},b} into "a} b", so any {, then a separator, then } counts. A lone { or {}
// stays literal, which is what the shell does and what find -exec needs.
type braceState struct {
	open     bool
	sawSep   bool
	expanded bool
	prev     byte
}

func (b *braceState) feed(c byte) {
	switch c {
	case '{':
		b.open = true
	case ',':
		b.sawSep = b.sawSep || b.open
	case '.':
		b.sawSep = b.sawSep || (b.open && b.prev == '.')
	case '}':
		b.expanded = b.expanded || b.sawSep
	}
	b.prev = c
}

func (b *wordBuilder) lit(c byte) {
	b.opened = true
	b.val.WriteByte(c)
}

func (b *wordBuilder) quoted(c byte) {
	b.lit(c)
	b.word.Quoted = true
}

func (b *wordBuilder) unquoted(c byte) {
	b.lit(c)
	b.brace.feed(c)
	if c == '*' || c == '?' || c == '[' {
		b.word.Glob = true
	}
}

func (b *wordBuilder) expansion(quoted bool) {
	b.opened = true
	b.val.WriteString(Hole)
	b.word.Dynamic = true
	if !quoted {
		b.word.Split = true
	}
}

func (b *wordBuilder) finish(raw string) Word {
	b.word.Raw = strings.ReplaceAll(raw, "\\\n", "")
	b.word.Value = b.val.String()
	if b.brace.expanded {
		b.word.Dynamic = true
		b.word.Split = true
	}
	if b.word.Value == "[" {
		b.word.Glob = false
	}
	return b.word
}
