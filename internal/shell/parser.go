// Package shell parses just enough POSIX sh and bash to list every command a
// string would run.
//
// The parser is written for a policy engine, so it has one rule: when it is not
// sure what the shell will do, it returns an error. Callers treat an error as a
// denial. Anything outside the supported subset (case statements, function
// definitions, C-style for loops, arithmetic on variables) is rejected rather
// than guessed at.
package shell

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	maxSource = 1 << 20
	maxDepth  = 32
)

// Error explains why a string could not be parsed with confidence.
type Error struct {
	Pos int
	Msg string
}

func (e *Error) Error() string {
	return fmt.Sprintf("offset %d: %s", e.Pos, e.Msg)
}

// Redirect is one I/O redirection attached to a command.
type Redirect struct {
	FD     string
	Op     string
	Target Word
}

// Writes reports whether the redirect can create or change a file.
func (r Redirect) Writes() bool {
	switch r.Op {
	case ">", ">>", ">|", "<>", "&>", "&>>":
		return true
	case ">&":
		return !isDuplicateTarget(r.Target)
	}
	return false
}

func isDuplicateTarget(w Word) bool {
	if !w.Fixed() {
		return false
	}
	if w.Value == "-" {
		return true
	}
	return allDigits(w.Value)
}

// Assign is a NAME=value prefix or a standalone assignment.
type Assign struct {
	Name  string
	Value Word
}

// Command is one simple command.
type Command struct {
	Assigns   []Assign
	Args      []Word
	Redirects []Redirect
	// Via lists the wrappers this command was found inside, outermost first.
	Via []string
	// Wrapper marks a command such as sudo or env whose inner command was
	// extracted separately. Only rules written for it apply.
	Wrapper bool
}

// Name returns the lower-cased base name of the program, so /usr/bin/git, ./git
// and GIT all give "git". Case folding matters because macOS volumes are usually
// case-insensitive and there RM really does run rm.
func (c Command) Name() string {
	if len(c.Args) == 0 {
		return ""
	}
	return BaseName(c.Args[0].Value)
}

// BaseName reduces a program path to the name a policy refers to.
func BaseName(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// String renders the command roughly as written, for logs and messages.
func (c Command) String() string {
	var parts []string
	for _, a := range c.Assigns {
		parts = append(parts, a.Name+"="+a.Value.Raw)
	}
	for _, w := range c.Args {
		parts = append(parts, w.Raw)
	}
	for _, r := range c.Redirects {
		parts = append(parts, r.FD+r.Op+r.Target.Raw)
	}
	return strings.Join(parts, " ")
}

// Script is the flat list of simple commands found in a source string. Control
// flow is discarded: a command in an untaken branch still appears, so the list
// is a superset of what runs.
type Script struct {
	Commands []Command
}

// Parse lists the simple commands in src, including those nested in subshells,
// groups, loops, conditionals, command substitutions and here-documents.
func Parse(src string) (*Script, error) {
	return parseAt(src, 0)
}

func parseAt(src string, depth int) (*Script, error) {
	if len(src) > maxSource {
		return nil, &Error{Msg: "command is too long to inspect"}
	}
	if strings.IndexByte(src, 0) >= 0 {
		return nil, &Error{Msg: "command contains a NUL byte"}
	}
	if !utf8.ValidString(src) {
		return nil, &Error{Msg: "command is not valid UTF-8"}
	}
	p := &parser{src: src, depth: depth}
	if err := p.list(0); err != nil {
		return nil, err
	}
	return &Script{Commands: p.cmds}, nil
}

type parser struct {
	src      string
	pos      int
	depth    int
	cmds     []Command
	heredocs []*heredoc
}

func (p *parser) errf(format string, args ...any) error {
	return &Error{Pos: p.pos, Msg: fmt.Sprintf(format, args...)}
}

// peek returns the current byte, or 0 at the end of input.
func (p *parser) peek() byte {
	if p.pos >= len(p.src) {
		return 0
	}
	return p.src[p.pos]
}

// peek2 returns the byte after the current one, also skipping continuations.
func (p *parser) peek2() byte {
	p.peek()
	save := p.pos
	p.pos++
	c := p.peek()
	p.pos = save
	return c
}

func (p *parser) advance() {
	p.peek()
	p.pos++
}

// skipBlanks moves past spaces, tabs and a comment. It stops at the newline that
// ends a comment.
func (p *parser) skipBlanks() {
	for {
		switch p.peek() {
		case ' ', '\t':
			p.pos++
		case '#':
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
			return
		default:
			return
		}
	}
}

// skipLines moves past blanks and newlines, reading any here-documents that were
// waiting for a newline.
func (p *parser) skipLines() error {
	for {
		p.skipBlanks()
		if p.peek() != '\n' {
			return nil
		}
		if err := p.newline(); err != nil {
			return err
		}
	}
}

func (p *parser) newline() error {
	p.advance()
	return p.readHeredocs()
}

// list parses commands until the end of input or, when closer is ')', until the
// matching close paren.
func (p *parser) list(closer byte) error {
	for {
		if err := p.skipLines(); err != nil {
			return err
		}
		switch c := p.peek(); c {
		case 0:
			if closer != 0 {
				return p.errf("unterminated subshell or command substitution")
			}
			return p.noPendingHeredocs()
		case ')':
			if closer != ')' {
				return p.errf("unexpected )")
			}
			p.pos++
			return p.noPendingHeredocs()
		case ';', '&', '|':
			return p.errf("unexpected %q", string(c))
		}
		if err := p.andOr(); err != nil {
			return err
		}
		p.skipBlanks()
		switch c := p.peek(); c {
		case ';':
			p.advance()
			if n := p.peek(); n == ';' || n == '&' {
				return p.errf("case terminators are not supported")
			}
		case '&':
			p.advance()
		case '\n', ')', 0:
		default:
			return p.errf("unexpected %q", string(c))
		}
	}
}

// andOr parses a pipeline-and-list chain: a | b && c || d.
func (p *parser) andOr() error {
	for {
		if err := p.command(); err != nil {
			return err
		}
		p.skipBlanks()
		c, n := p.peek(), p.peek2()
		switch {
		case c == '&' && n == '&', c == '|' && (n == '|' || n == '&'):
			p.advance()
			p.advance()
		case c == '|':
			p.advance()
		default:
			return nil
		}
		if err := p.skipLines(); err != nil {
			return err
		}
		if c := p.peek(); c == 0 || c == ')' || c == ';' || c == '&' || c == '|' {
			return p.errf("operator is missing its right-hand command")
		}
	}
}

var assignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\+?=`)

// command parses one simple command, or walks through one piece of compound
// syntax. Compound commands are flattened: keywords are skipped and the commands
// inside them are picked up by later calls.
func (p *parser) command() error {
	var cmd Command
	closed := false // a compound command just ended; only redirects may follow
	for {
		p.skipBlanks()
		c := p.peek()
		switch {
		case c == 0, c == ';', c == '\n', c == ')', c == '|':
			p.emit(cmd)
			return nil
		case c == '&':
			if p.peek2() != '>' {
				p.emit(cmd)
				return nil
			}
			if err := p.redirect(&cmd, ""); err != nil {
				return err
			}
			continue
		case c == '(':
			if len(cmd.Args) > 0 || len(cmd.Assigns) > 0 || closed {
				return p.errf("function definitions and arrays are not supported")
			}
			if p.peek2() == '(' {
				return p.errf("arithmetic commands are not supported")
			}
			if err := p.enter(); err != nil {
				return err
			}
			p.advance()
			err := p.list(')')
			p.depth--
			if err != nil {
				return err
			}
			closed = true
			continue
		case (c == '<' || c == '>') && p.peek2() != '(':
			if err := p.redirect(&cmd, ""); err != nil {
				return err
			}
			continue
		}

		w, err := p.word()
		if err != nil {
			return err
		}
		if c := p.peek(); (c == '<' || c == '>') && p.peek2() != '(' && !w.Quoted && allDigits(w.Value) {
			if err := p.redirect(&cmd, w.Value); err != nil {
				return err
			}
			continue
		}
		if closed {
			return p.errf("unexpected word after a compound command: %q", w.Raw)
		}
		first := len(cmd.Args) == 0 && len(cmd.Assigns) == 0 && len(cmd.Redirects) == 0
		if first && !w.Quoted && !w.Dynamic {
			switch w.Value {
			case "if", "then", "elif", "else", "while", "until", "do", "!", "{":
				if err := p.skipLines(); err != nil {
					return err
				}
				continue
			case "fi", "done", "}":
				closed = true
				continue
			case "for":
				if err := p.forHeader(); err != nil {
					return err
				}
				continue
			case "[[":
				if err := p.condition(); err != nil {
					return err
				}
				closed = true
				continue
			case "case", "esac", "select", "coproc", "function":
				return p.errf("%q is not supported", w.Value)
			}
		}
		if len(cmd.Args) == 0 && assignRe.MatchString(w.Raw) {
			name, value, _ := strings.Cut(w.Value, "=")
			_, raw, _ := strings.Cut(w.Raw, "=")
			w.Value, w.Raw = value, raw
			cmd.Assigns = append(cmd.Assigns, Assign{Name: strings.TrimSuffix(name, "+"), Value: w})
			continue
		}
		cmd.Args = append(cmd.Args, w)
	}
}

func (p *parser) emit(cmd Command) {
	if len(cmd.Args) > 0 || len(cmd.Assigns) > 0 || len(cmd.Redirects) > 0 {
		p.cmds = append(p.cmds, cmd)
	}
}

func (p *parser) enter() error {
	if p.depth >= maxDepth {
		return p.errf("commands are nested too deeply")
	}
	p.depth++
	return nil
}

// forHeader consumes "NAME [in WORDS]" and leaves the parser at the loop body.
func (p *parser) forHeader() error {
	p.skipBlanks()
	if p.peek() == '(' {
		return p.errf("C-style for loops are not supported")
	}
	name, err := p.word()
	if err != nil {
		return err
	}
	if name.Value == "" || name.Quoted || name.Dynamic {
		return p.errf("expected a loop variable")
	}
	if err := p.skipLines(); err != nil {
		return err
	}
	if p.peek() == ';' {
		p.advance()
		return p.skipLines()
	}
	w, err := p.word()
	if err != nil {
		return err
	}
	if !w.Quoted && w.Value == "do" {
		return p.skipLines()
	}
	if w.Quoted || w.Value != "in" {
		return p.errf("expected in or do after the loop variable")
	}
	for {
		p.skipBlanks()
		switch c := p.peek(); c {
		case ';':
			p.advance()
			return p.skipLines()
		case '\n':
			return p.skipLines()
		case 0, '&', '|', '(', ')', '<', '>':
			return p.errf("malformed for loop")
		}
		if _, err := p.word(); err != nil {
			return err
		}
	}
}

// condition consumes the inside of [[ ... ]]. Its operators are not shell
// operators, but expansions inside it still run, so words are parsed normally.
func (p *parser) condition() error {
	for {
		p.skipBlanks()
		switch c := p.peek(); c {
		case 0:
			return p.errf("unterminated [[")
		case '\n':
			if err := p.newline(); err != nil {
				return err
			}
			continue
		case '&', '|', '(', ')', ';':
			p.advance()
			continue
		case '<', '>':
			if p.peek2() != '(' {
				p.advance()
				continue
			}
		}
		w, err := p.word()
		if err != nil {
			return err
		}
		if !w.Quoted && w.Value == "]]" {
			return nil
		}
	}
}

// redirect parses a redirection operator and its target.
func (p *parser) redirect(cmd *Command, fd string) error {
	op := p.redirectOp()
	if op == "<<" || op == "<<-" {
		return p.heredocStart(cmd, fd, op)
	}
	p.skipBlanks()
	w, err := p.word()
	if err != nil {
		return err
	}
	if w.Raw == "" {
		return p.errf("redirection is missing its target")
	}
	cmd.Redirects = append(cmd.Redirects, Redirect{FD: fd, Op: op, Target: w})
	return nil
}

func (p *parser) redirectOp() string {
	ops := []string{"&>>", "&>", "<<<", "<<-", "<<", "<&", "<>", ">>", ">&", ">|", "<", ">"}
	// Walk one byte at a time so a continuation inside an operator is handled.
	var seen strings.Builder
	for seen.Len() < 3 {
		c := p.peek()
		if !strings.ContainsRune("<>&|-", rune(c)) || c == 0 {
			break
		}
		next := seen.String() + string(c)
		found := false
		for _, op := range ops {
			if strings.HasPrefix(op, next) {
				found = true
				break
			}
		}
		if !found {
			break
		}
		seen.WriteByte(c)
		p.pos++
	}
	return seen.String()
}

// word reads one word. It returns an empty word when the input is at a
// metacharacter, so callers that need a word must check Raw.
func (p *parser) word() (Word, error) {
	var b wordBuilder
	p.peek()
	start := p.pos
	for {
		c := p.peek()
		switch c {
		case 0, ' ', '\t', '\n', ';', '&', '|', '(', ')':
			return b.finish(p.src[start:p.pos]), nil
		case '<', '>':
			if b.opened || p.peek2() != '(' {
				return b.finish(p.src[start:p.pos]), nil
			}
			p.advance()
			if err := p.substitution(&b, false); err != nil {
				return Word{}, err
			}
		case '\\':
			p.pos++
			if p.pos >= len(p.src) {
				return Word{}, p.errf("trailing backslash")
			}
			b.quoted(p.src[p.pos])
			p.pos++
		case '\'':
			if err := p.singleQuoted(&b); err != nil {
				return Word{}, err
			}
		case '"':
			p.advance()
			b.word.Quoted = true
			b.opened = true
			if err := p.doubleQuoted(&b, '"'); err != nil {
				return Word{}, err
			}
		case '$':
			if err := p.dollar(&b, false); err != nil {
				return Word{}, err
			}
		case '`':
			if err := p.backtick(&b, false); err != nil {
				return Word{}, err
			}
		default:
			b.unquoted(c)
			p.pos++
		}
	}
}

func (p *parser) singleQuoted(b *wordBuilder) error {
	p.pos++
	end := strings.IndexByte(p.src[p.pos:], '\'')
	if end < 0 {
		return p.errf("unterminated single quote")
	}
	b.opened = true
	b.word.Quoted = true
	b.val.WriteString(p.src[p.pos : p.pos+end])
	p.pos += end + 1
	return nil
}

// doubleQuoted scans double-quoted text up to term. A term of 0 scans to the end
// of input, which is how an unquoted here-document body behaves.
func (p *parser) doubleQuoted(b *wordBuilder, term byte) error {
	for {
		c := p.peek()
		if c == 0 && term != 0 {
			return p.errf("unterminated double quote")
		}
		if c == term {
			if c != 0 {
				p.advance()
			}
			return nil
		}
		switch c {
		case '\\':
			p.pos++
			if p.pos >= len(p.src) {
				return p.errf("trailing backslash")
			}
			n := p.src[p.pos]
			if n != '$' && n != '`' && n != '"' && n != '\\' {
				b.lit('\\')
			}
			b.lit(n)
			p.pos++
		case '$':
			if err := p.dollar(b, true); err != nil {
				return err
			}
		case '`':
			if err := p.backtick(b, true); err != nil {
				return err
			}
		default:
			b.lit(c)
			p.pos++
		}
	}
}

func (p *parser) dollar(b *wordBuilder, quoted bool) error {
	p.advance()
	c := p.peek()
	switch {
	case c == '(':
		if p.peek2() == '(' {
			return p.arithmetic(b, quoted)
		}
		return p.substitution(b, quoted)
	case c == '{':
		return p.parameter(b, quoted)
	case c == '\'' && !quoted:
		return p.ansiC(b)
	case c == '"' && !quoted:
		p.advance()
		b.word.Quoted = true
		return p.doubleQuoted(b, '"')
	case isNameStart(c):
		for isNameByte(p.peek()) {
			p.pos++
		}
		b.expansion(quoted)
	case strings.IndexByte("@*#?$!-0123456789", c) >= 0:
		p.advance()
		b.expansion(quoted)
	default:
		if quoted {
			b.lit('$')
		} else {
			b.unquoted('$')
		}
	}
	return nil
}

// substitution parses $(...), <(...) or >(...) with the parser at the open paren.
// The commands inside are real commands and join the list.
func (p *parser) substitution(b *wordBuilder, quoted bool) error {
	if len(p.heredocs) > 0 {
		return p.errf("command substitution on a line with a pending here-document")
	}
	if err := p.enter(); err != nil {
		return err
	}
	p.advance()
	err := p.list(')')
	p.depth--
	if err != nil {
		return err
	}
	b.expansion(quoted)
	return nil
}

func (p *parser) backtick(b *wordBuilder, quoted bool) error {
	p.pos++
	var inner strings.Builder
	for {
		if p.pos >= len(p.src) {
			return p.errf("unterminated backtick")
		}
		c := p.src[p.pos]
		if c == '`' {
			p.pos++
			break
		}
		if c == '\\' && p.pos+1 < len(p.src) {
			n := p.src[p.pos+1]
			if n == '`' || n == '\\' || n == '$' || (quoted && n == '"') {
				inner.WriteByte(n)
				p.pos += 2
				continue
			}
		}
		inner.WriteByte(c)
		p.pos++
	}
	if p.depth >= maxDepth {
		return p.errf("commands are nested too deeply")
	}
	sub, err := parseAt(inner.String(), p.depth+1)
	if err != nil {
		return err
	}
	p.cmds = append(p.cmds, sub.Commands...)
	b.expansion(quoted)
	return nil
}

// arithmetic accepts $(( )) holding only numbers and operators. A name is not
// safe: bash evaluates a variable's contents as an expression, so x='a[$(cmd)]'
// followed by $((x)) runs cmd.
func (p *parser) arithmetic(b *wordBuilder, quoted bool) error {
	p.advance()
	p.advance()
	depth := 2
	for depth > 0 {
		c := p.peek()
		switch c {
		case 0:
			return p.errf("unterminated arithmetic expansion")
		case '(':
			depth++
		case ')':
			depth--
			if depth == 1 && p.peek2() != ')' {
				return p.errf("ambiguous $(( ))")
			}
		default:
			if strings.IndexByte("0123456789 \t+-*/%<>=!&|^~?:,", c) < 0 {
				return p.errf("arithmetic on anything but numbers is not supported")
			}
		}
		p.advance()
	}
	b.expansion(quoted)
	return nil
}

// parameter accepts ${NAME} and its pattern and default forms. Anything that
// could run a command or evaluate a value as code is rejected, including
// indirection, array subscripts and the @P prompt transform.
func (p *parser) parameter(b *wordBuilder, quoted bool) error {
	p.advance()
	if p.peek() == '!' {
		return p.errf("indirect expansion is not supported")
	}
	depth := 1
	for depth > 0 {
		c := p.peek()
		switch c {
		case 0:
			return p.errf("unterminated ${")
		case '`', '\'', '"', '\\', '[':
			return p.errf("${...} containing %q is not supported", string(c))
		case '$':
			switch p.peek2() {
			case '(':
				return p.errf("command substitution inside ${...} is not supported")
			case '{':
				depth++
				p.advance()
			}
		case '<', '>':
			if p.peek2() == '(' {
				return p.errf("process substitution inside ${...} is not supported")
			}
		case '@':
			return p.errf("${...@} transforms are not supported")
		case '}':
			depth--
		}
		p.advance()
	}
	b.expansion(quoted)
	return nil
}

// ansiC skips $'...'. The value is deliberately not decoded: it is treated as
// unknown, so $'\x72\x6d' can never be read as anything but opaque.
func (p *parser) ansiC(b *wordBuilder) error {
	p.pos++
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case '\\':
			p.pos += 2
		case '\'':
			p.pos++
			b.word.Quoted = true
			b.expansion(true)
			return nil
		default:
			p.pos++
		}
	}
	return p.errf("unterminated $'")
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isNameByte(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9')
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
