package shell

import "strings"

// heredoc is a here-document whose body starts after the next newline.
type heredoc struct {
	delim     string
	quoted    bool
	stripTabs bool
}

// heredocStart reads the delimiter word of << or <<-.
func (p *parser) heredocStart(cmd *Command, fd, op string) error {
	p.skipBlanks()
	w, err := p.word()
	if err != nil {
		return err
	}
	if w.Raw == "" || w.Dynamic {
		return p.errf("here-document needs a plain delimiter")
	}
	p.heredocs = append(p.heredocs, &heredoc{
		delim:     w.Value,
		quoted:    w.Quoted,
		stripTabs: op == "<<-",
	})
	cmd.Redirects = append(cmd.Redirects, Redirect{FD: fd, Op: op, Target: w})
	return nil
}

// readHeredocs consumes every pending body. An unquoted body is still expanded by
// the shell, so a command substitution inside it is a real command.
func (p *parser) readHeredocs() error {
	pending := p.heredocs
	p.heredocs = nil
	for _, h := range pending {
		body, err := p.heredocBody(h)
		if err != nil {
			return err
		}
		if h.quoted {
			continue
		}
		sub := &parser{src: body, depth: p.depth + 1}
		if sub.depth > maxDepth {
			return p.errf("commands are nested too deeply")
		}
		var ignored wordBuilder
		if err := sub.doubleQuoted(&ignored, 0); err != nil {
			return err
		}
		p.cmds = append(p.cmds, sub.cmds...)
	}
	return nil
}

func (p *parser) heredocBody(h *heredoc) (string, error) {
	var body strings.Builder
	for {
		if p.pos >= len(p.src) {
			return "", p.errf("here-document %q is not closed", h.delim)
		}
		line := p.rawLine()
		// In an unquoted body a trailing backslash joins the next line, so the
		// next line cannot be the delimiter.
		for !h.quoted && endsInOddBackslashes(line) {
			if p.pos >= len(p.src) {
				return "", p.errf("here-document %q is not closed", h.delim)
			}
			line = line[:len(line)-1] + p.rawLine()
		}
		check := line
		if h.stripTabs {
			check = strings.TrimLeft(check, "\t")
		}
		if check == h.delim {
			return body.String(), nil
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}
}

func (p *parser) rawLine() string {
	rest := p.src[p.pos:]
	i := strings.IndexByte(rest, '\n')
	if i < 0 {
		p.pos = len(p.src)
		return rest
	}
	p.pos += i + 1
	return rest[:i]
}

func endsInOddBackslashes(s string) bool {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

func (p *parser) noPendingHeredocs() error {
	if len(p.heredocs) > 0 {
		return p.errf("here-document %q has no body", p.heredocs[0].delim)
	}
	return nil
}
