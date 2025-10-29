package policy

import (
	"strings"

	"github.com/deanyool/agent-seatbelt/internal/shell"
)

// pathStep is one word of a subcommand path. The end marker $ means no further
// positional arguments are allowed.
type pathStep struct {
	end bool
	pat pattern
}

func compilePath(s string) ([]pathStep, error) {
	fields := strings.Fields(s)
	steps := make([]pathStep, 0, len(fields))
	for _, f := range fields {
		if f == "$" {
			steps = append(steps, pathStep{end: true})
			continue
		}
		p, err := compilePattern(f)
		if err != nil {
			return nil, err
		}
		steps = append(steps, pathStep{pat: p})
	}
	return steps, nil
}

// matchWord tests a word against a pattern. An expansion's value is unknown, so
// the answer depends on which mistake is safe: a strict rule assumes it matches,
// and an allow rule assumes it doesn't.
func matchWord(p pattern, w shell.Word, strict bool) bool {
	if w.Dynamic {
		return strict
	}
	return p.match(w.Value)
}

func (r *Rule) strict() bool {
	return r.Decision != nil && *r.Decision != Allow
}

// matches reports whether the rule applies to a parsed command line.
func (r *Rule) matches(a *parsedArgs) bool {
	strict := r.strict()
	rest := a.Pos
	if len(r.paths) > 0 {
		var ok bool
		if rest, ok = r.matchPaths(a); !ok {
			return false
		}
	}
	if !r.matchFlags(a, strict) {
		return false
	}
	if r.Args != nil && !matchArgs(r.Args, rest, strict) {
		return false
	}
	return true
}

func (r *Rule) matchPaths(a *parsedArgs) ([]positional, bool) {
	strict := r.strict()
	for _, path := range r.paths {
		if rest, ok := matchPath(path, a, strict); ok {
			return rest, true
		}
	}
	return nil, false
}

func matchPath(path []pathStep, a *parsedArgs, strict bool) ([]positional, bool) {
	i := 0
	for _, step := range path {
		if step.end {
			if i != len(a.Pos) {
				return nil, false
			}
			continue
		}
		if i >= len(a.Pos) || !matchWord(step.pat, a.Pos[i].Word, strict) {
			return nil, false
		}
		i++
	}
	return a.Pos[i:], true
}

func (r *Rule) matchFlags(a *parsedArgs, strict bool) bool {
	if r.Flags == nil {
		return true
	}
	if len(r.Flags.Any) > 0 {
		found := false
		for _, name := range r.Flags.Any {
			found = found || a.has(name, strict)
		}
		if !found {
			return false
		}
	}
	for _, name := range r.Flags.All {
		if !a.has(name, strict) {
			return false
		}
	}
	for _, name := range r.Flags.None {
		if a.has(name, !strict) {
			return false
		}
	}
	return true
}

func matchArgs(m *ArgMatch, pos []positional, strict bool) bool {
	words := make([]shell.Word, len(pos))
	for i, p := range pos {
		words[i] = p.Word
	}
	if len(m.anyP) > 0 && !anyWordMatches(m.anyP, words, strict) {
		return false
	}
	for _, p := range m.allP {
		if !anyWordMatches([]pattern{p}, words, strict) {
			return false
		}
	}
	// For none the safe guess flips: to a strict rule, an unknown word is assumed
	// not to be the exempt value, and to an allow rule it is assumed to be the
	// forbidden one.
	return len(m.noneP) == 0 || !anyWordMatches(m.noneP, words, !strict)
}

func anyWordMatches(patterns []pattern, words []shell.Word, strict bool) bool {
	for _, p := range patterns {
		for _, w := range words {
			if matchWord(p, w, strict) {
				return true
			}
		}
	}
	return false
}
