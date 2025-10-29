package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// pattern matches a whole string. Plain text is a glob where * and ? also cross
// slashes, and text starting with re: is a regular expression. Go regular
// expressions run in linear time, so a policy can't be made to hang on input.
type pattern struct {
	source string
	re     *regexp.Regexp
}

func compilePattern(s string) (pattern, error) {
	if s == "" {
		return pattern{}, fmt.Errorf("empty pattern")
	}
	if expr, ok := strings.CutPrefix(s, "re:"); ok {
		re, err := regexp.Compile("(?s)" + expr)
		if err != nil {
			return pattern{}, fmt.Errorf("pattern %q: %w", s, err)
		}
		return pattern{source: s, re: re}, nil
	}
	var sb strings.Builder
	sb.WriteString("(?s)^")
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '*':
			sb.WriteString(".*")
		case '?':
			sb.WriteByte('.')
		default:
			sb.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	sb.WriteByte('$')
	re, err := regexp.Compile(sb.String())
	if err != nil {
		return pattern{}, fmt.Errorf("pattern %q: %w", s, err)
	}
	return pattern{source: s, re: re}, nil
}

func compilePatterns(list []string) ([]pattern, error) {
	out := make([]pattern, 0, len(list))
	for _, s := range list {
		p, err := compilePattern(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (p pattern) match(s string) bool {
	return p.re.MatchString(s)
}
