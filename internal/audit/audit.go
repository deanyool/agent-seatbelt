// Package audit keeps the append-only JSONL record of every decision.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/deanyool/agent-seatbelt/internal/policy"
)

// Entry is one line of the audit log.
type Entry struct {
	Time     time.Time       `json:"time"`
	Source   string          `json:"source"`
	Command  string          `json:"command"`
	Decision policy.Decision `json:"decision"`
	Rule     string          `json:"rule,omitempty"`
	Reason   string          `json:"reason,omitempty"`
	CWD      string          `json:"cwd,omitempty"`
	Session  string          `json:"session,omitempty"`
}

// Logger appends entries to a file.
type Logger struct {
	Path string
}

// DefaultPath returns the log location: an explicit setting, then
// SEATBELT_AUDIT_LOG, then ~/.seatbelt/audit.jsonl.
func DefaultPath(setting string, getenv func(string) string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if setting != "" {
		if rest, ok := strings.CutPrefix(setting, "~/"); ok {
			return filepath.Join(home, rest), nil
		}
		return setting, nil
	}
	if v := getenv("SEATBELT_AUDIT_LOG"); v != "" {
		return v, nil
	}
	return filepath.Join(home, ".seatbelt", "audit.jsonl"), nil
}

// Write appends one entry. Each entry is a single write to a file opened for
// append, so concurrent hooks don't interleave. Secrets on the command line are
// masked first.
func (l *Logger) Write(e Entry) error {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC()
	e.Command = Redact(e.Command)
	e.Reason = Redact(e.Reason)
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(l.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(data, '\n'))
	return errors.Join(err, f.Close())
}

var secretPatterns = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:password|passwd|pwd|secret|token|api[_-]?key)[A-Z0-9_]*=)("[^"]*"|'[^']*'|\S+)`), "${1}***"},
	{regexp.MustCompile(`(?i)(--[a-z0-9-]*(?:password|passwd|secret|token|api-key)[ =])("[^"]*"|'[^']*'|\S+)`), "${1}***"},
	{regexp.MustCompile(`(?i)(authorization:\s*(?:bearer\s+|basic\s+|token\s+)?)("[^"]*"|'[^']*'|[^\s'"]+)`), "${1}***"},
	{regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+`), "${1}***"},
	{regexp.MustCompile(`(://[^/\s:@]+:)[^/\s@]+@`), "${1}***@"},
	{regexp.MustCompile(`(?i)\b((?:mysql|mariadb)\b[^|;&]*\s-p)\S+`), "${1}***"},
}

// Redact masks the common ways a credential ends up on a command line.
func Redact(s string) string {
	for _, p := range secretPatterns {
		s = p.re.ReplaceAllString(s, p.with)
	}
	return s
}

// Query selects entries from a log. Zero fields match everything.
type Query struct {
	Decision *policy.Decision
	Source   string
	Rule     string
	Text     string
	Since    time.Time
	Until    time.Time
}

func (q Query) matches(e Entry) bool {
	switch {
	case q.Decision != nil && e.Decision != *q.Decision:
		return false
	case q.Source != "" && e.Source != q.Source:
		return false
	case q.Rule != "" && !strings.Contains(e.Rule, q.Rule):
		return false
	case !q.Since.IsZero() && e.Time.Before(q.Since):
		return false
	case !q.Until.IsZero() && e.Time.After(q.Until):
		return false
	}
	if q.Text == "" {
		return true
	}
	needle := strings.ToLower(q.Text)
	for _, field := range []string{e.Command, e.Reason, e.Rule, e.CWD} {
		if strings.Contains(strings.ToLower(field), needle) {
			return true
		}
	}
	return false
}

// Search reads a log and returns matching entries, oldest first. Only the most
// recent limit entries are kept when limit is positive. A damaged line is counted
// rather than treated as fatal, since a log is most useful right after something
// went wrong.
func Search(r io.Reader, q Query, limit int) (found []Entry, damaged int, err error) {
	reader := bufio.NewReader(r)
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			var e Entry
			if err := json.Unmarshal(line, &e); err != nil {
				damaged++
			} else if q.matches(e) {
				found = append(found, e)
				if limit > 0 && len(found) > limit {
					found = found[1:]
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			return found, damaged, nil
		}
		if readErr != nil {
			return found, damaged, fmt.Errorf("reading log: %w", readErr)
		}
	}
}
