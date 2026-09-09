package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/deanyool/agent-seatbelt/internal/audit"
	"github.com/deanyool/agent-seatbelt/internal/policy"
)

func (a *App) log(args []string) int {
	flags := a.flags("log")
	policyPath := flags.String("policy", "", "policy file, for its audit_log setting")
	file := flags.String("file", "", "log file to read")
	decision := flags.String("decision", "", "only this decision: allow, confirm or deny")
	source := flags.String("source", "", "only this source: hook, shim, mcp, run or plan")
	rule := flags.String("rule", "", "only rules containing this text")
	grep := flags.String("grep", "", "only entries containing this text")
	since := flags.String("since", "", "only entries newer than this: 30m, 24h, 7d or a date")
	limit := flags.Int("limit", 50, "show at most this many of the newest entries (0 for all)")
	asJSON := flags.Bool("json", false, "print JSONL")
	if code, ok := parseFlags(flags, args); !ok {
		return code
	}
	q := audit.Query{Source: *source, Rule: *rule, Text: *grep}
	if *decision != "" {
		d, err := policy.ParseDecision(*decision)
		if err != nil {
			return a.usageError("%v", err)
		}
		q.Decision = &d
	}
	if *since != "" {
		t, err := parseSince(*since, a.Now())
		if err != nil {
			return a.usageError("%v", err)
		}
		q.Since = t
	}
	path := *file
	if path == "" {
		p, err := a.loadPolicy(*policyPath)
		if err != nil {
			return a.fail(err)
		}
		if path, err = audit.DefaultPath(p.Settings.AuditLog, a.Getenv); err != nil {
			return a.fail(err)
		}
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(a.Stderr, "no audit log at %s yet\n", path)
		return exitOK
	}
	if err != nil {
		return a.fail(err)
	}
	defer f.Close()
	found, damaged, err := audit.Search(f, q, *limit)
	if err != nil {
		return a.fail(err)
	}
	for _, e := range found {
		if *asJSON {
			data, err := json.Marshal(e)
			if err != nil {
				return a.fail(err)
			}
			fmt.Fprintln(a.Stdout, string(data))
			continue
		}
		rule := e.Rule
		if rule == "" {
			rule = "-"
		}
		fmt.Fprintf(a.Stdout, "%s  %s %-5s %s  [%s]\n", e.Time.Local().Format("2006-01-02 15:04:05"), a.colorize(e.Decision), e.Source, oneLine(e.Command), rule)
	}
	if damaged > 0 {
		fmt.Fprintf(a.Stderr, "seatbelt: skipped %d damaged line(s)\n", damaged)
	}
	return exitOK
}

var relativeTime = regexp.MustCompile(`^(\d+)([smhdw])$`)

// parseSince reads a duration back from now, or an absolute date.
func parseSince(s string, now time.Time) (time.Time, error) {
	if m := relativeTime.FindStringSubmatch(s); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return time.Time{}, err
		}
		unit := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour, "w": 7 * 24 * time.Hour}[m[2]]
		return now.Add(-time.Duration(n) * unit), nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot read --since %q (try 24h, 7d or 2026-01-31)", s)
}
