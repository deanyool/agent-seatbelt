package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/deanyool/agent-seatbelt/internal/audit"
	"github.com/deanyool/agent-seatbelt/internal/policy"
)

func (a *App) log(args []string) int {
	flags := a.flags("log")
	policyPath := flags.String("policy", "", "policy file, for its audit_log setting")
	file := flags.String("file", "", "log file to read")
	decision := flags.String("decision", "", "only this decision: allow, confirm or deny")
	source := flags.String("source", "", "only this source: hook, shim, mcp, run or plan")
	grep := flags.String("grep", "", "only entries containing this text")
	limit := flags.Int("limit", 200, "show at most this many of the newest entries (0 for all)")
	asJSON := flags.Bool("json", false, "print JSONL")
	if code, ok := parseFlags(flags, args); !ok {
		return code
	}
	q := audit.Query{Source: *source, Text: *grep}
	if *decision != "" {
		d, err := policy.ParseDecision(*decision)
		if err != nil {
			return a.usageError("%v", err)
		}
		q.Decision = &d
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
