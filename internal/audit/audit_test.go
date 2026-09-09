package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deanyool/agent-seatbelt/internal/policy"
)

func TestWriteAndSearch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "audit.jsonl")
	l := &Logger{Path: path}
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	entries := []Entry{
		{Time: base, Source: "hook", Command: "git status", Decision: policy.Allow, Rule: "git/read"},
		{Time: base.Add(time.Hour), Source: "hook", Command: "rm -rf /", Decision: policy.Deny, Rule: "rm/delete", Reason: "never"},
		{Time: base.Add(2 * time.Hour), Source: "shim", Command: "git push", Decision: policy.Confirm, Rule: "git/write", CWD: "/srv/app"},
	}
	for _, e := range entries {
		if err := l.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}

	deny := policy.Deny
	tests := []struct {
		name  string
		q     Query
		limit int
		want  []string
	}{
		{"all", Query{}, 0, []string{"git status", "rm -rf /", "git push"}},
		{"decision", Query{Decision: &deny}, 0, []string{"rm -rf /"}},
		{"source", Query{Source: "shim"}, 0, []string{"git push"}},
		{"rule", Query{Rule: "git/"}, 0, []string{"git status", "git push"}},
		{"text", Query{Text: "GIT"}, 0, []string{"git status", "git push"}},
		{"text in reason", Query{Text: "never"}, 0, []string{"rm -rf /"}},
		{"text in cwd", Query{Text: "/srv"}, 0, []string{"git push"}},
		{"since", Query{Since: base.Add(90 * time.Minute)}, 0, []string{"git push"}},
		{"until", Query{Until: base.Add(30 * time.Minute)}, 0, []string{"git status"}},
		{"limit keeps newest", Query{}, 2, []string{"rm -rf /", "git push"}},
		{"nothing", Query{Text: "absent"}, 0, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			found, damaged, err := Search(f, tt.q, tt.limit)
			if err != nil || damaged != 0 {
				t.Fatalf("err=%v damaged=%d", err, damaged)
			}
			var got []string
			for _, e := range found {
				got = append(got, e.Command)
			}
			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSearchSurvivesDamage(t *testing.T) {
	log := `{"command":"a","decision":"allow"}
not json
{"command":"b","decision":"nonsense"}
{"command":"c","decision":"deny"}`
	found, damaged, err := Search(strings.NewReader(log), Query{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 || damaged != 2 {
		t.Errorf("found=%d damaged=%d", len(found), damaged)
	}
}

func TestConcurrentWritesStayWhole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l := &Logger{Path: path}
			cmd := strings.Repeat("x", 2000+i)
			if err := l.Write(Entry{Source: "hook", Command: cmd}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 40 {
		t.Fatalf("lines = %d", len(lines))
	}
	for _, line := range lines {
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("damaged line: %v", err)
		}
	}
}

func TestWriteDefaultsTimeAndRedacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	l := &Logger{Path: path}
	if err := l.Write(Entry{Command: "curl -H 'Authorization: Bearer abc123' x"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "abc123") {
		t.Errorf("secret reached the log: %s", data)
	}
	var e Entry
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	if e.Time.IsZero() {
		t.Error("time not set")
	}
}

func TestRedact(t *testing.T) {
	tests := []struct{ in, want string }{
		{"PGPASSWORD=hunter2 psql", "PGPASSWORD=*** psql"},
		{"API_KEY='a b' run", "API_KEY=*** run"},
		{"GITHUB_TOKEN=abc gh pr list", "GITHUB_TOKEN=*** gh pr list"},
		{"tool --password hunter2 x", "tool --password *** x"},
		{"tool --api-key=abc", "tool --api-key=***"},
		{"tool --db-password \"a b\" x", "tool --db-password *** x"},
		{"curl -H 'Authorization: Bearer abc' x", "curl -H 'Authorization: Bearer ***' x"},
		{"curl -H \"authorization: token abc\" x", "curl -H \"authorization: token ***\" x"},
		{"x bearer abc.def", "x bearer ***"},
		{"git clone https://me:hunter2@example.com/r", "git clone https://me:***@example.com/r"},
		{"mysql -u root -phunter2 db", "mysql -u root -p*** db"},
		{"git status", "git status"},
		{"grep -p foo", "grep -p foo"},
	}
	for _, tt := range tests {
		if got := Redact(tt.in); got != tt.want {
			t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDefaultPath(t *testing.T) {
	env := func(string) string { return "" }
	if got, _ := DefaultPath("/a/b", env); got != "/a/b" {
		t.Errorf("setting: %q", got)
	}
	if got, _ := DefaultPath("~/logs/a.jsonl", env); !strings.HasSuffix(got, "/logs/a.jsonl") || strings.HasPrefix(got, "~") {
		t.Errorf("tilde: %q", got)
	}
	got, _ := DefaultPath("", func(k string) string {
		if k == "SEATBELT_AUDIT_LOG" {
			return "/c"
		}
		return ""
	})
	if got != "/c" {
		t.Errorf("env: %q", got)
	}
	got, err := DefaultPath("", env)
	if err != nil || !strings.HasSuffix(got, filepath.Join(".seatbelt", "audit.jsonl")) {
		t.Errorf("default: %q %v", got, err)
	}
}
