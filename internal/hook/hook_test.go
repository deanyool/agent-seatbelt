package hook

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/deanyool/agent-seatbelt/internal/policy"
)

func defaultPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// bashPayload is the documented shape of a Bash PreToolUse call.
func bashPayload(command string) string {
	data, _ := json.Marshal(map[string]any{
		"session_id":      "abc123",
		"transcript_path": "/home/user/.claude/projects/x/transcript.jsonl",
		"cwd":             "/home/user/my-project",
		"permission_mode": "default",
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input": map[string]any{
			"command":           command,
			"description":       "Run a command",
			"timeout":           120000,
			"run_in_background": false,
		},
		"tool_use_id": "toolu_01ABC123",
	})
	return string(data)
}

func decisionOf(t *testing.T, r Result) (string, string) {
	t.Helper()
	if r.Stdout == "" {
		return "", ""
	}
	var out Output
	if err := json.Unmarshal([]byte(r.Stdout), &out); err != nil {
		t.Fatalf("bad stdout %q: %v", r.Stdout, err)
	}
	if out.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("hookEventName = %q", out.HookSpecificOutput.HookEventName)
	}
	return out.HookSpecificOutput.PermissionDecision, out.HookSpecificOutput.PermissionDecisionReason
}

func TestBashDecisions(t *testing.T) {
	p := defaultPolicy(t)
	tests := []struct {
		command string
		want    string
		reason  string
	}{
		{"git status", "", ""},
		{"npm test", "", ""},
		{"git push", "ask", "changes the repository"},
		{"rm -rf /", "deny", "deleting files is never allowed"},
		{"git push --force", "deny", "force pushes"},
		{"echo 'open", "deny", "cannot read this command"},
		{"$(echo rm) x", "deny", "run time"},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			r := Run(strings.NewReader(bashPayload(tt.command)), Options{Policy: p})
			if r.Code != 0 {
				t.Fatalf("code = %d, stderr = %q", r.Code, r.Stderr)
			}
			got, reason := decisionOf(t, r)
			if got != tt.want || !strings.Contains(reason, tt.reason) {
				t.Errorf("got %q %q, want %q %q", got, reason, tt.want, tt.reason)
			}
		})
	}
}

func TestFailuresBlock(t *testing.T) {
	p := defaultPolicy(t)
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"not json", "rm -rf /"},
		{"truncated", `{"tool_name":"Bash"`},
		{"no tool", `{"hook_event_name":"PreToolUse"}`},
		{"bash without input", `{"tool_name":"Bash"}`},
		{"bash without command", `{"tool_name":"Bash","tool_input":{}}`},
		{"bash bad command type", `{"tool_name":"Bash","tool_input":{"command":1}}`},
		{"edit without path", `{"tool_name":"Edit","tool_input":{}}`},
		{"edit bad input", `{"tool_name":"Write","tool_input":[]}`},
		{"mcp bad input", `{"tool_name":"mcp__a__b","tool_input":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Run(strings.NewReader(tt.input), Options{Policy: p})
			if r.Code != 2 {
				t.Errorf("code = %d, want 2", r.Code)
			}
			if !strings.HasPrefix(r.Stderr, "seatbelt: ") {
				t.Errorf("stderr = %q", r.Stderr)
			}
		})
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestReadFailureBlocks(t *testing.T) {
	r := Run(failingReader{}, Options{Policy: defaultPolicy(t)})
	if r.Code != 2 {
		t.Errorf("code = %d", r.Code)
	}
}

func TestEditTools(t *testing.T) {
	p := defaultPolicy(t)
	tests := []struct {
		payload string
		want    string
	}{
		{`{"tool_name":"Edit","cwd":"/w","tool_input":{"file_path":"/w/src/a.go"}}`, ""},
		{`{"tool_name":"Write","cwd":"/w","tool_input":{"file_path":"/w/.git/hooks/pre-commit","content":"x"}}`, "deny"},
		{`{"tool_name":"MultiEdit","cwd":"/w","tool_input":{"file_path":".seatbelt.yaml"}}`, "deny"},
		{`{"tool_name":"NotebookEdit","cwd":"/w","tool_input":{"notebook_path":"/etc/x.ipynb"}}`, "deny"},
	}
	for _, tt := range tests {
		r := Run(strings.NewReader(tt.payload), Options{Policy: p})
		if got, _ := decisionOf(t, r); got != tt.want || r.Code != 0 {
			t.Errorf("%s: got %q code %d", tt.payload, got, r.Code)
		}
	}
}

func TestMCPTools(t *testing.T) {
	p := defaultPolicy(t)
	tests := []struct {
		payload string
		want    string
	}{
		{`{"tool_name":"mcp__crm__search","tool_input":{"q":"x"}}`, ""},
		{`{"tool_name":"mcp__crm__delete_record","tool_input":{"id":1}}`, "deny"},
		{`{"tool_name":"mcp__crm__delete_record"}`, "deny"},
	}
	for _, tt := range tests {
		r := Run(strings.NewReader(tt.payload), Options{Policy: p})
		if got, _ := decisionOf(t, r); got != tt.want || r.Code != 0 {
			t.Errorf("%s: got %q code %d", tt.payload, got, r.Code)
		}
	}
}

func TestOtherToolsAndEventsPass(t *testing.T) {
	p := defaultPolicy(t)
	for _, payload := range []string{
		`{"tool_name":"Read","tool_input":{"file_path":"/etc/passwd"}}`,
		`{"tool_name":"WebFetch","tool_input":{"url":"https://example.com"}}`,
		`{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`,
	} {
		r := Run(strings.NewReader(payload), Options{Policy: p})
		if r.Code != 0 || r.Stdout != "" {
			t.Errorf("%s: %+v", payload, r)
		}
	}
}

func TestPlanMode(t *testing.T) {
	p, err := policy.Parse([]byte("version: 1\npresets: [git]\nsettings: {confirm_mode: plan}\n"))
	if err != nil {
		t.Fatal(err)
	}
	var queued []string
	o := Options{Policy: p, Queue: func(v Verdict) (string, error) {
		queued = append(queued, v.Command)
		return "queued as a1", nil
	}}
	r := Run(strings.NewReader(bashPayload("git push")), o)
	got, reason := decisionOf(t, r)
	if got != "deny" || reason != "queued as a1" {
		t.Errorf("got %q %q", got, reason)
	}
	if len(queued) != 1 || queued[0] != "git push" {
		t.Errorf("queued = %q", queued)
	}
	o.Queue = func(Verdict) (string, error) { return "", errors.New("disk full") }
	if r := Run(strings.NewReader(bashPayload("git push")), o); r.Code != 2 {
		t.Errorf("queue failure must block: %+v", r)
	}
}

func TestObserveSeesEveryDecision(t *testing.T) {
	p := defaultPolicy(t)
	var seen []policy.Decision
	o := Options{Policy: p, Observe: func(v Verdict) {
		seen = append(seen, v.Report.Decision)
		if v.Input.SessionID != "abc123" || v.Input.CWD == "" {
			t.Errorf("verdict input = %+v", v.Input)
		}
	}}
	for _, c := range []string{"git status", "git push", "rm x"} {
		Run(strings.NewReader(bashPayload(c)), o)
	}
	if len(seen) != 3 || seen[0] != policy.Allow || seen[1] != policy.Confirm || seen[2] != policy.Deny {
		t.Errorf("seen = %v", seen)
	}
}
