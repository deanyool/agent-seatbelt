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
