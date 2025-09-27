// Package hook is the Claude Code PreToolUse hook.
package hook

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/deanyool/agent-seatbelt/internal/policy"
)

type input struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

type output struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

// Run reads the hook payload and returns the exit code. A denial is reported as
// JSON so the reason reaches the model. Exit 2 is for failures: any other nonzero
// code is treated as a broken hook and the tool call runs anyway.
func Run(stdin io.Reader, stdout, stderr io.Writer, p *policy.Policy) int {
	var in input
	if err := json.NewDecoder(stdin).Decode(&in); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if in.ToolName != "Bash" {
		return 0
	}
	r := p.Check(in.ToolInput.Command)
	if r.Allowed {
		return 0
	}
	var out output
	out.HookSpecificOutput.HookEventName = "PreToolUse"
	out.HookSpecificOutput.PermissionDecision = "deny"
	out.HookSpecificOutput.PermissionDecisionReason = r.Reason
	if err := json.NewEncoder(stdout).Encode(out); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}
