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

// Run reads the hook payload and returns the exit code. Exit 2 is what blocks a
// tool call. Any other nonzero code is treated as a hook failure and the call runs.
func Run(stdin io.Reader, _, stderr io.Writer, p *policy.Policy) int {
	var in input
	if err := json.NewDecoder(stdin).Decode(&in); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if in.ToolName != "Bash" {
		return 0
	}
	if r := p.Check(in.ToolInput.Command); !r.Allowed {
		fmt.Fprintln(stderr, "blocked:", r.Reason)
		return 2
	}
	return 0
}
