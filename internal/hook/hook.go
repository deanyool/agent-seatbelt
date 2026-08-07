// Package hook speaks the Claude Code PreToolUse hook protocol.
//
// Claude Code runs the hook before each tool call, with a JSON description of the
// call on stdin. Exit code 0 with JSON on stdout sets a permission decision. Exit
// code 2 blocks the call and shows stderr to the model. Any other exit code lets
// the call proceed, so a hook that means to block must never exit 1: every failure
// path here ends in exit 2.
package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/deanyool/agent-seatbelt/internal/policy"
)

// maxInput bounds how much of stdin is read. A Write tool call carries a whole
// file, so this is large, but it is still a bound.
const maxInput = 64 << 20

// Input is the hook payload. Unknown fields are ignored, since Claude Code adds
// new ones over time.
type Input struct {
	SessionID     string          `json:"session_id"`
	CWD           string          `json:"cwd"`
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
}

// Output is the JSON a hook prints to set a decision.
type Output struct {
	HookSpecificOutput SpecificOutput `json:"hookSpecificOutput"`
}

// SpecificOutput is the PreToolUse part of Output.
type SpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// Result is what the process should print and return.
type Result struct {
	Stdout string
	Stderr string
	Code   int
}

// Verdict is one evaluated tool call, handed to the caller for logging.
type Verdict struct {
	Input   Input
	Command string
	Report  policy.Report
}

// Options configure the hook.
type Options struct {
	Policy *policy.Policy
	// Observe is called with each verdict, for the audit log.
	Observe func(Verdict)
	// Queue handles a confirm decision when the policy says to plan. It returns
	// the message for the model.
	Queue func(Verdict) (string, error)
}

// block ends the hook with a refusal that doesn't depend on parsing any JSON.
func block(format string, args ...any) Result {
	return Result{Stderr: "seatbelt: " + fmt.Sprintf(format, args...) + "\n", Code: 2}
}

// Run handles one hook call.
func Run(stdin io.Reader, o Options) Result {
	data, err := io.ReadAll(io.LimitReader(stdin, maxInput+1))
	if err != nil {
		return block("cannot read the hook payload: %v", err)
	}
	if len(data) > maxInput {
		return block("hook payload is too large to inspect")
	}
	var in Input
	if err := json.Unmarshal(data, &in); err != nil {
		return block("cannot parse the hook payload: %v", err)
	}
	if in.HookEventName != "" && in.HookEventName != "PreToolUse" {
		return Result{}
	}
	if in.ToolName == "" {
		return block("hook payload has no tool_name")
	}
	command, rep, handled, err := evaluate(in, o.Policy)
	if err != nil {
		return block("%v", err)
	}
	if !handled {
		return Result{}
	}
	v := Verdict{Input: in, Command: command, Report: rep}
	if o.Observe != nil {
		o.Observe(v)
	}
	switch rep.Decision {
	case policy.Allow:
		return Result{}
	case policy.Confirm:
		if o.Policy.Settings.ConfirmMode == policy.ConfirmPlan && o.Queue != nil {
			msg, err := o.Queue(v)
			if err != nil {
				return block("cannot queue this command: %v", err)
			}
			return decide("deny", msg)
		}
		return decide("ask", rep.Reason())
	}
	return decide("deny", "seatbelt: "+rep.Reason())
}

func decide(decision, reason string) Result {
	out, err := json.Marshal(Output{HookSpecificOutput: SpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       decision,
		PermissionDecisionReason: reason,
	}})
	if err != nil {
		return block("cannot encode the decision: %v", err)
	}
	return Result{Stdout: string(out) + "\n"}
}

// evaluate picks the check for a tool. handled is false for tools that have nothing
// for a command policy to look at.
func evaluate(in Input, p *policy.Policy) (string, policy.Report, bool, error) {
	opts := policy.Options{CWD: in.CWD}
	switch {
	case in.ToolName == "Bash":
		var input struct {
			Command *string `json:"command"`
		}
		if err := json.Unmarshal(in.ToolInput, &input); err != nil {
			return "", policy.Report{}, false, fmt.Errorf("cannot read the Bash tool input: %w", err)
		}
		if input.Command == nil {
			return "", policy.Report{}, false, errors.New("the Bash tool input has no command")
		}
		return *input.Command, p.Evaluate(*input.Command, opts), true, nil
	case in.ToolName == "Edit", in.ToolName == "MultiEdit", in.ToolName == "Write", in.ToolName == "NotebookEdit":
		var input struct {
			FilePath     string `json:"file_path"`
			NotebookPath string `json:"notebook_path"`
		}
		if err := json.Unmarshal(in.ToolInput, &input); err != nil {
			return "", policy.Report{}, false, fmt.Errorf("cannot read the %s tool input: %w", in.ToolName, err)
		}
		path := input.FilePath
		if path == "" {
			path = input.NotebookPath
		}
		if path == "" {
			return "", policy.Report{}, false, fmt.Errorf("the %s tool input has no file path", in.ToolName)
		}
		return in.ToolName + " " + path, p.EvaluateWrite(path, opts), true, nil
	case strings.HasPrefix(in.ToolName, "mcp__"):
		var input map[string]any
		if len(in.ToolInput) > 0 {
			if err := json.Unmarshal(in.ToolInput, &input); err != nil {
				return "", policy.Report{}, false, fmt.Errorf("cannot read the %s tool input: %w", in.ToolName, err)
			}
		}
		return in.ToolName, p.EvaluateTool(in.ToolName, input), true, nil
	}
	return "", policy.Report{}, false, nil
}
