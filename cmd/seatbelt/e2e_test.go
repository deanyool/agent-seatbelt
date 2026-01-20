package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These tests build the real binary and drive it the way an agent's host would.

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "seatbelt-e2e")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binary = filepath.Join(dir, "seatbelt")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type env struct {
	home string
	vars []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	home := t.TempDir()
	return &env{home: home, vars: []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"SEATBELT_AUDIT_LOG=" + filepath.Join(home, "audit.jsonl"),
		"SEATBELT_PLAN=" + filepath.Join(home, "plan.json"),
	}}
}

func (e *env) run(t *testing.T, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = e.vars
	cmd.Dir = e.home
	cmd.Stdin = strings.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return out.String(), errOut.String(), code
}

func bashPayload(command string) string {
	data, _ := json.Marshal(map[string]any{
		"session_id":      "abc123",
		"transcript_path": "/tmp/transcript.jsonl",
		"cwd":             "/tmp",
		"permission_mode": "default",
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": command, "description": "test", "timeout": 120000, "run_in_background": false},
		"tool_use_id":     "toolu_01ABC",
	})
	return string(data)
}

func TestHookBlocksDestructiveCommand(t *testing.T) {
	e := newEnv(t)
	stdout, stderr, code := e.run(t, bashPayload("rm -rf /"), "hook", "claude-code")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	var out struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout is not JSON: %q", stdout)
	}
	s := out.HookSpecificOutput
	if s.HookEventName != "PreToolUse" || s.PermissionDecision != "deny" || !strings.Contains(s.PermissionDecisionReason, "rm/delete") {
		t.Errorf("output = %+v", s)
	}
}

func TestHookStaysOutOfTheWay(t *testing.T) {
	e := newEnv(t)
	stdout, stderr, code := e.run(t, bashPayload("git status"), "hook", "claude-code")
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestHookFailureExitsTwo(t *testing.T) {
	e := newEnv(t)
	_, stderr, code := e.run(t, "this is not json", "hook", "claude-code")
	if code != 2 || !strings.Contains(stderr, "seatbelt:") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestCheckAndLogThroughTheBinary(t *testing.T) {
	e := newEnv(t)
	if _, _, code := e.run(t, "", "check", "git push --force"); code != 4 {
		t.Errorf("check code = %d", code)
	}
	e.run(t, bashPayload("kubectl delete ns prod"), "hook", "claude-code")
	stdout, _, code := e.run(t, "", "log", "--decision", "deny")
	if code != 0 || !strings.Contains(stdout, "kubectl delete ns prod") {
		t.Errorf("log: %d %q", code, stdout)
	}
}

func TestRunRefusesAndPasses(t *testing.T) {
	e := newEnv(t)
	marker := filepath.Join(e.home, "kept")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := e.run(t, "", "run", "--", "rm", marker)
	if code != 126 || !strings.Contains(stderr, "denied") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("rm got through")
	}
	stdout, _, code := e.run(t, "", "run", "--", "echo", "hello")
	if code != 0 || stdout != "hello\n" {
		t.Errorf("code=%d stdout=%q", code, stdout)
	}
}

func TestShimEndToEnd(t *testing.T) {
	e := newEnv(t)
	shims := filepath.Join(e.home, "shims")
	bin := filepath.Join(e.home, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(bin, "git")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho real git \"$@\"\nexit 9\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := e.run(t, "", "shim", "install", "--dir", shims, "git"); code != 0 {
		t.Fatalf("install: %d %q", code, stderr)
	}

	path := strings.Join([]string{shims, bin, os.Getenv("PATH")}, string(os.PathListSeparator))
	run := func(args ...string) (string, string, int) {
		cmd := exec.Command(filepath.Join(shims, "git"), args...)
		cmd.Env = []string{"HOME=" + e.home, "PATH=" + path, "SEATBELT_AUDIT_LOG=" + filepath.Join(e.home, "a.jsonl")}
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		}
		return out.String(), errOut.String(), code
	}
	stdout, stderr, code := run("status")
	if code != 9 || stdout != "real git status\n" {
		t.Errorf("allowed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	stdout, stderr, code = run("push", "--force")
	if code != 126 || stdout != "" || !strings.Contains(stderr, "force") {
		t.Errorf("denied: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestPlanApproveNeedsATerminal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /dev/tty")
	}
	e := newEnv(t)
	if _, stderr, code := e.run(t, "", "plan", "add", "--", "git", "push"); code != 0 {
		t.Fatalf("add: %d %q", code, stderr)
	}
	// With no controlling terminal, as under an agent, there is nobody to ask.
	cmd := exec.Command(binary, "plan", "approve")
	cmd.Env = e.vars
	cmd.Stdin = strings.NewReader("anything\n")
	cmd.SysProcAttr = detached()
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "needs a terminal") {
		t.Errorf("err=%v output=%q", err, out)
	}
}
