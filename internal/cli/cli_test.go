package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

)

type harness struct {
	app    *App
	out    *bytes.Buffer
	err    *bytes.Buffer
	dir    string
	env    map[string]string
	tty    string
	noTTY  bool
	execed []string
}

type fakeTTY struct {
	in  io.Reader
	out bytes.Buffer
}

func (f *fakeTTY) Read(p []byte) (int, error)  { return f.in.Read(p) }
func (f *fakeTTY) Write(p []byte) (int, error) { return f.out.Write(p) }
func (f *fakeTTY) Close() error                { return nil }
func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{
		out: &bytes.Buffer{},
		err: &bytes.Buffer{},
		dir: dir,
		env: map[string]string{
			"SEATBELT_POLICY":    "",
			"SEATBELT_AUDIT_LOG": filepath.Join(dir, "audit.jsonl"),
		},
	}
	t.Setenv("HOME", dir)
	h.app = &App{
		Stdin:   strings.NewReader(""),
		Stdout:  h.out,
		Stderr:  h.err,
		Getenv:  func(k string) string { return h.env[k] },
		Environ: func() []string { return []string{"PATH=/usr/bin:/bin"} },
		Getwd:   func() (string, error) { return dir, nil },
		Now:     func() time.Time { return time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC) },
		OpenTTY: func() (io.ReadWriteCloser, error) {
			if h.noTTY {
				return nil, errors.New("no terminal")
			}
			return &fakeTTY{in: strings.NewReader(h.tty)}, nil
		},
	}
	return h
}

func (h *harness) run(args ...string) int {
	h.out.Reset()
	h.err.Reset()
	return h.app.Main(append([]string{"seatbelt"}, args...))
}

func (h *harness) writePolicy(t *testing.T, src string) string {
	t.Helper()
	path := filepath.Join(h.dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (h *harness) logLines(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(h.env["SEATBELT_AUDIT_LOG"])
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func TestCheckExitCodes(t *testing.T) {
	h := newHarness(t)
	tests := []struct {
		args []string
		code int
		text string
	}{
		{[]string{"check", "git status"}, exitOK, "ALLOW"},
		{[]string{"check", "git push"}, exitConfirm, "CONFIRM"},
		{[]string{"check", "rm -rf /"}, exitDeny, "DENY"},
		{[]string{"check", "git", "push", "--force"}, exitDeny, "force"},
		{[]string{"check", "--", "git", "log", "$HOME"}, exitOK, "ALLOW"},
		{[]string{"check", "--", "rm", "x"}, exitDeny, "DENY"},
		{[]string{"check", "# only a comment"}, exitOK, "nothing to run"},
	}
	for _, tt := range tests {
		if code := h.run(tt.args...); code != tt.code || !strings.Contains(h.out.String(), tt.text) {
			t.Errorf("%q: code %d, output %q", tt.args, code, h.out)
		}
	}
}

func TestCheckStdinAndJSON(t *testing.T) {
	h := newHarness(t)
	h.app.Stdin = strings.NewReader("git status && rm x\n")
	if code := h.run("check", "--json", "-"); code != exitDeny {
		t.Fatalf("code = %d", code)
	}
	var rep struct {
		Decision string `json:"decision"`
		Findings []struct {
			Decision string `json:"decision"`
			Rule     string `json:"rule"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(h.out.Bytes(), &rep); err != nil {
		t.Fatalf("%v: %s", err, h.out)
	}
	if rep.Decision != "deny" || len(rep.Findings) != 2 || rep.Findings[1].Rule != "rm/delete" {
		t.Errorf("rep = %+v", rep)
	}
}

func TestColorOutput(t *testing.T) {
	h := newHarness(t)
	h.app.Color = true
	h.run("check", "rm x")
	if !strings.Contains(h.out.String(), "\x1b[1;31m") {
		t.Errorf("no color in %q", h.out)
	}
}

func TestLongCommandsAreCut(t *testing.T) {
	h := newHarness(t)
	h.run("check", "echo "+strings.Repeat("x", 300)+"\necho y")
	if !strings.Contains(h.out.String(), "...") || strings.Contains(h.out.String(), strings.Repeat("x", 200)) {
		t.Errorf("output = %q", h.out)
	}
}

func TestPolicySelection(t *testing.T) {
	h := newHarness(t)
	path := h.writePolicy(t, "version: 1\nrules:\n- {id: no-ls, command: ls, decision: deny}\n")

	if code := h.run("check", "--policy", path, "ls"); code != exitDeny {
		t.Errorf("--policy: %d", code)
	}
	h.env["SEATBELT_POLICY"] = path
	if code := h.run("check", "ls"); code != exitDeny {
		t.Errorf("env: %d", code)
	}
	h.env["SEATBELT_POLICY"] = ""

	user := filepath.Join(h.dir, ".config", "seatbelt", "policy.yaml")
	if err := os.MkdirAll(filepath.Dir(user), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(user, []byte("version: 1\nrules:\n- {id: no-cat, command: cat, decision: deny}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.run("check", "cat x"); code != exitDeny {
		t.Errorf("user file: %d", code)
	}
	if code := h.run("check", "--policy", filepath.Join(h.dir, "missing.yaml"), "ls"); code != exitFailure {
		t.Errorf("missing file: %d", code)
	}
}

func TestRun(t *testing.T) {
	h := newHarness(t)
	marker := filepath.Join(h.dir, "ran")
	if code := h.run("run", "--", "/usr/bin/touch", marker); code != 0 {
		t.Fatalf("code = %d, %q", code, h.err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("the command did not run")
	}
	if code := h.run("run", "-c", "exit 7"); code != 7 {
		t.Errorf("exit code = %d", code)
	}
	if code := h.run("run", "--", "/nonexistent/x"); code != 127 {
		t.Errorf("missing program = %d", code)
	}
	if code := h.run("run", "--", "rm", marker); code != exitBlocked {
		t.Errorf("rm = %d", code)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("rm ran")
	}
	if !strings.Contains(h.err.String(), "denied") {
		t.Errorf("stderr = %q", h.err)
	}
	if lines := h.logLines(t); len(lines) != 4 {
		t.Errorf("log = %q", lines)
	}
}

func TestRunConfirm(t *testing.T) {
	path := func(h *harness) string {
		return h.writePolicy(t, "version: 1\nrules:\n- {id: c, command: touch, decision: confirm, reason: asks}\n")
	}
	h := newHarness(t)
	marker := filepath.Join(h.dir, "m")
	h.tty = "n\n"
	if code := h.run("run", "--policy", path(h), "--", "touch", marker); code != exitBlocked {
		t.Errorf("declined: %d", code)
	}
	h.tty = "yes\n"
	if code := h.run("run", "--policy", path(h), "--", "touch", marker); code != 0 {
		t.Errorf("accepted: %d %q", code, h.err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("not run after yes")
	}
	lines := h.logLines(t)
	if len(lines) != 3 || !strings.Contains(lines[2], "confirmed by a person") {
		t.Errorf("log = %q", lines)
	}
	h.noTTY = true
	if code := h.run("run", "--policy", path(h), "--", "touch", marker); code != exitBlocked {
		t.Errorf("no terminal: %d", code)
	}
	if !strings.Contains(h.err.String(), "no terminal") {
		t.Errorf("stderr = %q", h.err)
	}
}

func TestPresetCommands(t *testing.T) {
	h := newHarness(t)
	if code := h.run("preset", "list"); code != 0 || !strings.Contains(h.out.String(), "kubectl") {
		t.Errorf("list: %d %q", code, h.out)
	}
	if code := h.run("preset", "show", "git"); code != 0 || !strings.Contains(h.out.String(), "force-push") {
		t.Errorf("show: %d", code)
	}
	if code := h.run("preset", "show", "nope"); code != exitFailure {
		t.Errorf("unknown: %d", code)
	}
}

func hookPayload(command string) string {
	data, _ := json.Marshal(map[string]any{
		"session_id":      "s1",
		"cwd":             "/w",
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": command},
	})
	return string(data)
}

func TestHookCommand(t *testing.T) {
	h := newHarness(t)
	h.app.Stdin = strings.NewReader(hookPayload("rm -rf /"))
	if code := h.run("hook", "claude-code"); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(h.out.String(), `"permissionDecision":"deny"`) {
		t.Errorf("out = %q", h.out)
	}
	lines := h.logLines(t)
	if len(lines) != 1 || !strings.Contains(lines[0], `"source":"hook"`) || !strings.Contains(lines[0], `"session":"s1"`) {
		t.Errorf("log = %q", lines)
	}

	h.app.Stdin = strings.NewReader("garbage")
	if code := h.run("hook", "claude-code"); code != 2 {
		t.Errorf("bad payload: %d", code)
	}

	bad := h.writePolicy(t, "version: 9\n")
	h.app.Stdin = strings.NewReader(hookPayload("ls"))
	if code := h.run("hook", "claude-code", "--policy", bad); code != 2 {
		t.Errorf("a broken policy must block: %d", code)
	}
	if code := h.run("hook", "claude-code", "--nope"); code != 2 {
		t.Errorf("a bad flag must block: %d", code)
	}
}

func TestAuditFailureDoesNotChangeTheDecision(t *testing.T) {
	h := newHarness(t)
	h.env["SEATBELT_AUDIT_LOG"] = "/dev/null/nope/audit.jsonl"
	h.app.Stdin = strings.NewReader(hookPayload("rm x"))
	if code := h.run("hook", "claude-code"); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(h.out.String(), `"deny"`) || !strings.Contains(h.err.String(), "audit log") {
		t.Errorf("out=%q err=%q", h.out, h.err)
	}
}

func TestReadLine(t *testing.T) {
	got, err := readLine(strings.NewReader("abc\ndef"))
	if err != nil || got != "abc" {
		t.Errorf("%q %v", got, err)
	}
	got, err = readLine(strings.NewReader("abc"))
	if !errors.Is(err, io.EOF) || got != "abc" {
		t.Errorf("%q %v", got, err)
	}
}
