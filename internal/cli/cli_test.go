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

	"github.com/deanyool/agent-seatbelt/internal/plan"
	"github.com/deanyool/agent-seatbelt/internal/version"
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
			"SEATBELT_PLAN":      filepath.Join(dir, "plan.json"),
		},
	}
	t.Setenv("HOME", dir)
	self := filepath.Join(dir, "seatbelt")
	if err := os.WriteFile(self, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
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
		Exec: func(path string, argv, _ []string) error {
			h.execed = append(h.execed, path+" "+strings.Join(argv, " "))
			return nil
		},
		Executable: func() (string, error) { return self, nil },
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

func TestUsage(t *testing.T) {
	h := newHarness(t)
	if code := h.run(); code != exitUsage {
		t.Errorf("no args: %d", code)
	}
	if code := h.run("help"); code != 0 || !strings.Contains(h.out.String(), "Usage:") {
		t.Errorf("help: %d %q", code, h.out)
	}
	if code := h.run("nope"); code != exitUsage || !strings.Contains(h.err.String(), "unknown command") {
		t.Errorf("unknown: %d %q", code, h.err)
	}
	if code := h.run("version"); code != 0 || !strings.Contains(h.out.String(), version.Version) {
		t.Errorf("version: %d %q", code, h.out)
	}
}

func TestSubcommandUsageErrors(t *testing.T) {
	tests := [][]string{
		{"check"},
		{"check", "--nope"},
		{"run"},
		{"run", "-c", "ls", "--", "ls"},
		{"hook"},
		{"hook", "nope"},
		{"shim"},
		{"shim", "install"},
		{"shim", "nope"},
		{"plan"},
		{"plan", "nope"},
		{"plan", "add"},
		{"preset"},
		{"preset", "nope"},
		{"preset", "show"},
		{"policy"},
		{"policy", "nope"},
		{"mcp-proxy"},
		{"log", "--decision", "maybe"},
		{"log", "--since", "soon"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			h := newHarness(t)
			if code := h.run(args...); code != exitUsage {
				t.Errorf("code = %d, stderr %q", code, h.err)
			}
		})
	}
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

func TestRunPlanMode(t *testing.T) {
	h := newHarness(t)
	path := h.writePolicy(t, "version: 1\npresets: [git]\nsettings: {confirm_mode: plan}\n")
	if code := h.run("run", "--policy", path, "--", "git", "push"); code != exitBlocked {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(h.err.String(), "queued as") {
		t.Errorf("stderr = %q", h.err)
	}
	p, err := plan.Load(h.env["SEATBELT_PLAN"])
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Pending()) != 1 || p.Pending()[0].Command != "git push" {
		t.Errorf("plan = %+v", p)
	}
}

func TestPlanFlow(t *testing.T) {
	h := newHarness(t)
	marker := filepath.Join(h.dir, "applied")

	if code := h.run("plan", "show"); code != 0 || !strings.Contains(h.out.String(), "nothing pending") {
		t.Errorf("empty show: %d %q", code, h.out)
	}
	if code := h.run("plan", "approve"); code != 0 || !strings.Contains(h.out.String(), "nothing pending") {
		t.Errorf("empty approve: %d %q", code, h.out)
	}
	if code := h.run("plan", "add", "--", "touch", marker); code != 0 {
		t.Fatalf("add: %d %q", code, h.err)
	}
	if code := h.run("plan", "add", "--", "rm", "-rf", "/"); code != exitDeny {
		t.Errorf("denied add: %d", code)
	}
	if code := h.run("plan", "list"); code != 0 || !strings.Contains(h.out.String(), "not approved") || !strings.Contains(h.out.String(), "touch") {
		t.Errorf("list: %d %q", code, h.out)
	}
	if code := h.run("plan", "apply"); code != exitFailure || !strings.Contains(h.err.String(), "not been approved") {
		t.Errorf("unapproved apply: %d %q", code, h.err)
	}

	p, err := plan.Load(h.env["SEATBELT_PLAN"])
	if err != nil {
		t.Fatal(err)
	}
	h.tty = "wrong\n"
	if code := h.run("plan", "approve"); code != exitFailure {
		t.Errorf("wrong code: %d", code)
	}
	h.noTTY = true
	if code := h.run("plan", "approve"); code != exitFailure || !strings.Contains(h.err.String(), "needs a terminal") {
		t.Errorf("no terminal: %d %q", code, h.err)
	}
	h.noTTY = false
	h.tty = p.Digest()[:6] + "\n"
	if code := h.run("plan", "approve"); code != 0 {
		t.Fatalf("approve: %d %q", code, h.err)
	}
	if code := h.run("plan", "show"); code != 0 || !strings.Contains(h.out.String(), "1 pending, approved") {
		t.Errorf("show: %d %q", code, h.out)
	}
	if code := h.run("plan", "apply"); code != 0 {
		t.Fatalf("apply: %d %q", code, h.err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("the plan did not run")
	}
	if !strings.Contains(h.out.String(), "applied 1") {
		t.Errorf("out = %q", h.out)
	}
}

func TestPlanApplyRechecksAndReportsFailure(t *testing.T) {
	h := newHarness(t)
	path := h.env["SEATBELT_PLAN"]
	for _, c := range []string{"exit 3", "rm -rf /tmp/x", "# MCP tool call: x"} {
		h2 := newHarness(t)
		h2.env["SEATBELT_PLAN"] = path + c[:1]
		if _, err := plan.Add(h2.env["SEATBELT_PLAN"], plan.Entry{Command: c}); err != nil {
			t.Fatal(err)
		}
		p, _ := plan.Load(h2.env["SEATBELT_PLAN"])
		if err := plan.Approve(h2.env["SEATBELT_PLAN"], p.Digest(), time.Now()); err != nil {
			t.Fatal(err)
		}
		if code := h2.run("plan", "apply"); code != exitFailure {
			t.Errorf("%q: %d", c, code)
		}
		if !strings.Contains(h2.err.String(), "stopped after 0") {
			t.Errorf("%q: %q", c, h2.err)
		}
	}
}

func TestPlanClear(t *testing.T) {
	h := newHarness(t)
	h.run("plan", "add", "--", "touch", "x")
	if code := h.run("plan", "clear"); code != 0 || !strings.Contains(h.out.String(), "1 pending") {
		t.Errorf("clear: %d %q", code, h.out)
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

func TestPolicyCommands(t *testing.T) {
	h := newHarness(t)
	if code := h.run("policy", "show"); code != 0 || !strings.Contains(h.out.String(), "built-in") {
		t.Errorf("show: %d %q", code, h.out)
	}
	if code := h.run("policy", "validate"); code != 0 || !strings.Contains(h.out.String(), "valid") {
		t.Errorf("validate: %d", code)
	}
	bad := h.writePolicy(t, "version: 1\nrulez: []\n")
	if code := h.run("policy", "validate", bad); code != exitFailure {
		t.Errorf("bad: %d", code)
	}
}

func TestInit(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(h.dir, "new", "policy.yaml")
	if code := h.run("init", "--policy", path); code != 0 {
		t.Fatalf("init: %d %q", code, h.err)
	}
	if code := h.run("policy", "validate", path); code != 0 {
		t.Errorf("the starter policy doesn't load: %q", h.err)
	}
	if code := h.run("init", "--policy", path); code != exitFailure || !strings.Contains(h.err.String(), "exists") {
		t.Errorf("second init: %d %q", code, h.err)
	}
	if code := h.run("init"); code != 0 {
		t.Errorf("default path: %d %q", code, h.err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, ".config", "seatbelt", "policy.yaml")); err != nil {
		t.Error(err)
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

func TestHookPrint(t *testing.T) {
	h := newHarness(t)
	if code := h.run("hook", "print", "--policy", "/p.yaml"); code != 0 {
		t.Fatalf("code = %d", code)
	}
	var snippet map[string]any
	if err := json.Unmarshal(h.out.Bytes(), &snippet); err != nil {
		t.Fatalf("%v: %s", err, h.out)
	}
	if !strings.Contains(h.out.String(), "hook claude-code --policy") || !strings.Contains(h.out.String(), "PreToolUse") {
		t.Errorf("out = %q", h.out)
	}
}

func TestHookInstallKeepsOtherSettings(t *testing.T) {
	h := newHarness(t)
	settings := filepath.Join(h.dir, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := `{"model":"x","hooks":{"PostToolUse":[{"matcher":"Bash","hooks":[]}],"PreToolUse":[{"matcher":"Read","hooks":[]}]}}`
	if err := os.WriteFile(settings, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.run("hook", "install"); code != 0 {
		t.Fatalf("code = %d, %q", code, h.err)
	}
	data, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Model string `json:"model"`
		Hooks struct {
			Post []any `json:"PostToolUse"`
			Pre  []any `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Model != "x" || len(got.Hooks.Post) != 1 || len(got.Hooks.Pre) != 2 {
		t.Errorf("settings = %s", data)
	}
	if code := h.run("hook", "install"); code != 0 || !strings.Contains(h.out.String(), "already") {
		t.Errorf("second install: %d %q", code, h.out)
	}
	data2, _ := os.ReadFile(settings)
	if !bytes.Equal(data, data2) {
		t.Error("second install changed the file")
	}
}

func TestHookInstallProjectAndErrors(t *testing.T) {
	h := newHarness(t)
	if code := h.run("hook", "install", "--project"); code != 0 {
		t.Fatalf("code = %d, %q", code, h.err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, ".claude", "settings.json")); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"not json", `{"hooks":1}`, `{"hooks":{"PreToolUse":1}}`} {
		path := filepath.Join(h.dir, "s.json")
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := installHook(path, "x"); err == nil {
			t.Errorf("%q: want an error", bad)
		}
		data, _ := os.ReadFile(path)
		if string(data) != bad {
			t.Errorf("%q: file was changed", bad)
		}
	}
}

func TestShimCommands(t *testing.T) {
	h := newHarness(t)
	dir := filepath.Join(h.dir, "shims")
	if code := h.run("shim", "install", "--dir", dir, "git", "kubectl"); code != 0 {
		t.Fatalf("install: %d %q", code, h.err)
	}
	if !strings.Contains(h.out.String(), "export PATH") {
		t.Errorf("out = %q", h.out)
	}
	if code := h.run("shim", "list", "--dir", dir); code != 0 || h.out.String() != "git\nkubectl\n" {
		t.Errorf("list: %d %q", code, h.out)
	}
	if code := h.run("shim", "install", "--dir", dir, "a/b"); code != exitFailure {
		t.Errorf("bad name: %d", code)
	}
}

func shimEnv(t *testing.T, h *harness) string {
	t.Helper()
	bin := filepath.Join(h.dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"git", "ls"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.env["PATH"] = bin
	return bin
}

func TestShimMain(t *testing.T) {
	h := newHarness(t)
	bin := shimEnv(t, h)

	if code := h.app.Main([]string{"git", "status"}); code != 0 {
		t.Fatalf("code = %d, %q", code, h.err)
	}
	if len(h.execed) != 1 || h.execed[0] != filepath.Join(bin, "git")+" git status" {
		t.Errorf("exec = %q", h.execed)
	}
	h.execed = nil
	if code := h.app.Main([]string{"/some/where/git", "push", "--force"}); code != exitBlocked {
		t.Errorf("denied: %d", code)
	}
	if len(h.execed) != 0 {
		t.Errorf("exec = %q", h.execed)
	}
	h.noTTY = true
	if code := h.app.Main([]string{"git", "push"}); code != exitBlocked {
		t.Errorf("no terminal: %d", code)
	}
	if code := h.app.Main([]string{"nothing-here"}); code != 127 {
		t.Errorf("missing: %d", code)
	}
	if lines := h.logLines(t); len(lines) != 3 {
		t.Errorf("log = %q", lines)
	}
}

func TestShimRefusesOnBrokenPolicy(t *testing.T) {
	h := newHarness(t)
	shimEnv(t, h)
	h.env["SEATBELT_POLICY"] = h.writePolicy(t, "version: 9\n")
	if code := h.app.Main([]string{"git", "status"}); code != exitBlocked {
		t.Errorf("code = %d", code)
	}
	if len(h.execed) != 0 {
		t.Errorf("exec = %q", h.execed)
	}
}

func TestExecFailureIsReported(t *testing.T) {
	h := newHarness(t)
	shimEnv(t, h)
	h.app.Exec = func(string, []string, []string) error { return errors.New("exec failed") }
	if code := h.app.Main([]string{"ls"}); code != exitFailure {
		t.Errorf("code = %d", code)
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

func TestMCPProxyCommand(t *testing.T) {
	h := newHarness(t)
	server := filepath.Join(h.dir, "server.sh")
	script := `#!/bin/sh
while read -r line; do
  printf '{"jsonrpc":"2.0","id":1,"result":{"saw":%s}}\n' "${#line}"
done
`
	if err := os.WriteFile(server, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	h.app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_x"}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search"}}
`)
	if code := h.run("mcp-proxy", "--server", "crm", "--", server); code != 0 {
		t.Fatalf("code = %d, %q", code, h.err)
	}
	out := h.out.String()
	if !strings.Contains(out, "destroys something") || !strings.Contains(out, `"saw"`) {
		t.Errorf("out = %q", out)
	}
	if n := strings.Count(out, "\n"); n != 2 {
		t.Errorf("lines = %d: %q", n, out)
	}
	lines := h.logLines(t)
	if len(lines) != 2 || !strings.Contains(lines[0], "mcp__crm__delete_x") {
		t.Errorf("log = %q", lines)
	}
}

func TestMCPProxyStartFailure(t *testing.T) {
	h := newHarness(t)
	if code := h.run("mcp-proxy", "--", filepath.Join(h.dir, "missing")); code != exitFailure {
		t.Errorf("code = %d", code)
	}
}

func TestMCPProxyPassesExitCode(t *testing.T) {
	h := newHarness(t)
	if code := h.run("mcp-proxy", "--", "/bin/sh", "-c", "exit 5"); code != 5 {
		t.Errorf("code = %d", code)
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
