package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
		Getwd:   func() (string, error) { return dir, nil },
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
