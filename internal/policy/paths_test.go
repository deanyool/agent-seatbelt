package policy

import "testing"

// withWindowsPaths runs a test under the Windows path rules, whatever this
// system is.
func withWindowsPaths(t *testing.T, home string) {
	t.Helper()
	old := windowsPaths
	windowsPaths = true
	t.Cleanup(func() { windowsPaths = old })
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func TestResolveWindowsPath(t *testing.T) {
	home := `C:\Users\dev`
	cases := []struct{ path, cwd, want string }{
		{`C:\Users\dev\.ssh\id_ed25519`, "", "c:/users/dev/.ssh/id_ed25519"},
		{"C:/Users/dev/.ssh/config", "", "c:/users/dev/.ssh/config"},
		{"/c/Users/dev/.ssh/config", "", "c:/users/dev/.ssh/config"},
		{"/c", "", "c:/"},
		{"~/.aws/credentials", "", "c:/users/dev/.aws/credentials"},
		{"~", "", "c:/users/dev"},
		{`.claude\settings.json`, `D:\src\app`, "d:/src/app/.claude/settings.json"},
		{"../app/.seatbelt.yaml", "/d/src/tools", "d:/src/app/.seatbelt.yaml"},
		{"/etc/hosts", `E:\work`, "e:/etc/hosts"},
		{`\\server\share\x\..\y`, "", "//server/share/y"},
		{"C:/a/../../b", "", "c:/b"},
		{"/cd/x", `C:\w`, "c:/cd/x"},
	}
	for _, c := range cases {
		if got := resolveWindowsPath(c.path, c.cwd, home); got != c.want {
			t.Errorf("resolveWindowsPath(%q, %q) = %q, want %q", c.path, c.cwd, got, c.want)
		}
	}
}

func TestExpandWindowsPattern(t *testing.T) {
	home := `C:\Users\dev`
	cases := map[string]string{
		"~/.ssh/*":                 "c:/users/dev/.ssh/*",
		"~":                        "c:/users/dev",
		".claude/settings*.json":   "*/.claude/settings*.json",
		`D:\Secrets\*`:             "d:/secrets/*",
		`re:(?i)^c:/users/.*\.pem`: `re:(?i)^c:/users/.*\.pem`,
	}
	for in, want := range cases {
		if got := expandWindowsPattern(in, home); got != want {
			t.Errorf("expandWindowsPattern(%q) = %q, want %q", in, got, want)
		}
	}
}

// The same protected file, written three ways from Git Bash and once by an edit
// tool, must be refused every time.
func TestProtectedPathsOnWindows(t *testing.T) {
	withWindowsPaths(t, `C:\Users\dev`)
	p, err := Parse([]byte("version: 1\npresets: [rm]\n"))
	if err != nil {
		t.Fatal(err)
	}
	o := Options{CWD: `C:\Users\dev\src\app`}
	for _, cmd := range []string{
		`echo x > C:/Users/dev/.ssh/authorized_keys`,
		`echo x > /c/Users/dev/.ssh/authorized_keys`,
		`echo x > ~/.SSH/authorized_keys`,
		`cp evil.json .claude/settings.json`,
		`tee -a ../app/.Claude/Settings.local.json`,
	} {
		if rep := p.Evaluate(cmd, o); rep.Decision != Deny {
			t.Errorf("%s: got %s, want deny", cmd, rep.Decision)
		}
	}
	for _, path := range []string{
		`C:\Users\dev\.seatbelt\audit.jsonl`,
		`c:\users\DEV\.config\seatbelt\policy.yaml`,
		`C:\Users\dev\src\app\.claude\settings.json`,
	} {
		if rep := p.EvaluateWrite(path, o); rep.Decision != Deny {
			t.Errorf("write %s: got %s, want deny", path, rep.Decision)
		}
	}
	for _, cmd := range []string{`echo x > C:/Users/dev/notes.txt`, `cp evil.json backup.json`} {
		if rep := p.Evaluate(cmd, o); rep.Decision != Allow {
			t.Errorf("%s: got %s, want allow", cmd, rep.Decision)
		}
	}
	if rep := p.EvaluateWrite(`C:\Users\dev\src\app\main.go`, o); rep.Decision != Allow {
		t.Errorf("ordinary file: got %s, want allow", rep.Decision)
	}
}
