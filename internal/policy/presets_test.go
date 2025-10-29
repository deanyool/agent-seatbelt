package policy

import (
	"testing"
)

func loadDefault(t testing.TB) *Policy {
	t.Helper()
	p, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// expect checks a table of commands against one decision.
func expect(t *testing.T, want Decision, commands ...string) {
	t.Helper()
	p := loadDefault(t)
	for _, c := range commands {
		rep := p.Evaluate(c, Options{CWD: "/work"})
		if rep.Decision != want {
			t.Errorf("%q: got %s, want %s\n  %s", c, rep.Decision, want, rep.Reason())
		}
	}
}
