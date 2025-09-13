package policy

import "testing"

func TestDefaultPolicy(t *testing.T) {
	p, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		line string
		want bool
	}{
		{"ls", true},
		{"git status", true},
		{"rm x", false},
		{"ls && rm x", false},
		{"git push --force", false},
		{"git push", true},
		{"git reset --hard", false},
	}
	for _, tt := range tests {
		if got := p.Check(tt.line).Allowed; got != tt.want {
			t.Errorf("%q: got %v", tt.line, got)
		}
	}
}
