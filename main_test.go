package main

import "testing"

func TestCheck(t *testing.T) {
	cfg := rules{Deny: []rule{
		{Command: "rm"},
		{Command: "git", Subcommand: "push", Flags: []string{"--force"}},
	}}
	tests := []struct {
		line string
		want bool
	}{
		{"ls -la", true},
		{"rm -rf /", false},
		{"git push", true},
		{"git push --force", false},
		{"ls && rm x", false},
		{"ls; rm x", false},
		{"ls | rm x", false},
	}
	for _, tt := range tests {
		if got := check(cfg, tt.line); got != tt.want {
			t.Errorf("%q: got %v", tt.line, got)
		}
	}
}
