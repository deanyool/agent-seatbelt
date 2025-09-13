// Package policy decides whether a command may run.
package policy

import (
	"fmt"
	"slices"

	"go.yaml.in/yaml/v3"

	"github.com/deanyool/agent-seatbelt/internal/presets"
	"github.com/deanyool/agent-seatbelt/internal/shell"
)

// Rule is one deny rule.
type Rule struct {
	Command    string   `yaml:"command"`
	Subcommand string   `yaml:"subcommand"`
	Flags      []string `yaml:"flags"`
	Reason     string   `yaml:"reason"`
}

// Policy is a set of rules.
type Policy struct {
	Rules []Rule `yaml:"rules"`
}

// Default loads the built-in presets.
func Default() (*Policy, error) {
	p := &Policy{}
	for _, name := range presets.Names() {
		data, err := presets.Get(name)
		if err != nil {
			return nil, err
		}
		var one Policy
		if err := yaml.Unmarshal(data, &one); err != nil {
			return nil, fmt.Errorf("preset %s: %w", name, err)
		}
		p.Rules = append(p.Rules, one.Rules...)
	}
	return p, nil
}

func (r Rule) matches(words []string) bool {
	if words[0] != r.Command {
		return false
	}
	if r.Subcommand != "" && (len(words) < 2 || words[1] != r.Subcommand) {
		return false
	}
	if len(r.Flags) == 0 {
		return true
	}
	for _, w := range words {
		if slices.Contains(r.Flags, w) {
			return true
		}
	}
	return false
}

// Result is the outcome of a check.
type Result struct {
	Allowed bool
	Reason  string
}

// Check tests every part of a command line.
func (p *Policy) Check(line string) Result {
	for _, words := range shell.Split(line) {
		for _, r := range p.Rules {
			if r.matches(words) {
				return Result{Reason: r.Reason}
			}
		}
	}
	return Result{Allowed: true}
}
