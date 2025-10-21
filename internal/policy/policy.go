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

func (r Rule) matches(c shell.Command) bool {
	if c.Name() != r.Command {
		return false
	}
	var values []string
	for _, w := range c.Args[1:] {
		values = append(values, w.Value)
	}
	if r.Subcommand != "" && (len(values) == 0 || values[0] != r.Subcommand) {
		return false
	}
	if len(r.Flags) == 0 {
		return true
	}
	for _, v := range values {
		if slices.Contains(r.Flags, v) {
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

// Check tests every command a line would run. A line that can't be parsed is
// refused.
func (p *Policy) Check(line string) Result {
	script, err := shell.Parse(line)
	if err != nil {
		return Result{Reason: "cannot read this command: " + err.Error()}
	}
	cmds, err := shell.Flatten(script)
	if err != nil {
		return Result{Reason: "cannot read this command: " + err.Error()}
	}
	for _, c := range cmds {
		if len(c.Args) == 0 {
			continue
		}
		for _, r := range p.Rules {
			if r.matches(c) {
				return Result{Reason: r.Reason}
			}
		}
	}
	return Result{Allowed: true}
}
