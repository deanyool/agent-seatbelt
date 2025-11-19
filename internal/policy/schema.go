package policy

import (
	"fmt"

	"go.yaml.in/yaml/v3"
)

// fileSchema is the YAML shape shared by policy files and presets.
type fileSchema struct {
	Version     int                     `yaml:"version"`
	Name        string                  `yaml:"name"`
	Description string                  `yaml:"description"`
	Presets     []string                `yaml:"presets"`
	Disable     []string                `yaml:"disable"`
	Settings    settingsSchema          `yaml:"settings"`
	Commands    map[string]*CommandSpec `yaml:"commands"`
	Rules       []*Rule                 `yaml:"rules"`
}

type settingsSchema struct {
	Default         *Decision `yaml:"default"`
	UnknownCommands *Decision `yaml:"unknown_commands"`
	Unparsed        *Decision `yaml:"unparsed"`
	AuditLog        string    `yaml:"audit_log"`
}

// CommandSpec teaches the matcher how a program reads its command line.
type CommandSpec struct {
	// Aliases are other program names that behave the same, like tofu for terraform.
	Aliases []string `yaml:"aliases"`
	// Global lists flags that may appear before the subcommand. An allow rule only
	// matches when every flag ahead of the subcommand is declared here, because an
	// undeclared flag might swallow the next word.
	Global GlobalFlags `yaml:"global_flags"`
	// ValueFlags take a value wherever they appear.
	ValueFlags []string `yaml:"value_flags"`
	// SingleDash means -name is one long flag, not a cluster of letters.
	SingleDash bool `yaml:"single_dash"`
}

// GlobalFlags splits declared flags by whether they take a value.
type GlobalFlags struct {
	Value []string `yaml:"value"`
	Bool  []string `yaml:"bool"`
}

// stringList accepts a YAML scalar or a sequence.
type stringList []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (l *stringList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*l = []string{n.Value}
		return nil
	case yaml.SequenceNode:
		var out []string
		if err := n.Decode(&out); err != nil {
			return err
		}
		*l = out
		return nil
	}
	return fmt.Errorf("line %d: expected a string or a list", n.Line)
}

// FlagMatch constrains which flags are present. A bare list means Any.
type FlagMatch struct {
	Any  []string `yaml:"any"`
	All  []string `yaml:"all"`
	None []string `yaml:"none"`
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (f *FlagMatch) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.SequenceNode {
		return n.Decode(&f.Any)
	}
	type plain FlagMatch
	var p plain
	if err := decodeStrict(n, &p); err != nil {
		return err
	}
	*f = FlagMatch(p)
	return nil
}

// ArgMatch constrains positional arguments. A bare list means Any.
type ArgMatch struct {
	Any  []string `yaml:"any"`
	All  []string `yaml:"all"`
	None []string `yaml:"none"`

	anyP, allP, noneP []pattern
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (a *ArgMatch) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.SequenceNode {
		return n.Decode(&a.Any)
	}
	type plain struct {
		Any  []string `yaml:"any"`
		All  []string `yaml:"all"`
		None []string `yaml:"none"`
	}
	var p plain
	if err := decodeStrict(n, &p); err != nil {
		return err
	}
	a.Any, a.All, a.None = p.Any, p.All, p.None
	return nil
}

func (a *ArgMatch) compile() error {
	var err error
	if a.anyP, err = compilePatterns(a.Any); err != nil {
		return err
	}
	if a.allP, err = compilePatterns(a.All); err != nil {
		return err
	}
	a.noneP, err = compilePatterns(a.None)
	return err
}

// Rule is one line of a policy. Every condition present must hold.
type Rule struct {
	ID         string            `yaml:"id"`
	Command    stringList        `yaml:"command"`
	Subcommand stringList        `yaml:"subcommand"`
	Flags      *FlagMatch        `yaml:"flags"`
	Args       *ArgMatch         `yaml:"args"`
	Decision   *Decision         `yaml:"decision"`
	Reason     string            `yaml:"reason"`

	paths [][]pathStep
	user  bool
}

func decodeStrict(n *yaml.Node, out any) error {
	data, err := yaml.Marshal(n)
	if err != nil {
		return err
	}
	return decodeBytes(data, out)
}
