package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/deanyool/agent-seatbelt/internal/presets"
)

func decodeBytes(data []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// Load reads a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Source = path
	return p, nil
}

// Default returns the built-in policy: every preset with default settings.
func Default() (*Policy, error) {
	p, err := Parse([]byte("version: 1\npresets: [all]\n"))
	if err != nil {
		return nil, err
	}
	p.Source = "built-in"
	return p, nil
}

// Parse builds a policy from YAML. It rejects unknown fields, so a typo in a rule
// can't silently turn the rule into something that never matches.
func Parse(data []byte) (*Policy, error) {
	var f fileSchema
	if err := decodeBytes(data, &f); err != nil {
		return nil, err
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("unsupported version %d (want 1)", f.Version)
	}

	b := newBuilder()
	names := f.Presets
	if slices.Contains(names, "all") {
		names = presets.Names()
	}
	if !slices.Contains(names, presets.Self) {
		names = append([]string{presets.Self}, names...)
	}
	for _, name := range names {
		data, err := presets.Get(name)
		if err != nil {
			return nil, err
		}
		var pf fileSchema
		if err := decodeBytes(data, &pf); err != nil {
			return nil, fmt.Errorf("preset %s: %w", name, err)
		}
		if err := b.add(&pf, name, false); err != nil {
			return nil, fmt.Errorf("preset %s: %w", name, err)
		}
		b.policy.Presets = append(b.policy.Presets, name)
	}
	if err := b.add(&f, "", true); err != nil {
		return nil, err
	}
	if err := b.disable(f.Disable); err != nil {
		return nil, err
	}
	if err := b.settings(&f.Settings); err != nil {
		return nil, err
	}
	return b.policy, nil
}

type builder struct {
	policy *Policy
	seen   map[string]bool
}

func newBuilder() *builder {
	return &builder{
		policy: &Policy{
			Settings: Settings{
				Default:         Deny,
				UnknownCommands: Allow,
				Unparsed:        Deny,
			},
			specs:   map[string]*CommandSpec{},
			aliases: map[string]string{},
			rules:   map[string][]*Rule{},
		},
		seen: map[string]bool{},
	}
}

func (b *builder) add(f *fileSchema, prefix string, user bool) error {
	for name, spec := range f.Commands {
		name = strings.ToLower(name)
		if _, dup := b.policy.specs[name]; dup {
			return fmt.Errorf("command %s is defined twice", name)
		}
		b.policy.specs[name] = spec
		for _, alias := range spec.Aliases {
			b.policy.aliases[strings.ToLower(alias)] = name
		}
	}
	for i, r := range f.Rules {
		if r.ID == "" {
			return fmt.Errorf("rule %d has no id", i+1)
		}
		if prefix != "" {
			r.ID = prefix + "/" + r.ID
		}
		if b.seen[r.ID] {
			return fmt.Errorf("duplicate rule id %s", r.ID)
		}
		b.seen[r.ID] = true
		r.user = user
		if err := b.compileRule(r); err != nil {
			return fmt.Errorf("rule %s: %w", r.ID, err)
		}
	}
	return nil
}

func (b *builder) compileRule(r *Rule) error {
	if r.Decision == nil {
		return errors.New("missing decision")
	}
	if len(r.Command) == 0 {
		return errors.New("missing command")
	}
	for _, s := range r.Subcommand {
		steps, err := compilePath(s)
		if err != nil {
			return err
		}
		if len(steps) == 0 {
			return errors.New("empty subcommand")
		}
		r.paths = append(r.paths, steps)
	}
	if r.Args != nil {
		if err := r.Args.compile(); err != nil {
			return err
		}
	}
	for _, m := range r.FlagValues {
		if err := m.compile(); err != nil {
			return err
		}
	}
	for _, name := range r.Command {
		if name == "*" {
			b.policy.anyRules = append(b.policy.anyRules, r)
			continue
		}
		name = strings.ToLower(name)
		b.policy.rules[name] = append(b.policy.rules[name], r)
	}
	return nil
}

func (b *builder) disable(ids []string) error {
	drop := map[string]bool{}
	for _, id := range ids {
		if !b.seen[id] {
			return fmt.Errorf("disable: no rule named %s", id)
		}
		drop[id] = true
	}
	for name, rules := range b.policy.rules {
		b.policy.rules[name] = slices.DeleteFunc(rules, func(r *Rule) bool { return drop[r.ID] })
	}
	b.policy.anyRules = slices.DeleteFunc(b.policy.anyRules, func(r *Rule) bool { return drop[r.ID] })
	return nil
}

func (b *builder) settings(s *settingsSchema) error {
	set := &b.policy.Settings
	assign := func(dst *Decision, src *Decision) {
		if src != nil {
			*dst = *src
		}
	}
	assign(&set.Default, s.Default)
	assign(&set.UnknownCommands, s.UnknownCommands)
	assign(&set.Unparsed, s.Unparsed)
	if set.Unparsed == Allow {
		return errors.New("settings.unparsed cannot be allow: a command that can't be read can't be trusted")
	}
	set.AuditLog = s.AuditLog
	return nil
}
