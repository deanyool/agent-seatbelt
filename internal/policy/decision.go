package policy

import (
	"encoding/json"
	"fmt"

	"go.yaml.in/yaml/v3"
)

// Decision is the outcome of checking a command. The order matters: a higher
// value is stricter, and a chain of commands takes the strictest result.
type Decision int

// The three decisions a policy can reach.
const (
	Allow Decision = iota
	Confirm
	Deny
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Confirm:
		return "confirm"
	case Deny:
		return "deny"
	}
	return fmt.Sprintf("Decision(%d)", int(d))
}

// ParseDecision turns allow, confirm or deny into a Decision.
func ParseDecision(s string) (Decision, error) {
	switch s {
	case "allow":
		return Allow, nil
	case "confirm":
		return Confirm, nil
	case "deny":
		return Deny, nil
	}
	return Deny, fmt.Errorf("unknown decision %q (want allow, confirm or deny)", s)
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Decision) UnmarshalYAML(n *yaml.Node) error {
	got, err := ParseDecision(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = got
	return nil
}

// MarshalJSON implements json.Marshaler.
func (d Decision) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Decision) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	got, err := ParseDecision(s)
	if err != nil {
		return err
	}
	*d = got
	return nil
}
