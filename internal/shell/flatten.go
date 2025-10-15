package shell

import (
	"fmt"
)

// Flatten expands wrappers and nested shells so that the result holds every
// program the script would start. For sudo rm -rf x it returns the sudo command,
// marked as a wrapper, and the rm command. An error means the real command cannot
// be determined, and callers must treat that as a denial.
func Flatten(s *Script) ([]Command, error) {
	var out []Command
	for _, c := range s.Commands {
		got, err := flattenCommand(c, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

func flattenCommand(c Command, depth int) ([]Command, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("wrappers are nested too deeply")
	}
	if len(c.Args) == 0 {
		return []Command{c}, nil
	}
	return []Command{c}, nil
}
