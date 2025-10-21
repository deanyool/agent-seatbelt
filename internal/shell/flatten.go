package shell

import (
	"fmt"
	"strings"
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
	if err := checkProgram(c.Args[0]); err != nil {
		return nil, err
	}
	name := c.Name()
	w, ok := wrappers[name]
	if !ok {
		return []Command{c}, nil
	}
	inner, err := w.unwrap(c, depth)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	outer := c
	outer.Wrapper = true
	out := []Command{outer}
	for _, ic := range inner {
		got, err := flattenCommand(ic, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

// checkProgram rejects a command name that the shell computes at run time. Globs
// count: /bin/r? -rf / runs rm. A leading = is a zsh expansion of a program path.
func checkProgram(w Word) error {
	switch {
	case w.Dynamic:
		return fmt.Errorf("the program name %s is only known at run time", w.Raw)
	case w.Glob:
		return fmt.Errorf("the program name %s contains a glob", w.Raw)
	case strings.HasPrefix(w.Value, "=") && !w.Quoted:
		return fmt.Errorf("the program name %s is a zsh expansion", w.Raw)
	}
	return nil
}

func child(c Command, via string, args []Word) Command {
	return Command{
		Assigns:   c.Assigns,
		Args:      args,
		Redirects: c.Redirects,
		Via:       append(append([]string(nil), c.Via...), via),
	}
}

// reparse parses text that the program will hand to a shell, such as the argument
// of bash -c or eval.
func reparse(text string, c Command, via string, depth int) ([]Command, error) {
	s, err := parseAt(text, depth+1)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", via, err)
	}
	var out []Command
	for _, ic := range s.Commands {
		// The redirects of the outer command belong to the outer shell, and the
		// inner commands inherit its environment.
		ic.Assigns = append(append([]Assign(nil), c.Assigns...), ic.Assigns...)
		ic.Via = append(append([]string(nil), c.Via...), via)
		got, err := flattenCommand(ic, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

func flattenJoined(c Command, args []Word, depth int) ([]Command, error) {
	via := c.Name()
	parts := make([]string, 0, len(args))
	for _, a := range args {
		if !a.Fixed() {
			return nil, fmt.Errorf("%s: the code to run is only known at run time", via)
		}
		parts = append(parts, a.Value)
	}
	outer := c
	outer.Wrapper = true
	got, err := reparse(strings.Join(parts, " "), c, via, depth)
	if err != nil {
		return nil, err
	}
	return append([]Command{outer}, got...), nil
}
