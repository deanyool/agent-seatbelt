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
	switch {
	case isShell(name):
		return flattenShell(c, depth)
	case name == "eval":
		return flattenJoined(c, c.Args[1:], depth)
	case name == "find":
		return flattenFind(c, depth)
	}
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

func isShell(name string) bool {
	switch name {
	case "sh", "bash", "zsh", "dash", "ksh", "ash", "fish":
		return true
	}
	return false
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

// flattenShell handles sh, bash and friends. With -c the script is parsed in
// place. With a file it is an ordinary program whose contents are out of reach.
// With neither, it runs whatever arrives on stdin, which can't be inspected.
func flattenShell(c Command, depth int) ([]Command, error) {
	name := c.Name()
	args := c.Args[1:]
	takesCode := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a.Dynamic {
			return nil, fmt.Errorf("%s: arguments are only known at run time", name)
		}
		v := a.Value
		switch {
		case v == "--" || v == "-":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s: reads commands from stdin", name)
			}
			i++
			return shellOperand(c, args[i], takesCode, depth)
		case v == "--rcfile", v == "--init-file", v == "-o", v == "+o", v == "-O", v == "+O":
			i++
		case strings.HasPrefix(v, "--"):
		case strings.HasPrefix(v, "-") || strings.HasPrefix(v, "+"):
			if strings.ContainsRune(v, 's') {
				return nil, fmt.Errorf("%s: reads commands from stdin", name)
			}
			if strings.ContainsRune(v, 'c') {
				takesCode = true
			}
			if last := v[len(v)-1]; last == 'o' || last == 'O' {
				i++
			}
		default:
			return shellOperand(c, a, takesCode, depth)
		}
	}
	return nil, fmt.Errorf("%s: reads commands from stdin", name)
}

func shellOperand(c Command, operand Word, takesCode bool, depth int) ([]Command, error) {
	if !takesCode {
		return []Command{c}, nil
	}
	if !operand.Fixed() {
		return nil, fmt.Errorf("%s -c: the script is only known at run time", c.Name())
	}
	got, err := reparse(operand.Value, c, c.Name(), depth)
	if err != nil {
		return nil, err
	}
	outer := c
	outer.Wrapper = true
	return append([]Command{outer}, got...), nil
}

// flattenFind pulls out -exec style commands. The placeholder {} is a file name
// that isn't known yet.
func flattenFind(c Command, depth int) ([]Command, error) {
	out := []Command{c}
	args := c.Args
	for i := 1; i < len(args); i++ {
		switch args[i].Value {
		case "-exec", "-execdir", "-ok", "-okdir":
		default:
			continue
		}
		var inner []Word
		j := i + 1
		for ; j < len(args); j++ {
			v := args[j].Value
			if v == ";" || (v == "+" && len(inner) > 0 && inner[len(inner)-1].Raw == "{}") {
				break
			}
			if v == "{}" {
				inner = append(inner, Word{Raw: "{}", Value: Hole, Dynamic: true, Split: true})
				continue
			}
			inner = append(inner, args[j])
		}
		if j >= len(args) || len(inner) == 0 {
			return nil, fmt.Errorf("find: malformed %s", args[i].Value)
		}
		found := Command{Via: append(append([]string(nil), c.Via...), "find"), Args: inner}
		got, err := flattenCommand(found, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
		i = j
	}
	return out, nil
}
