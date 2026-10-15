package shell

import (
	"errors"
	"strings"
)

// wrapper describes a program whose job is to run another program. Any flag not
// listed here is an error: an unknown flag might take a value, and then the word
// after it isn't the command at all. A long flag whose value is optional, such as
// xargs --replace, belongs in boolean, because its value is only ever attached.
type wrapper struct {
	value   []string // flags that take a value
	boolean []string // flags that don't
	stop    []string // flags that mean no command runs, such as sudo -l
	// assigns: NAME=value words may come before the command.
	assigns bool
	// operands: positional words consumed before the command, like timeout's
	// duration or chroot's root directory.
	operands int
	// numeric: -N is a flag, as in nice -5.
	numeric bool
	// joined: the remaining words are joined and given to a shell, as in watch.
	joined bool
	// trailing: the program appends unknown arguments, as xargs does.
	trailing bool
	// split: this flag holds a whole command line, as with env -S.
	split []string
}

var wrappers = map[string]wrapper{
	"sudo": {
		value:   []string{"-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-C", "--close-from", "-r", "--role", "-t", "--type", "-T", "--command-timeout", "-U", "--other-user", "-D", "--chdir", "-R", "--chroot"},
		boolean: []string{"-A", "--askpass", "-b", "--background", "-E", "--preserve-env", "-H", "--set-home", "-k", "--reset-timestamp", "-K", "--remove-timestamp", "-n", "--non-interactive", "-P", "--preserve-groups", "-S", "--stdin", "-s", "--shell", "-i", "--login", "-B", "--bell"},
		stop:    []string{"-l", "--list", "-v", "--validate", "-V", "--version", "--help"},
		assigns: true,
	},
	"doas":       {value: []string{"-u", "-C"}, boolean: []string{"-n", "-s", "-L"}},
	"env":        {value: []string{"-u", "--unset", "-C", "--chdir", "-P"}, boolean: []string{"-i", "--ignore-environment", "-0", "--null", "-v", "--debug", "-"}, assigns: true, split: []string{"-S", "--split-string"}},
	"command":    {boolean: []string{"-p"}, stop: []string{"-v", "-V"}},
	"builtin":    {},
	"exec":       {value: []string{"-a"}, boolean: []string{"-c", "-l"}},
	"nohup":      {},
	"setsid":     {boolean: []string{"-c", "--ctty", "-f", "--fork", "-w", "--wait"}},
	"nice":       {value: []string{"-n", "--adjustment"}, numeric: true},
	"ionice":     {value: []string{"-c", "--class", "-n", "--classdata"}, boolean: []string{"-t", "--ignore"}},
	"time":       {value: []string{"-o", "--output", "-f", "--format"}, boolean: []string{"-p", "--portability", "-a", "--append", "-v", "--verbose", "-l", "-h"}, assigns: true},
	"timeout":    {value: []string{"-s", "--signal", "-k", "--kill-after"}, boolean: []string{"-v", "--verbose", "--foreground", "--preserve-status", "-f", "-p"}, operands: 1},
	"gtimeout":   {value: []string{"-s", "--signal", "-k", "--kill-after"}, boolean: []string{"-v", "--verbose", "--foreground", "--preserve-status"}, operands: 1},
	"stdbuf":     {value: []string{"-i", "--input", "-o", "--output", "-e", "--error"}},
	"unbuffer":   {boolean: []string{"-p"}},
	"caffeinate": {value: []string{"-t", "-w"}, boolean: []string{"-d", "-i", "-m", "-s", "-u"}},
	"chroot":     {value: []string{"--userspec", "--groups"}, boolean: []string{"--skip-chdir"}, operands: 1},
	"-":          {},
	"noglob":     {assigns: true},
	"nocorrect":  {assigns: true},
	"busybox":    {},
	"toybox":     {},
	"watch":      {value: []string{"-n", "--interval", "-d", "--differences"}, boolean: []string{"-t", "--no-title", "-b", "--beep", "-e", "--errexit", "-g", "--chgexit", "-p", "--precise", "-c", "--color"}, joined: true},
	"xargs":      {value: []string{"-I", "-E", "-L", "-n", "--max-args", "-P", "--max-procs", "-s", "--max-chars", "-d", "--delimiter", "-a", "--arg-file", "-J", "-R", "-S"}, boolean: []string{"-0", "--null", "-r", "--no-run-if-empty", "-t", "--verbose", "-p", "--interactive", "-o", "--open-tty", "-x", "--exit", "--replace", "--eof", "--max-lines"}, trailing: true},
}

func (w wrapper) unwrap(c Command, depth int) ([]Command, error) {
	name := c.Name()
	args := c.Args[1:]
	next := c
	i := 0
	operands := w.operands

scan:
	for i < len(args) {
		a := args[i]
		if a.Dynamic {
			return nil, errors.New("arguments are only known at run time")
		}
		v := a.Value
		switch {
		case v == "--":
			i += 1 + operands
			break scan
		case v == "-" && contains(w.boolean, "-"):
			i++
		case strings.HasPrefix(v, "--"):
			flag, _, hasValue := strings.Cut(v, "=")
			switch {
			case contains(w.stop, flag):
				return nil, nil
			case contains(w.split, flag):
				if !hasValue {
					i++
					if i >= len(args) {
						return nil, errors.New(flag + " is missing its value")
					}
					return reparse(args[i].Value, next, name, depth)
				}
				_, val, _ := strings.Cut(v, "=")
				return reparse(val, next, name, depth)
			case contains(w.value, flag):
				i++
				if !hasValue {
					i++
				}
			case contains(w.boolean, flag):
				i++
			default:
				return nil, errors.New("unknown flag " + flag)
			}
		case strings.HasPrefix(v, "-") && len(v) > 1:
			if w.numeric && allDigits(v[1:]) {
				i++
				continue
			}
			consumed, stop, script, err := w.shortFlags(v, args, i)
			if err != nil {
				return nil, err
			}
			if stop {
				return nil, nil
			}
			if script != nil {
				return reparse(*script, next, name, depth)
			}
			i += consumed
		case w.assigns && assignRe.MatchString(v):
			flag, val, _ := strings.Cut(v, "=")
			_, raw, _ := strings.Cut(a.Raw, "=")
			word := a
			word.Value, word.Raw = val, raw
			next.Assigns = append(append([]Assign(nil), next.Assigns...), Assign{Name: flag, Value: word})
			i++
		case operands > 0:
			operands--
			i++
		default:
			break scan
		}
	}
	rest := args[min(i, len(args)):]
	if len(rest) == 0 {
		return nil, nil
	}
	if w.joined {
		got, err := flattenJoined(next, rest, depth)
		if err != nil {
			return nil, err
		}
		return got[1:], nil
	}
	inner := append([]Word(nil), rest...)
	if w.trailing {
		inner = append(inner, Word{Raw: "...", Value: Hole, Dynamic: true, Split: true})
	}
	return []Command{child(next, name, inner)}, nil
}

// shortFlags walks one -abc cluster. A value flag takes the rest of the cluster
// or, failing that, the next word.
func (w wrapper) shortFlags(v string, args []Word, i int) (consumed int, stop bool, script *string, err error) {
	for j := 1; j < len(v); j++ {
		flag := "-" + string(v[j])
		switch {
		case contains(w.stop, flag):
			return 0, true, nil, nil
		case contains(w.split, flag):
			if j+1 < len(v) {
				s := v[j+1:]
				return 1, false, &s, nil
			}
			if i+1 >= len(args) {
				return 0, false, nil, errors.New(flag + " is missing its value")
			}
			if args[i+1].Dynamic {
				return 0, false, nil, errors.New(flag + " holds a command only known at run time")
			}
			s := args[i+1].Value
			return 2, false, &s, nil
		case contains(w.value, flag):
			if j+1 < len(v) {
				return 1, false, nil, nil
			}
			return 2, false, nil, nil
		case contains(w.boolean, flag):
		default:
			return 0, false, nil, errors.New("unknown flag " + flag)
		}
	}
	return 1, false, nil, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
