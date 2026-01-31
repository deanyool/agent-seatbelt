package policy

import (
	"slices"
	"strings"

	"github.com/deanyool/agent-seatbelt/internal/shell"
)

// flagUse is one flag found on a command line.
type flagUse struct {
	Name  string // the normalized name, like --force or -f
	Raw   string // the word as given, like -rf
	Value shell.Word
	Has   bool // a value is attached or was consumed from the next word
	Index int  // position of the flag's word
	Known bool // declared as a global flag
}

// positional is one non-flag word.
type positional struct {
	Word  shell.Word
	Index int
}

// parsedArgs is a command line split according to its CommandSpec.
type parsedArgs struct {
	Flags []flagUse
	Pos   []positional
	// Risky holds words whose expansion could turn into a flag or an extra argument.
	Risky []shell.Word
}

// parseArgs splits the words after the program name.
func parseArgs(words []shell.Word, spec *CommandSpec) *parsedArgs {
	if spec == nil {
		spec = &CommandSpec{}
	}
	a := &parsedArgs{}
	// Global flags only mean what they say ahead of the subcommand. After it, -c on
	// git grep is a different flag from the -c on git itself.
	takesValue := func(name string) bool {
		return slices.Contains(spec.ValueFlags, name) ||
			(len(a.Pos) == 0 && slices.Contains(spec.Global.Value, name))
	}
	known := func(name string) bool {
		return slices.Contains(spec.ValueFlags, name) ||
			slices.Contains(spec.Global.Value, name) || slices.Contains(spec.Global.Bool, name)
	}
	addFlag := func(f flagUse) {
		f.Known = known(f.Name)
		a.Flags = append(a.Flags, f)
	}
	// value fills in a flag's value from the next word when it takes one.
	nextValue := func(f *flagUse, i int) int {
		if takesValue(f.Name) && !f.Has && i+1 < len(words) {
			f.Value, f.Has = words[i+1], true
			return i + 1
		}
		return i
	}

	for i := 0; i < len(words); i++ {
		w := words[i]
		v := w.Value
		if v == "--" && !w.Quoted {
			for j := i + 1; j < len(words); j++ {
				a.addPositional(words[j], j, true)
			}
			break
		}
		if !strings.HasPrefix(w.Prefix(), "-") || w.Prefix() == "-" && !w.Dynamic {
			a.addPositional(w, i, false)
			continue
		}
		if w.Dynamic {
			// Without a literal --name= in front, the expansion may be anything.
			name, rest, found := strings.Cut(v, "=")
			if !found || strings.Contains(name, shell.Hole) {
				a.addPositional(w, i, false)
				continue
			}
			value := w
			value.Value = rest
			addFlag(flagUse{Name: normalizeFlag(name, spec), Raw: v, Value: value, Has: true, Index: i})
			continue
		}
		if strings.HasPrefix(v, "--") || spec.SingleDash {
			name, rest, found := strings.Cut(v, "=")
			f := flagUse{Name: normalizeFlag(name, spec), Raw: v, Index: i}
			if found {
				f.Value, f.Has = shell.Literal(rest), true
			}
			i = nextValue(&f, i)
			addFlag(f)
			continue
		}
		// A short cluster. A value flag takes the rest of the word or the next word.
		for j := 1; j < len(v); j++ {
			f := flagUse{Name: "-" + v[j:j+1], Raw: v, Index: i}
			if takesValue(f.Name) {
				if j+1 < len(v) {
					f.Value, f.Has = shell.Literal(strings.TrimPrefix(v[j+1:], "=")), true
				} else {
					i = nextValue(&f, i)
				}
				addFlag(f)
				break
			}
			addFlag(f)
		}
	}
	if spec.ColonSubcommands && len(a.Pos) > 0 && strings.Contains(a.Pos[0].Word.Value, ":") {
		first := a.Pos[0]
		var split []positional
		for _, part := range strings.Split(first.Word.Value, ":") {
			w := first.Word
			w.Value = part
			split = append(split, positional{Word: w, Index: first.Index})
		}
		a.Pos = append(split, a.Pos[1:]...)
	}
	return a
}

// normalizeFlag gives single-dash tools one spelling, since Go-style flag parsers
// treat -name and --name alike.
func normalizeFlag(name string, spec *CommandSpec) string {
	if spec.SingleDash {
		return "-" + strings.TrimLeft(name, "-")
	}
	return name
}

func (a *parsedArgs) addPositional(w shell.Word, i int, afterDashes bool) {
	a.Pos = append(a.Pos, positional{Word: w, Index: i})
	// After -- nothing can be a flag, but an unquoted expansion can still add words.
	if w.Split || (w.Dynamic && !afterDashes && !hasSafePrefix(w)) {
		a.Risky = append(a.Risky, w)
	}
}

// hasSafePrefix reports a word whose literal start keeps it from being a flag.
func hasSafePrefix(w shell.Word) bool {
	p := w.Prefix()
	return p != "" && !strings.HasPrefix(p, "-")
}

// has reports whether a flag is present. With loose set it also accepts an
// abbreviation, because git and getopt_long accept any unique prefix: --forc means
// --force. Loose matching can only make a strict rule fire more often.
func (a *parsedArgs) has(name string, loose bool) bool {
	for _, f := range a.Flags {
		if f.Name == name || f.Raw == name {
			return true
		}
		if loose && len(f.Name) >= 3 && strings.HasPrefix(f.Name, "--") && strings.HasPrefix(name, f.Name) {
			return true
		}
	}
	return false
}

// valuesOf returns the values given to any of the named flags.
func (a *parsedArgs) valuesOf(names []string, loose bool) []shell.Word {
	var out []shell.Word
	for _, f := range a.Flags {
		if !f.Has {
			continue
		}
		for _, n := range names {
			if f.Name == n || (loose && len(f.Name) >= 3 && strings.HasPrefix(f.Name, "--") && strings.HasPrefix(n, f.Name)) {
				out = append(out, f.Value)
				break
			}
		}
	}
	return out
}
