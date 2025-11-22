package cli

import (
	"fmt"
	"strings"

	"github.com/deanyool/agent-seatbelt/internal/presets"
)
func (a *App) preset(args []string) int {
	if len(args) == 0 {
		return a.usageError("preset needs a subcommand: list or show")
	}
	switch args[0] {
	case "list":
		for _, name := range presets.Names() {
			data, err := presets.Get(name)
			if err != nil {
				return a.fail(err)
			}
			fmt.Fprintf(a.Stdout, "%-10s %s\n", name, presetDescription(string(data)))
		}
		return exitOK
	case "show":
		if len(args) != 2 {
			return a.usageError("preset show needs a preset name")
		}
		data, err := presets.Get(args[1])
		if err != nil {
			return a.fail(err)
		}
		if _, err := a.Stdout.Write(data); err != nil {
			return a.fail(err)
		}
		return exitOK
	}
	return a.usageError("unknown preset subcommand %q", args[0])
}

func presetDescription(src string) string {
	for _, line := range strings.Split(src, "\n") {
		if rest, ok := strings.CutPrefix(line, "description: "); ok {
			return rest
		}
	}
	return ""
}
