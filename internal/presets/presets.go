// Package presets holds the policies that ship with seatbelt.
package presets

import (
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed *.yaml
var files embed.FS

// Self is the preset that protects seatbelt from the agent it restrains. It is
// always loaded.
const Self = "seatbelt"

// Names lists every preset.
func Names() []string {
	entries, err := files.ReadDir(".")
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(e.Name(), ".yaml"))
	}
	sort.Strings(names)
	return names
}

// Get returns a preset's YAML source.
func Get(name string) ([]byte, error) {
	data, err := files.ReadFile(name + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("unknown preset %q (have %s)", name, strings.Join(Names(), ", "))
	}
	return data, nil
}
