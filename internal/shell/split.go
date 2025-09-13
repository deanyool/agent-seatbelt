// Package shell splits command lines.
package shell

import "strings"

// Split breaks a line on the shell operators and returns the words of each part.
// Quotes aren't handled yet.
func Split(line string) [][]string {
	for _, op := range []string{"&&", "||", "|", ";"} {
		line = strings.ReplaceAll(line, op, "\n")
	}
	var out [][]string
	for _, part := range strings.Split(line, "\n") {
		if words := strings.Fields(part); len(words) > 0 {
			out = append(out, words)
		}
	}
	return out
}
