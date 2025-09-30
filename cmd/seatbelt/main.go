// Command seatbelt checks commands against a policy.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/deanyool/agent-seatbelt/internal/hook"
	"github.com/deanyool/agent-seatbelt/internal/policy"
)

const usage = `useage:
  seatbelt check 'COMMAND'
  seatbelt hook
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	p, err := policy.Default()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "hook":
		os.Exit(hook.Run(os.Stdin, os.Stdout, os.Stderr, p))
	case "check":
		line := strings.Join(os.Args[2:], " ")
		if r := p.Check(line); !r.Allowed {
			fmt.Println("DENY", line)
			fmt.Println("    ", r.Reason)
			os.Exit(4)
		}
		fmt.Println("ALLOW", line)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}
