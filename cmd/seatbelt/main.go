// Command seatbelt checks commands against a policy.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/deanyool/agent-seatbelt/internal/hook"
	"github.com/deanyool/agent-seatbelt/internal/policy"
)

func main() {
	p, err := policy.Default()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(os.Args) > 1 && os.Args[1] == "hook" {
		os.Exit(hook.Run(os.Stdin, os.Stdout, os.Stderr, p))
	}
	line := strings.Join(os.Args[1:], " ")
	if r := p.Check(line); !r.Allowed {
		fmt.Println("blocked:", r.Reason)
		os.Exit(1)
	}
	fmt.Println("ok")
}
