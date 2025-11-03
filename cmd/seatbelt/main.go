// Command seatbelt is a policy layer between AI agents and dangerous CLIs.
package main

import (
	"os"

	"github.com/deanyool/agent-seatbelt/internal/cli"
)

func main() {
	os.Exit(cli.New().Main(os.Args))
}
