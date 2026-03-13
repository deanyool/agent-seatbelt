package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/deanyool/agent-seatbelt/internal/mcp"
)

func (a *App) mcpProxy(args []string) int {
	flags := a.flags("mcp-proxy")
	policyPath := flags.String("policy", "", "policy file")
	server := flags.String("server", "", "server label, used as mcp__<server>__<tool> when matching rules")
	showDenied := flags.Bool("show-denied", false, "leave denied tools in tools/list")
	if code, ok := parseFlags(flags, args); !ok {
		return code
	}
	argv := flags.Args()
	if len(argv) == 0 {
		return a.usageError("mcp-proxy needs the server command after --")
	}
	p, err := a.loadPolicy(*policyPath)
	if err != nil {
		return a.fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stderr = a.Stderr
	cmd.Env = a.Environ()
	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return a.fail(err)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return a.fail(err)
	}
	if err := cmd.Start(); err != nil {
		return a.fail(err)
	}
	cwd := a.cwd()
	proxy := &mcp.Proxy{
		Policy:     p,
		Server:     *server,
		HideDenied: !*showDenied,
		Observe: func(v mcp.Verdict) {
			a.recordReport(p, "mcp", cwd, "", v.Report)
		},
		Queue: func(v mcp.Verdict) (string, error) {
			return a.queue(fmt.Sprintf("# MCP tool call: %s", v.Tool), cwd, "mcp", v.Report)
		},
	}
	proxyErr := proxy.Run(a.Stdin, a.Stdout, serverIn, serverOut)
	waitErr := cmd.Wait()
	if proxyErr != nil {
		return a.fail(proxyErr)
	}
	var exit *exec.ExitError
	if errors.As(waitErr, &exit) && ctx.Err() == nil {
		return exit.ExitCode()
	}
	return exitOK
}
