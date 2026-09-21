// Command govern gates one workflow step on a Decionis decision.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/decionis/agent-safe-pipeline/govern/v2"
	"github.com/decionis/agent-safe-pipeline/govern/v2/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(cli.Main(ctx, cli.Process{Args: os.Args[1:], Env: os.Getenv, Stdout: os.Stdout, Stderr: os.Stderr, Version: govern.Version}))
}
