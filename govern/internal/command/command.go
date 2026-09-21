// Package command runs the gated command: through a shell so the pipeline's
// own command line works unchanged, with the decision's identifiers in its
// environment and its output streamed as the runner shows it. What comes back
// is what the executor observed, an exit code and a duration, which the
// finalization records as the attempt's outcome.
package command

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"
)

// Result is what was observed of the attempt.
type Result struct {
	// Started is false when the shell could not be started at all.
	Started  bool
	ExitCode int
	Duration time.Duration
	// Signal names the signal that ended the command, when one did.
	Signal string
}

// Runner starts commands; the gate takes one so tests can supply a fake.
type Runner interface {
	Run(ctx context.Context, spec Spec) Result
}

// Spec is one command to run.
type Spec struct {
	// Shell is `bash` (default) or `sh`; the command line is its `-c` argument.
	Shell string
	Line  string
	// Env is added to the process environment; the executor's identifiers ride here.
	Env    map[string]string
	Dir    string
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
}

// Shell runs a Spec through the operating system's shell.
type Shell struct{}

// Run starts the shell with `-e -c <line>` and waits.
func (Shell) Run(ctx context.Context, spec Spec) Result {
	shell := "bash"
	if spec.Shell == "sh" {
		shell = "sh"
	}
	cmd := exec.CommandContext(ctx, shell, "-e", "-c", spec.Line)
	cmd.Dir = spec.Dir
	cmd.Stdout, cmd.Stderr, cmd.Stdin = spec.Stdout, spec.Stderr, spec.Stdin
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	cmd.Env = os.Environ()
	for key, value := range spec.Env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	started := time.Now()
	if err := cmd.Start(); err != nil {
		return Result{Started: false, ExitCode: 127}
	}
	err := cmd.Wait()
	result := Result{Started: true, Duration: time.Since(started)}
	var exit *exec.ExitError
	switch {
	case err == nil:
		result.ExitCode = 0
	case errors.As(err, &exit):
		result.ExitCode = exit.ExitCode()
		if result.ExitCode < 0 {
			result.ExitCode = 128
			if status := exit.Sys(); status != nil {
				if s, ok := status.(interface{ Signal() os.Signal }); ok && s.Signal() != nil {
					result.Signal = s.Signal().String()
				}
			}
		}
	default:
		result.ExitCode = 1
	}
	return result
}
