// Package command runs the gated command: through a shell so the pipeline's
// own command line works unchanged, with the decision's identifiers in its
// environment and its output streamed as the runner shows it. What comes back
// is what the executor observed, an exit code and a duration, which the
// finalization records as the attempt's outcome.
package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
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

// Shells the gated command may run through, by the name the setting uses,
// each with the arguments it takes the line behind. bash and sh take it with
// `-e -c`, so the first failing command ends it. pwsh and powershell take it
// with `-Command`, wrapped the way GitHub Actions wraps its own PowerShell
// steps: `$ErrorActionPreference = 'Stop'` before it, and after it an exit
// with the last native command's code, which PowerShell otherwise drops. cmd
// takes it with `/d /s /c` as one raw command line, since cmd.exe reads a
// line, not an argument vector (see command_windows.go). Anything else is
// refused before anything runs.
var Shells = map[string][]string{
	"bash":       {"bash", "-e", "-c"},
	"sh":         {"sh", "-e", "-c"},
	"pwsh":       {"pwsh", "-NoProfile", "-NonInteractive", "-Command"},
	"powershell": {"powershell", "-NoProfile", "-NonInteractive", "-Command"},
	"cmd":        {"cmd", "/d", "/s", "/c"},
}

// DefaultShell is the shell a command runs through when none is named: bash,
// or Windows PowerShell on Windows, the one every Windows has.
var DefaultShell = defaultShell(runtime.GOOS)

func defaultShell(goos string) string {
	if goos == "windows" {
		return "powershell"
	}
	return "bash"
}

// Join turns the arguments after `--` into one line for the shell, quoting
// what needs it by that shell's rules, so `govern run -- ./deploy.sh --env
// "prod us"` runs as typed under bash and sh, `govern run --shell pwsh --
// ./deploy.ps1 -Environment "prod us"` under PowerShell, and a cmd line
// under cmd. A word of plain characters goes through as it is; anything
// else is quoted whole, so the shell expands nothing in it, which is what
// an argument vector means.
func Join(shell string, args []string) (string, error) {
	if shell == "" {
		shell = DefaultShell
	}
	switch shell {
	case "bash", "sh":
		return joinWith(args, posixQuote), nil
	case "pwsh", "powershell":
		line := joinWith(args, powershellQuote)
		// A quoted command is a string to PowerShell until the call operator says otherwise.
		if len(args) > 0 && powershellQuote(args[0]) != args[0] {
			line = "& " + line
		}
		return line, nil
	case "cmd":
		for _, arg := range args {
			// cmd.exe has no way to carry a double quote inside a quoted argument.
			if strings.Contains(arg, `"`) {
				return "", errors.New(`cmd cannot carry a double quote inside an argument; give the command as --run`)
			}
		}
		return joinWith(args, cmdQuote), nil
	}
	return "", fmt.Errorf("unknown shell %q", shell)
}

func joinWith(args []string, quote func(string) string) string {
	parts := make([]string, len(args))
	for i, arg := range args {
		parts[i] = quote(arg)
	}
	return strings.Join(parts, " ")
}

var posixPlain = regexp.MustCompile(`^[\w./:=@%+,-]+$`)

func posixQuote(arg string) string {
	if arg != "" && posixPlain.MatchString(arg) {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}

// PowerShell reads more into a bare word than a POSIX shell: a leading @
// splats, a comma makes an array, $ and ` expand; those are quoted.
var powershellPlain = regexp.MustCompile(`^[A-Za-z0-9_./\\-][\w./:=+@%\\-]*$`)

func powershellQuote(arg string) string {
	if arg != "" && powershellPlain.MatchString(arg) {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", "''") + "'"
}

// cmd's quoting is a pair of double quotes, inside which & | < > ^ are
// literal; %VAR% expands everywhere, as anyone writing a cmd line expects.
var cmdPlain = regexp.MustCompile(`^[\w./:=@%+\\-]+$`)

func cmdQuote(arg string) string {
	if arg != "" && cmdPlain.MatchString(arg) {
		return arg
	}
	return `"` + arg + `"`
}

// Invocation is the argument vector a shell runs a line with, or nil for a
// shell this package does not know.
func Invocation(shell, line string) []string {
	if shell == "" {
		shell = DefaultShell
	}
	prefix, ok := Shells[shell]
	if !ok {
		return nil
	}
	args := append([]string{}, prefix...)
	if shell == "pwsh" || shell == "powershell" {
		line = "$ErrorActionPreference = 'Stop'\n" + line +
			"\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }"
	}
	return append(args, line)
}

// Spec is one command to run.
type Spec struct {
	// Shell is one of Shells, DefaultShell when empty; Line is what it is handed.
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

// Run starts the shell with the line and waits; an unknown shell starts nothing.
func (Shell) Run(ctx context.Context, spec Spec) Result {
	argv := Invocation(spec.Shell, spec.Line)
	if argv == nil {
		return Result{Started: false, ExitCode: 127}
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	rawCommandLine(cmd, argv)
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
