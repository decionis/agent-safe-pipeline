package command

import (
	"bytes"
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestShellRunsTheLineWithTheEnvironment(t *testing.T) {
	var out bytes.Buffer
	result := Shell{}.Run(context.Background(), Spec{Shell: "sh", Line: "printf '%s' \"$DECIONIS_DECISION_ID\"", Env: map[string]string{"DECIONIS_DECISION_ID": "d-1"}, Stdout: &out, Stderr: &out})
	if !result.Started || result.ExitCode != 0 || out.String() != "d-1" {
		t.Fatalf("%+v %q", result, out.String())
	}
}

func TestShellReportsTheExitCodeAndStopsOnTheFirstFailure(t *testing.T) {
	var out bytes.Buffer
	result := Shell{}.Run(context.Background(), Spec{Shell: "bash", Line: "false; echo reached", Stdout: &out, Stderr: &out})
	if result.ExitCode != 1 || out.Len() != 0 {
		t.Fatalf("%+v %q", result, out.String())
	}
	r := Shell{}.Run(context.Background(), Spec{Shell: "bash", Line: "exit 42"})
	if r.ExitCode != 42 {
		t.Fatalf("%+v", r)
	}
}

func TestJoinQuotesForTheShellInUse(t *testing.T) {
	args := []string{"./deploy.sh", "--env", "prod us", "it's", "a=b"}
	cases := map[string]string{
		"bash":       `./deploy.sh --env 'prod us' 'it'\''s' a=b`,
		"sh":         `./deploy.sh --env 'prod us' 'it'\''s' a=b`,
		"pwsh":       `./deploy.sh --env 'prod us' 'it''s' a=b`,
		"powershell": `./deploy.sh --env 'prod us' 'it''s' a=b`,
		"cmd":        `./deploy.sh --env "prod us" "it's" a=b`,
	}
	for shell, want := range cases {
		got, err := Join(shell, args)
		if err != nil || got != want {
			t.Fatalf("%s: %q %v", shell, got, err)
		}
	}
	if got, _ := Join("", args); got != cases[DefaultShell] {
		t.Fatalf("the empty shell joins for the default: %q", got)
	}
	// PowerShell: a quoted command needs the call operator; what PowerShell
	// would read into a bare word is quoted; an empty argument survives.
	if got, _ := Join("pwsh", []string{"C:\\Program Files\\x\\deploy.ps1", "-Env", "prod"}); got != `& 'C:\Program Files\x\deploy.ps1' -Env prod` {
		t.Fatalf("%q", got)
	}
	want := ".\\deploy.ps1 '@splat' 'a,b' '$env:X' '`t' '' user@host 100%"
	if got, _ := Join("pwsh", []string{".\\deploy.ps1", "@splat", "a,b", "$env:X", "`t", "", "user@host", "100%"}); got != want {
		t.Fatalf("%q", got)
	}
	// cmd: a double quote has no escape, so the line is refused rather than guessed.
	if _, err := Join("cmd", []string{"echo", `say "hi"`}); err == nil || !strings.Contains(err.Error(), "double quote") {
		t.Fatalf("%v", err)
	}
	if got, _ := Join("cmd", []string{"deploy.bat", "a&b", "%TEMP%", ""}); got != `deploy.bat "a&b" %TEMP% ""` {
		t.Fatalf("%q", got)
	}
	if _, err := Join("fish", []string{"x"}); err == nil {
		t.Fatal("an unknown shell has no joining rules")
	}
}

func TestInvocationNamesEachShellsArguments(t *testing.T) {
	wrapped := "$ErrorActionPreference = 'Stop'\nx\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }"
	cases := map[string][]string{
		"bash":       {"bash", "-e", "-c", "x"},
		"sh":         {"sh", "-e", "-c", "x"},
		"pwsh":       {"pwsh", "-NoProfile", "-NonInteractive", "-Command", wrapped},
		"powershell": {"powershell", "-NoProfile", "-NonInteractive", "-Command", wrapped},
		"cmd":        {"cmd", "/d", "/s", "/c", "x"},
	}
	for shell, want := range cases {
		got := Invocation(shell, "x")
		if len(got) != len(want) {
			t.Fatalf("%q: %v", shell, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%q: %v, want %v", shell, got, want)
			}
		}
	}
	if got := Invocation("", "x"); got[0] != DefaultShell {
		t.Fatalf("an empty shell must be the default, got %v", got)
	}
	if defaultShell("windows") != "powershell" || defaultShell("linux") != "bash" || defaultShell("darwin") != "bash" {
		t.Fatal("the default shell is bash, or Windows PowerShell on Windows")
	}
	if Invocation("fish", "x") != nil {
		t.Fatal("an unknown shell must run nothing")
	}
	if r := (Shell{}).Run(context.Background(), Spec{Shell: "fish", Line: "echo hi"}); r.Started || r.ExitCode != 127 {
		t.Fatalf("%+v", r)
	}
}

// PowerShell is on every GitHub-hosted runner; where it is not, this skips.
func TestPwshRunsTheLineAndKeepsTheExitCode(t *testing.T) {
	if _, err := exec.LookPath("pwsh"); err != nil {
		t.Skip("pwsh is not installed here")
	}
	var out bytes.Buffer
	r := (Shell{}).Run(context.Background(), Spec{Shell: "pwsh", Line: "Write-Output \"id=$env:DECIONIS_DECISION_ID\"; exit 3", Env: map[string]string{"DECIONIS_DECISION_ID": "d-1"}, Stdout: &out, Stderr: &out})
	if !r.Started || r.ExitCode != 3 || !strings.Contains(out.String(), "id=d-1") {
		t.Fatalf("%+v %q", r, out.String())
	}
	// A native command's failure is the step's: the code is kept, not dropped.
	out.Reset()
	r = (Shell{}).Run(context.Background(), Spec{Shell: "pwsh", Line: "pwsh -NoProfile -Command 'exit 7'", Stdout: &out, Stderr: &out})
	if !r.Started || r.ExitCode != 7 {
		t.Fatalf("%+v %q", r, out.String())
	}
	// An error stops the line before what follows it.
	out.Reset()
	r = (Shell{}).Run(context.Background(), Spec{Shell: "pwsh", Line: "Get-Item -LiteralPath '/no/such/file/anywhere'\nWrite-Output reached", Stdout: &out, Stderr: &out})
	if !r.Started || r.ExitCode == 0 || strings.Contains(out.String(), "reached") {
		t.Fatalf("%+v %q", r, out.String())
	}
}

// cmd.exe exists on Windows alone; the raw command line it is handed keeps
// the line's own quotes.
func TestCmdRunsTheLineAsTyped(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd.exe is Windows'")
	}
	var out bytes.Buffer
	r := (Shell{}).Run(context.Background(), Spec{Shell: "cmd", Line: `echo "a b" %DECIONIS_DECISION_ID% && exit 3`, Env: map[string]string{"DECIONIS_DECISION_ID": "d-1"}, Stdout: &out, Stderr: &out})
	if !r.Started || r.ExitCode != 3 || !strings.Contains(out.String(), `"a b" d-1`) {
		t.Fatalf("%+v %q", r, out.String())
	}
}
