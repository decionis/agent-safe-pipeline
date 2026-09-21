package command

import (
	"bytes"
	"context"
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
	result := Shell{}.Run(context.Background(), Spec{Line: "false; echo reached", Stdout: &out, Stderr: &out})
	if result.ExitCode != 1 || out.Len() != 0 {
		t.Fatalf("%+v %q", result, out.String())
	}
	r := Shell{}.Run(context.Background(), Spec{Line: "exit 42"})
	if r.ExitCode != 42 {
		t.Fatalf("%+v", r)
	}
}
