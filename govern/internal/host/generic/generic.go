// Package generic is any other runner: the facts come from GOVERN_* variables
// the pipeline sets (GOVERN_REPOSITORY, GOVERN_REF, GOVERN_SHA,
// GOVERN_RUN_URL, GOVERN_RUN_ID, GOVERN_ACTOR, GOVERN_ENVIRONMENT), outputs
// go to a dotenv file, and lines are plain.
package generic

import (
	"context"
	"io"
	"os"

	"github.com/decionis/agent-safe-pipeline/govern/internal/host"
)

// Host is one run on an unknown runner.
type Host struct {
	env   host.Environment
	out   io.Writer
	facts host.Facts
}

// New reads the run from GOVERN_* variables.
func New(env host.Environment, out io.Writer) *Host {
	if out == nil {
		out = os.Stdout
	}
	return &Host{env: env, out: out, facts: host.Facts{
		System:      host.Generic,
		Repository:  env("GOVERN_REPOSITORY"),
		Ref:         env("GOVERN_REF"),
		SHA:         env("GOVERN_SHA"),
		Actor:       env("GOVERN_ACTOR"),
		RunID:       env("GOVERN_RUN_ID"),
		RunURL:      env("GOVERN_RUN_URL"),
		Workflow:    env("GOVERN_WORKFLOW"),
		Environment: env("GOVERN_ENVIRONMENT"),
	}}
}

// Name is the runner token.
func (h *Host) Name() string { return host.Generic }

// Facts is what the pipeline said about the run.
func (h *Host) Facts() host.Facts { return h.facts }

// Outputs writes the dotenv file GOVERN_OUTPUT_FILE names, when it names one.
func (h *Host) Outputs(values []host.Output) error {
	// Only where the pipeline asked: a stray file is not a surface.
	return host.Dotenv{Path: h.env("GOVERN_OUTPUT_FILE")}.Write(values)
}

// Summary appends to GOVERN_SUMMARY_FILE when set; the runner has no summary
// surface of its own, and the log already carries the verdict line.
func (h *Host) Summary(markdown string) error {
	return host.SummaryFile{Path: h.env("GOVERN_SUMMARY_FILE")}.Append(markdown)
}

// Comment has no surface here.
func (h *Host) Comment(context.Context, string) (bool, error) { return false, nil }

// Notice writes a plain line.
func (h *Host) Notice(message string) { host.Plain{Out: h.out}.Notice(message) }

// Warning writes a warning line.
func (h *Host) Warning(message string) { host.Plain{Out: h.out}.Warning(message) }

// Error writes an error line.
func (h *Host) Error(message string) { host.Plain{Out: h.out}.Error(message) }

// Group writes a titled block.
func (h *Host) Group(title, body string) { host.Plain{Out: h.out}.Group(title, body) }
