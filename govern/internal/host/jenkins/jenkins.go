// Package jenkins is the Jenkins host: facts from the build's variables,
// outputs as a properties file a later stage reads with readProperties, and
// plain log lines; Jenkins has no summary or change-request surface of its own.
package jenkins

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/decionis/agent-safe-pipeline/govern/internal/host"
)

// Host is one Jenkins build.
type Host struct {
	env   host.Environment
	out   io.Writer
	facts host.Facts
}

// New reads the build from its environment.
func New(env host.Environment, out io.Writer) *Host {
	if out == nil {
		out = os.Stdout
	}
	h := &Host{env: env, out: out}
	h.facts = host.Facts{
		System:        host.Jenkins,
		Repository:    repositoryOf(env("GIT_URL")),
		Ref:           env("GIT_BRANCH"),
		SHA:           env("GIT_COMMIT"),
		Actor:         firstOf(env("BUILD_USER_ID"), env("CHANGE_AUTHOR")),
		RunID:         env("BUILD_NUMBER"),
		RunURL:        env("BUILD_URL"),
		Workflow:      env("JOB_NAME"),
		Job:           env("STAGE_NAME"),
		ServerURL:     strings.TrimRight(env("JENKINS_URL"), "/"),
		ChangeRequest: env("CHANGE_ID"),
	}
	return h
}

// repositoryOf reads `owner/name` out of a clone URL when it has that shape.
func repositoryOf(cloneURL string) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(cloneURL), ".git")
	if trimmed == "" {
		return ""
	}
	if i := strings.Index(trimmed, "://"); i >= 0 {
		trimmed = trimmed[i+3:]
		if j := strings.Index(trimmed, "/"); j >= 0 {
			trimmed = trimmed[j+1:]
		}
	} else if i := strings.Index(trimmed, ":"); i >= 0 {
		trimmed = trimmed[i+1:]
	}
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], "/")
}

func firstOf(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// Name is the runner token.
func (h *Host) Name() string { return host.Jenkins }

// Facts is what the build says about itself.
func (h *Host) Facts() host.Facts { return h.facts }

// Outputs writes `govern.env`, or GOVERN_OUTPUT_FILE, as KEY=value lines.
func (h *Host) Outputs(values []host.Output) error {
	path := h.env("GOVERN_OUTPUT_FILE")
	if path == "" {
		path = "govern.env"
	}
	return host.Dotenv{Path: path}.Write(values)
}

// Summary appends to GOVERN_SUMMARY_FILE when set; the runner has no summary
// surface of its own, and the log already carries the verdict line.
func (h *Host) Summary(markdown string) error {
	return host.SummaryFile{Path: h.env("GOVERN_SUMMARY_FILE")}.Append(markdown)
}

// Comment has no surface on Jenkins.
func (h *Host) Comment(context.Context, string) (bool, error) { return false, nil }

// Notice writes a plain line.
func (h *Host) Notice(message string) { host.Plain{Out: h.out}.Notice(message) }

// Warning writes a warning line.
func (h *Host) Warning(message string) { host.Plain{Out: h.out}.Warning(message) }

// Error writes an error line.
func (h *Host) Error(message string) { host.Plain{Out: h.out}.Error(message) }

// Group writes a titled block.
func (h *Host) Group(title, body string) { host.Plain{Out: h.out}.Group(title, body) }
