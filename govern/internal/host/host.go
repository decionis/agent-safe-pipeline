// Package host is the seam between the gate and the workflow runner it runs
// in. A host says what the runner knows about the run (the facts the intent's
// context carries), where outputs go so a later step can read them, where a
// summary and a change-request comment go when the runner has such surfaces,
// and how a line is logged. GitHub Actions, GitLab CI and Jenkins are known;
// any other runner is the generic host, which reads GOVERN_* variables.
package host

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Environment reads one variable; the empty string means unset.
type Environment func(key string) string

// Facts is what the runner's own environment says about this run: only what
// is present is set, and nothing is guessed.
type Facts struct {
	// System is the runner as the intent's downstream_target.system names it.
	System string
	// Repository is `owner/name` or the project path.
	Repository    string
	Ref           string
	SHA           string
	Event         string
	Actor         string
	RunID         string
	RunAttempt    string
	RunURL        string
	Workflow      string
	Job           string
	ServerURL     string
	Environment   string
	WorkflowRef   string
	ChangeRequest string
}

// Context is the facts as the intent's context carries them: snake_case keys,
// absent when unknown, under the runner's own name.
func (f Facts) Context() map[string]any {
	out := map[string]any{"runner": f.System}
	put := func(key, value string) {
		if value != "" {
			out[key] = value
		}
	}
	put("repository", f.Repository)
	put("ref", f.Ref)
	put("sha", f.SHA)
	put("event", f.Event)
	put("triggered_by", f.Actor)
	put("run_id", f.RunID)
	put("run_attempt", f.RunAttempt)
	put("run_url", f.RunURL)
	put("workflow", f.Workflow)
	put("job", f.Job)
	put("server_url", f.ServerURL)
	put("workflow_ref", f.WorkflowRef)
	put("change_request", f.ChangeRequest)
	return out
}

// Output is one named value a later step reads.
type Output struct {
	Name  string
	Value string
}

// Host is one workflow runner.
type Host interface {
	// Name is the runner's token: github_actions, gitlab_ci, jenkins or ci.
	Name() string
	Facts() Facts
	// Outputs publishes the values where the runner's later steps read them.
	Outputs(values []Output) error
	// Summary appends Markdown to the run's summary surface, when there is one.
	Summary(markdown string) error
	// Comment posts the body on the change request the run is for, updating an
	// earlier comment of this gate in place. False when the runner has no such
	// surface, the run is not for a change request, or no token was given.
	Comment(ctx context.Context, body string) (bool, error)
	Logger
}

// Logger writes the runner's own log annotations.
type Logger interface {
	Notice(message string)
	Warning(message string)
	Error(message string)
	// Group writes a titled, collapsible block where the runner supports one.
	Group(title, body string)
}

// Marker is the hidden text that finds this gate's own comment on re-runs.
const Marker = "<!-- decionis-govern -->"

var outputName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// ValidOutputName is the shape every output name has, whichever runner.
func ValidOutputName(name string) bool { return outputName.MatchString(name) }

// Plain logs lines with a prefix and no runner syntax.
type Plain struct{ Out io.Writer }

func (p Plain) writer() io.Writer {
	if p.Out == nil {
		return os.Stdout
	}
	return p.Out
}

// Notice writes an informational line.
func (p Plain) Notice(message string) { fmt.Fprintf(p.writer(), "govern: %s\n", oneLine(message)) }

// Warning writes a warning line.
func (p Plain) Warning(message string) {
	fmt.Fprintf(p.writer(), "govern: warning: %s\n", oneLine(message))
}

// Error writes an error line.
func (p Plain) Error(message string) {
	fmt.Fprintf(p.writer(), "govern: error: %s\n", oneLine(message))
}

// Group writes a titled block.
func (p Plain) Group(title, body string) {
	fmt.Fprintf(p.writer(), "govern: %s\n%s\n", oneLine(title), indent(body))
}

func oneLine(value string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(value))
}

func indent(body string) string {
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	for i, line := range lines {
		lines[i] = "  " + line
	}
	return strings.Join(lines, "\n")
}

// Dotenv is the output surface runners without one share: `GOVERN_<NAME>=value`
// lines in a file a later job reads (`artifacts: reports: dotenv` on GitLab,
// `readProperties` on Jenkins). One line per value; a value's own newlines
// become spaces, because the format has no room for them.
type Dotenv struct{ Path string }

// Write appends the values.
func (d Dotenv) Write(values []Output) error {
	if d.Path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(d.Path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(d.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, value := range values {
		if !ValidOutputName(value.Name) {
			return fmt.Errorf("OUTPUT_NAME_INVALID: %q", value.Name)
		}
		key := "GOVERN_" + strings.ToUpper(strings.ReplaceAll(value.Name, "-", "_"))
		if _, err := fmt.Fprintf(file, "%s=%s\n", key, oneLine(value.Value)); err != nil {
			return err
		}
	}
	return nil
}

// SummaryFile appends Markdown to a file when the path is set: the runner's
// own summary file, or one the pipeline asked for.
type SummaryFile struct{ Path string }

// Append writes the markdown; no path, nothing written.
func (f SummaryFile) Append(markdown string) error {
	if f.Path == "" {
		return nil
	}
	file, err := os.OpenFile(f.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = fmt.Fprintln(file, markdown)
	return err
}

// Selection names the runner explicitly, or "" to detect one.
type Selection string

// Known runner names.
const (
	GitHub  = "github_actions"
	GitLab  = "gitlab_ci"
	Jenkins = "jenkins"
	Generic = "ci"
)

// Detect reads the runner from its own variables: GITHUB_ACTIONS, GITLAB_CI,
// JENKINS_URL with BUILD_NUMBER; anything else is the generic host.
func Detect(env Environment) string {
	switch {
	case env("GITHUB_ACTIONS") == "true":
		return GitHub
	case env("GITLAB_CI") == "true":
		return GitLab
	case env("JENKINS_URL") != "" && env("BUILD_NUMBER") != "":
		return Jenkins
	}
	return Generic
}
