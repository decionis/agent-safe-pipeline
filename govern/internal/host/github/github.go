// Package github is the GitHub Actions host: facts from GITHUB_*, outputs
// through GITHUB_OUTPUT, the step summary through GITHUB_STEP_SUMMARY,
// workflow commands for the log, and a pull-request comment through the REST
// API when a token is given.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/decionis/agent-safe-pipeline/govern/internal/host"
)

// Host is one GitHub Actions run.
type Host struct {
	env   host.Environment
	out   io.Writer
	http  *http.Client
	facts host.Facts
	// readEvent reads the event payload, for the pull request number.
	readEvent func(path string) ([]byte, error)
}

// New reads the run from its environment.
func New(env host.Environment, out io.Writer, client *http.Client) *Host {
	if out == nil {
		out = os.Stdout
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	h := &Host{env: env, out: out, http: client, readEvent: os.ReadFile}
	h.facts = h.readFacts()
	return h
}

func (h *Host) readFacts() host.Facts {
	server := h.env("GITHUB_SERVER_URL")
	if server == "" {
		server = "https://github.com"
	}
	facts := host.Facts{
		System:      host.GitHub,
		Repository:  h.env("GITHUB_REPOSITORY"),
		Ref:         h.env("GITHUB_REF"),
		SHA:         h.env("GITHUB_SHA"),
		Event:       h.env("GITHUB_EVENT_NAME"),
		Actor:       h.env("GITHUB_ACTOR"),
		RunID:       h.env("GITHUB_RUN_ID"),
		RunAttempt:  h.env("GITHUB_RUN_ATTEMPT"),
		Workflow:    h.env("GITHUB_WORKFLOW"),
		Job:         h.env("GITHUB_JOB"),
		ServerURL:   server,
		WorkflowRef: h.env("GITHUB_WORKFLOW_REF"),
	}
	if facts.Repository != "" && facts.RunID != "" {
		facts.RunURL = server + "/" + facts.Repository + "/actions/runs/" + facts.RunID
	}
	if ref := facts.Ref; strings.HasPrefix(ref, "refs/pull/") {
		if number := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(ref, "refs/pull/"), "/merge"), "/head"); isNumber(number) {
			facts.ChangeRequest = number
		}
	}
	if facts.ChangeRequest == "" {
		if path := h.env("GITHUB_EVENT_PATH"); path != "" {
			if raw, err := h.readEvent(path); err == nil {
				var event struct {
					Number      *json.Number `json:"number"`
					PullRequest *struct {
						Number json.Number `json:"number"`
					} `json:"pull_request"`
				}
				if json.Unmarshal(raw, &event) == nil {
					if event.PullRequest != nil && isNumber(event.PullRequest.Number.String()) {
						facts.ChangeRequest = event.PullRequest.Number.String()
					} else if event.Number != nil && isNumber(event.Number.String()) {
						facts.ChangeRequest = event.Number.String()
					}
				}
			}
		}
	}
	return facts
}

func isNumber(value string) bool {
	if value == "" || len(value) > 12 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Name is the runner token.
func (h *Host) Name() string { return host.GitHub }

// Facts is what the run says about itself.
func (h *Host) Facts() host.Facts { return h.facts }

// Outputs appends to GITHUB_OUTPUT in the delimited form, so a value may span
// lines; without the file (a run outside Actions) it writes nothing.
func (h *Host) Outputs(values []host.Output) error {
	path := h.env("GITHUB_OUTPUT")
	if path == "" {
		return nil
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, value := range values {
		if !host.ValidOutputName(value.Name) {
			return fmt.Errorf("OUTPUT_NAME_INVALID: %q", value.Name)
		}
		delimiter := "govern_" + strings.ReplaceAll(value.Name, "-", "_") + "_" + fmt.Sprint(time.Now().UnixNano())
		for strings.Contains(value.Value, delimiter) {
			delimiter += "_"
		}
		if _, err := fmt.Fprintf(file, "%s<<%s\n%s\n%s\n", value.Name, delimiter, value.Value, delimiter); err != nil {
			return err
		}
	}
	return nil
}

// Summary appends to the step summary.
func (h *Host) Summary(markdown string) error {
	return host.SummaryFile{Path: h.env("GITHUB_STEP_SUMMARY")}.Append(markdown)
}

// Comment upserts the gate's comment on the pull request the run is for.
// It needs a token in GOVERN_GITHUB_TOKEN or GITHUB_TOKEN with
// pull-requests: write; without one, or outside a pull request, it does nothing.
func (h *Host) Comment(ctx context.Context, body string) (bool, error) {
	token := h.env("GOVERN_GITHUB_TOKEN")
	if token == "" {
		token = h.env("GITHUB_TOKEN")
	}
	if token == "" || h.facts.Repository == "" || h.facts.ChangeRequest == "" {
		return false, nil
	}
	api := strings.TrimRight(h.env("GITHUB_API_URL"), "/")
	if api == "" {
		api = "https://api.github.com"
	}
	base := api + "/repos/" + h.facts.Repository
	existing, err := h.findComment(ctx, token, base)
	if err != nil {
		return false, err
	}
	method, target := http.MethodPost, base+"/issues/"+h.facts.ChangeRequest+"/comments"
	if existing != "" {
		method, target = http.MethodPatch, base+"/issues/comments/"+existing
	}
	payload, _ := json.Marshal(map[string]string{"body": body})
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	h.headers(request, token)
	request.Header.Set("content-type", "application/json")
	response, err := h.http.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false, fmt.Errorf("GITHUB_COMMENT_REFUSED: HTTP %d", response.StatusCode)
	}
	return true, nil
}

func (h *Host) findComment(ctx context.Context, token, base string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/issues/"+h.facts.ChangeRequest+"/comments?per_page=100", nil)
	if err != nil {
		return "", err
	}
	h.headers(request, token)
	response, err := h.http.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", nil
	}
	var comments []struct {
		ID   json.Number `json:"id"`
		Body string      `json:"body"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&comments); err != nil {
		return "", nil
	}
	for _, comment := range comments {
		if strings.Contains(comment.Body, host.Marker) {
			return comment.ID.String(), nil
		}
	}
	return "", nil
}

func (h *Host) headers(request *http.Request, token string) {
	request.Header.Set("authorization", "Bearer "+token)
	request.Header.Set("accept", "application/vnd.github+json")
	request.Header.Set("x-github-api-version", "2022-11-28")
	request.Header.Set("user-agent", "govern")
}

// Workflow commands: a message must stay on one line, so newlines are encoded
// as the runner expects.
func encode(message string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(message)
}

// Notice writes a notice annotation.
func (h *Host) Notice(message string) { fmt.Fprintf(h.out, "::notice::%s\n", encode(message)) }

// Warning writes a warning annotation.
func (h *Host) Warning(message string) { fmt.Fprintf(h.out, "::warning::%s\n", encode(message)) }

// Error writes an error annotation.
func (h *Host) Error(message string) { fmt.Fprintf(h.out, "::error::%s\n", encode(message)) }

// Group writes a collapsible log group.
func (h *Host) Group(title, body string) {
	fmt.Fprintf(h.out, "::group::%s\n%s\n::endgroup::\n", encode(title), body)
}
