// Package gitlab is the GitLab CI host: facts from CI_*, outputs as a dotenv
// report a later job reads, collapsible sections in the job log, and a
// merge-request note through the API when a token is given.
package gitlab

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

	"github.com/decionis/agent-safe-pipeline/govern/v2/internal/host"
)

// Host is one GitLab CI job.
type Host struct {
	env   host.Environment
	out   io.Writer
	http  *http.Client
	facts host.Facts
	now   func() time.Time
}

// New reads the job from its environment.
func New(env host.Environment, out io.Writer, client *http.Client) *Host {
	if out == nil {
		out = os.Stdout
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	h := &Host{env: env, out: out, http: client, now: time.Now}
	h.facts = host.Facts{
		System:        host.GitLab,
		Repository:    env("CI_PROJECT_PATH"),
		Ref:           env("CI_COMMIT_REF_NAME"),
		SHA:           env("CI_COMMIT_SHA"),
		Event:         env("CI_PIPELINE_SOURCE"),
		Actor:         env("GITLAB_USER_LOGIN"),
		RunID:         env("CI_PIPELINE_ID"),
		RunURL:        env("CI_PIPELINE_URL"),
		Workflow:      env("CI_PIPELINE_NAME"),
		Job:           env("CI_JOB_NAME"),
		ServerURL:     env("CI_SERVER_URL"),
		Environment:   env("CI_ENVIRONMENT_NAME"),
		ChangeRequest: env("CI_MERGE_REQUEST_IID"),
	}
	if h.facts.RunURL == "" {
		h.facts.RunURL = env("CI_JOB_URL")
	}
	return h
}

// Name is the runner token.
func (h *Host) Name() string { return host.GitLab }

// Facts is what the job says about itself.
func (h *Host) Facts() host.Facts { return h.facts }

// Outputs writes the dotenv report, `govern.env` unless GOVERN_OUTPUT_FILE says
// where; declare it under `artifacts: reports: dotenv` and later jobs see
// GOVERN_DECISION and the rest as variables.
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

// Comment upserts the gate's note on the merge request the pipeline is for.
// It needs a project or group access token with `api` scope in
// GOVERN_GITLAB_TOKEN; the job token cannot write notes.
func (h *Host) Comment(ctx context.Context, body string) (bool, error) {
	token := h.env("GOVERN_GITLAB_TOKEN")
	project := h.env("CI_PROJECT_ID")
	api := strings.TrimRight(h.env("CI_API_V4_URL"), "/")
	if token == "" || project == "" || h.facts.ChangeRequest == "" || api == "" {
		return false, nil
	}
	notes := api + "/projects/" + project + "/merge_requests/" + h.facts.ChangeRequest + "/notes"
	existing, err := h.findNote(ctx, token, notes)
	if err != nil {
		return false, err
	}
	method, target := http.MethodPost, notes
	if existing != "" {
		method, target = http.MethodPut, notes+"/"+existing
	}
	payload, _ := json.Marshal(map[string]string{"body": body})
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	request.Header.Set("PRIVATE-TOKEN", token)
	request.Header.Set("content-type", "application/json")
	response, err := h.http.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false, fmt.Errorf("GITLAB_NOTE_REFUSED: HTTP %d", response.StatusCode)
	}
	return true, nil
}

func (h *Host) findNote(ctx context.Context, token, notes string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, notes+"?per_page=100&sort=desc", nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("PRIVATE-TOKEN", token)
	response, err := h.http.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", nil
	}
	var list []struct {
		ID   json.Number `json:"id"`
		Body string      `json:"body"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&list); err != nil {
		return "", nil
	}
	for _, note := range list {
		if strings.Contains(note.Body, host.Marker) {
			return note.ID.String(), nil
		}
	}
	return "", nil
}

// Notice writes a plain line.
func (h *Host) Notice(message string) { host.Plain{Out: h.out}.Notice(message) }

// Warning writes a warning line.
func (h *Host) Warning(message string) { host.Plain{Out: h.out}.Warning(message) }

// Error writes an error line.
func (h *Host) Error(message string) { host.Plain{Out: h.out}.Error(message) }

// Group writes a collapsed job-log section.
func (h *Host) Group(title, body string) {
	id := "govern_" + fmt.Sprint(h.now().UnixNano())
	stamp := h.now().Unix()
	fmt.Fprintf(h.out, "\x1b[0Ksection_start:%d:%s[collapsed=true]\r\x1b[0K%s\n%s\n\x1b[0Ksection_end:%d:%s\r\x1b[0K\n", stamp, id, strings.TrimSpace(title), body, stamp, id)
}
