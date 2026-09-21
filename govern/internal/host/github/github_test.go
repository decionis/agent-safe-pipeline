package github

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decionis/agent-safe-pipeline/govern/internal/host"
)

func env(values map[string]string) host.Environment {
	return func(key string) string { return values[key] }
}

func TestFactsAndPullRequestNumber(t *testing.T) {
	dir := t.TempDir()
	event := filepath.Join(dir, "event.json")
	_ = os.WriteFile(event, []byte(`{"pull_request":{"number":42}}`), 0o644)
	h := New(env(map[string]string{"GITHUB_REPOSITORY": "decionis/example", "GITHUB_RUN_ID": "7", "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_PATH": event, "GITHUB_WORKFLOW_REF": "decionis/example/.github/workflows/deploy.yml@refs/heads/main"}), &bytes.Buffer{}, nil)
	facts := h.Facts()
	if facts.RunURL != "https://github.com/decionis/example/actions/runs/7" || facts.ChangeRequest != "42" || facts.System != host.GitHub || facts.WorkflowRef == "" {
		t.Fatalf("%+v", facts)
	}
	fromRef := New(env(map[string]string{"GITHUB_REF": "refs/pull/9/merge"}), &bytes.Buffer{}, nil)
	if fromRef.Facts().ChangeRequest != "9" {
		t.Fatalf("%+v", fromRef.Facts())
	}
}

func TestOutputsUseTheDelimitedForm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outputs")
	h := New(env(map[string]string{"GITHUB_OUTPUT": path}), &bytes.Buffer{}, nil)
	if err := h.Outputs([]host.Output{{Name: "badge-markdown", Value: "two\nlines"}}); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path)
	text := string(content)
	if !strings.HasPrefix(text, "badge-markdown<<govern_badge_markdown_") || !strings.Contains(text, "\ntwo\nlines\n") {
		t.Fatalf("%q", text)
	}
	if err := New(env(map[string]string{}), &bytes.Buffer{}, nil).Outputs([]host.Output{{Name: "x", Value: "y"}}); err != nil {
		t.Fatal("without GITHUB_OUTPUT nothing is written and nothing fails")
	}
}

func TestWorkflowCommandsEncodeNewlines(t *testing.T) {
	var out bytes.Buffer
	h := New(env(map[string]string{}), &out, nil)
	h.Notice("a\nb%")
	h.Warning("w")
	h.Error("e")
	h.Group("g", "body")
	if out.String() != "::notice::a%0Ab%25\n::warning::w\n::error::e\n::group::g\nbody\n::endgroup::\n" {
		t.Fatalf("%q", out.String())
	}
}

func TestCommentIsUpsertedByMarker(t *testing.T) {
	var calls []string
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("authorization") != "Bearer synthetic-token" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 1, "body": "unrelated"}, {"id": 2, "body": host.Marker + "\nold"}})
		default:
			var payload map[string]string
			_ = json.NewDecoder(r.Body).Decode(&payload)
			bodies = append(bodies, payload["body"])
			w.WriteHeader(200)
		}
	}))
	defer server.Close()
	h := New(env(map[string]string{"GITHUB_REPOSITORY": "decionis/example", "GITHUB_REF": "refs/pull/5/merge", "GITHUB_TOKEN": "synthetic-token", "GITHUB_API_URL": server.URL}), &bytes.Buffer{}, server.Client())
	posted, err := h.Comment(context.Background(), host.Marker+"\nnew")
	if err != nil || !posted {
		t.Fatalf("%v %v", posted, err)
	}
	if strings.Join(calls, ",") != "GET /repos/decionis/example/issues/5/comments,PATCH /repos/decionis/example/issues/comments/2" || bodies[0] != host.Marker+"\nnew" {
		t.Fatalf("%v %v", calls, bodies)
	}
	// No token: no surface, no error.
	quiet := New(env(map[string]string{"GITHUB_REPOSITORY": "decionis/example", "GITHUB_REF": "refs/pull/5/merge"}), &bytes.Buffer{}, nil)
	if posted, err := quiet.Comment(context.Background(), "x"); posted || err != nil {
		t.Fatalf("%v %v", posted, err)
	}
}
