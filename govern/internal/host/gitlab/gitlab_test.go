package gitlab

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/decionis/agent-safe-pipeline/govern/internal/host"
)

func env(values map[string]string) host.Environment {
	return func(key string) string { return values[key] }
}

func TestFactsComeFromTheJobVariables(t *testing.T) {
	h := New(env(map[string]string{"CI_PROJECT_PATH": "group/app", "CI_COMMIT_SHA": "abc", "CI_JOB_URL": "https://gitlab.example/group/app/-/jobs/1", "CI_MERGE_REQUEST_IID": "3", "CI_ENVIRONMENT_NAME": "production"}), &bytes.Buffer{}, nil)
	facts := h.Facts()
	if facts.System != host.GitLab || facts.Repository != "group/app" || facts.RunURL != "https://gitlab.example/group/app/-/jobs/1" || facts.ChangeRequest != "3" || facts.Environment != "production" {
		t.Fatalf("%+v", facts)
	}
}

func TestMergeRequestNoteIsUpsertedWithTheProjectToken(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("PRIVATE-TOKEN") != "synthetic-token" {
			w.WriteHeader(401)
			return
		}
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 11, "body": "hello"}})
			return
		}
		w.WriteHeader(201)
	}))
	defer server.Close()
	h := New(env(map[string]string{"CI_PROJECT_ID": "8", "CI_MERGE_REQUEST_IID": "3", "CI_API_V4_URL": server.URL, "GOVERN_GITLAB_TOKEN": "synthetic-token"}), &bytes.Buffer{}, server.Client())
	posted, err := h.Comment(context.Background(), host.Marker+" body")
	if err != nil || !posted || strings.Join(calls, ",") != "GET /projects/8/merge_requests/3/notes,POST /projects/8/merge_requests/3/notes" {
		t.Fatalf("%v %v %v", posted, err, calls)
	}
	quiet := New(env(map[string]string{"CI_PROJECT_ID": "8", "CI_MERGE_REQUEST_IID": "3", "CI_API_V4_URL": server.URL}), &bytes.Buffer{}, nil)
	if posted, err := quiet.Comment(context.Background(), "x"); posted || err != nil {
		t.Fatalf("%v %v", posted, err)
	}
}

func TestGroupIsACollapsedSection(t *testing.T) {
	var out bytes.Buffer
	New(env(map[string]string{}), &out, nil).Group("Decionis intent", "hash=…")
	if !strings.Contains(out.String(), "section_start:") || !strings.Contains(out.String(), "[collapsed=true]\r\x1b[0KDecionis intent\nhash=…\n") || !strings.Contains(out.String(), "section_end:") {
		t.Fatalf("%q", out.String())
	}
}
