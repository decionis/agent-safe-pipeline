package jenkins

import (
	"bytes"
	"testing"

	"github.com/decionis/agent-safe-pipeline/govern/v2/internal/host"
)

func TestFactsReadTheBuildAndItsRepository(t *testing.T) {
	values := map[string]string{"JENKINS_URL": "https://ci.example/", "BUILD_NUMBER": "12", "BUILD_URL": "https://ci.example/job/app/12/", "JOB_NAME": "app", "GIT_URL": "git@github.com:decionis/example.git", "GIT_COMMIT": "abc", "GIT_BRANCH": "origin/main", "CHANGE_ID": "4"}
	h := New(func(k string) string { return values[k] }, &bytes.Buffer{})
	facts := h.Facts()
	if facts.System != host.Jenkins || facts.Repository != "decionis/example" || facts.RunID != "12" || facts.RunURL != "https://ci.example/job/app/12/" || facts.ChangeRequest != "4" || facts.ServerURL != "https://ci.example" {
		t.Fatalf("%+v", facts)
	}
	for url, want := range map[string]string{"https://gitlab.example/group/sub/app.git": "sub/app", "https://github.com/decionis/example": "decionis/example", "example.git": "", "": ""} {
		if got := repositoryOf(url); got != want {
			t.Fatalf("%q → %q, want %q", url, got, want)
		}
	}
}
