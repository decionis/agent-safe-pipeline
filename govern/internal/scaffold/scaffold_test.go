package scaffold

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectReadsTheTree(t *testing.T) {
	dir := t.TempDir()
	if got := Detect(dir); got != GitHub {
		t.Fatalf("an empty tree defaults to %s", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "Jenkinsfile"), []byte("pipeline {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Detect(dir); got != Jenkins {
		t.Fatalf("Jenkinsfile → %s", got)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte("stages: []"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Detect(dir); got != GitLab {
		t.Fatalf(".gitlab-ci.yml → %s", got)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := Detect(dir); got != GitHub {
		t.Fatalf(".github/workflows → %s", got)
	}
}

func TestGitHubStarterNamesTheBranchModeAndAction(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git", "refs", "remotes", "origin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "refs", "remotes", "origin", "HEAD"), []byte("ref: refs/remotes/origin/trunk\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	result, err := Run(Options{Dir: dir, Action: "production-deploy", Version: "2.0.0", Policy: true}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if result.Host != GitHub || len(result.Files) != 2 || !result.Files[0].Written || !result.Files[1].Written {
		t.Fatalf("%+v", result)
	}
	workflow, err := os.ReadFile(filepath.Join(dir, ".github", "workflows", "decionis-govern.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"branches: [trunk]", "mode: shadow", "action: production-deploy", "uses: decionis/govern@v2", "${{ secrets.DECIONIS_API_KEY }}", "${{ vars.DECIONIS_TENANT_ID }}"} {
		if !strings.Contains(string(workflow), want) {
			t.Fatalf("workflow lacks %q:\n%s", want, workflow)
		}
	}
	if strings.Contains(string(workflow), "{{") && !strings.Contains(string(workflow), "${{") {
		t.Fatal("an unrendered placeholder")
	}
	policy, err := os.ReadFile(filepath.Join(dir, PolicyFile))
	if err != nil || !strings.HasPrefix(string(policy), "# Decionis Policy") {
		t.Fatalf("policy %v %q", err, string(policy)[:40])
	}
	if !strings.Contains(out.String(), "wrote .github/workflows/decionis-govern.yml") || !strings.Contains(out.String(), "DECIONIS_API_KEY") {
		t.Fatalf("output %q", out.String())
	}
}

func TestExistingFilesAreKeptUnlessForced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, PolicyFile)
	if err := os.WriteFile(path, []byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	result, err := Run(Options{Dir: dir, Host: GitHub, Version: "2.0.0", Policy: true}, &out)
	if err != nil {
		t.Fatal(err)
	}
	policy := result.Files[1]
	if !policy.Existed || policy.Written {
		t.Fatalf("%+v", policy)
	}
	if content, _ := os.ReadFile(path); string(content) != "mine\n" {
		t.Fatalf("overwritten: %q", content)
	}
	if !strings.Contains(out.String(), "exists; kept") {
		t.Fatal(out.String())
	}
	if _, err := Run(Options{Dir: dir, Host: GitHub, Version: "2.0.0", Policy: true, Force: true}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if content, _ := os.ReadFile(path); string(content) == "mine\n" {
		t.Fatal("--force did not overwrite")
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	result, err := Run(Options{Dir: dir, Host: GitLab, Version: "2.0.0", Policy: true, DryRun: true}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if result.Files[0].Written || result.Files[1].Written {
		t.Fatalf("%+v", result.Files)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("dry run wrote %v", entries)
	}
	if !strings.Contains(out.String(), "would write .gitlab/ci/decionis-govern.yml") {
		t.Fatal(out.String())
	}
}

func TestGitLabAndJenkinsStartersInstallThePinnedVersion(t *testing.T) {
	dir := t.TempDir()
	if _, err := Run(Options{Dir: dir, Host: GitLab, Mode: "enforce", Action: "release-publish", Version: "2.0.0", Policy: false}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	job, err := os.ReadFile(filepath.Join(dir, ".gitlab", "ci", "decionis-govern.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"GOVERN_VERSION=2.0.0", "GOVERN_MODE: enforce", "GOVERN_ACTION: release-publish", "local: .gitlab/ci/decionis-govern.yml", "GOVERN_SHELL: sh"} {
		if !strings.Contains(string(job), want) {
			t.Fatalf("gitlab starter lacks %q", want)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, PolicyFile)); err == nil {
		t.Fatal("--no-policy wrote a policy")
	}
	if _, err := Run(Options{Dir: dir, Host: Jenkins, Version: "2.0.0"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	stage, err := os.ReadFile(filepath.Join(dir, "jenkins", "decionis-govern.groovy"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stage), "credentials('decionis-api-key')") || !strings.Contains(string(stage), "GOVERN_VERSION=2.0.0") || !strings.Contains(string(stage), "GOVERN_MODE = 'shadow'") {
		t.Fatalf("jenkins starter:\n%s", stage)
	}
}

func TestRefusals(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		options Options
		code    string
	}{
		{Options{Dir: filepath.Join(dir, "missing"), Version: "2.0.0"}, "DIRECTORY_INVALID"},
		{Options{Dir: dir, Host: "circle", Version: "2.0.0"}, "HOST_INVALID"},
		{Options{Dir: dir, Mode: "loud", Version: "2.0.0"}, "MODE_INVALID"},
		{Options{Dir: dir, Action: "Deploy Now", Version: "2.0.0"}, "ACTION_INVALID"},
		{Options{Dir: dir, Branch: "a b", Version: "2.0.0"}, "BRANCH_INVALID"},
		{Options{Dir: dir}, "VERSION_MISSING"},
	}
	for _, c := range cases {
		_, err := Run(c.options, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), c.code) {
			t.Fatalf("%+v: want %s, got %v", c.options, c.code, err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("a refusal wrote %v", entries)
	}
}
