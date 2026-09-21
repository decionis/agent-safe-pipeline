package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decionis/agent-safe-pipeline/govern/v2/internal/authority/authoritytest"
)

func environment(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func githubEnvironment(t *testing.T, double *authoritytest.Double, extra map[string]string) (map[string]string, string, string) {
	t.Helper()
	dir := t.TempDir()
	outputs := filepath.Join(dir, "outputs.txt")
	summary := filepath.Join(dir, "summary.md")
	env := map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "decionis/example", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "0123abc",
		"GITHUB_RUN_ID": "99", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "deploy", "GITHUB_WORKFLOW": "Deploy", "GITHUB_ACTOR": "octocat",
		"GITHUB_OUTPUT": outputs, "GITHUB_STEP_SUMMARY": summary, "GITHUB_WORKSPACE": dir,
		"DECIONIS_API_KEY": authoritytest.APIKey, "DECIONIS_TENANT_ID": authoritytest.TenantID,
		"DECIONIS_API_URL": double.URL(), "DECIONIS_ALLOW_INSECURE_LOOPBACK": "true",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env, outputs, summary
}

func parseOutputs(t *testing.T, path string) map[string]string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	lines := strings.Split(string(content), "\n")
	for i := 0; i < len(lines); i++ {
		name, delimiter, ok := strings.Cut(lines[i], "<<")
		if !ok {
			continue
		}
		var value []string
		for i++; i < len(lines) && lines[i] != delimiter; i++ {
			value = append(value, lines[i])
		}
		out[name] = strings.Join(value, "\n")
	}
	return out
}

func TestRunEnforcesOnGitHub(t *testing.T) {
	double := authoritytest.New()
	defer double.Close()
	env, outputs, summary := githubEnvironment(t, double, map[string]string{"GOVERN_ACTION": "production-deploy", "GOVERN_PAYLOAD": `{"amountMinor": 100}`, "GOVERN_ENVIRONMENT": "production"})
	var stdout, stderr bytes.Buffer
	code := Main(context.Background(), Process{Args: []string{"run", "--report", filepath.Join(env["GITHUB_WORKSPACE"], "report.json"), "--", "sh", "-c", "echo deployed $DECIONIS_DECISION_ID"}, Env: environment(env), Stdout: &stdout, Stderr: &stderr, Version: "2.0.0-test"})
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, stdout.String(), stderr.String())
	}
	got := parseOutputs(t, outputs)
	if got["decision"] != "ALLOW" || got["executed"] != "true" || got["claimed"] != "true" || got["outcome"] != "COMMITTED" || got["finalization"] != "RECORDED" || got["mode"] != "ENFORCEMENT" || got["decision-id"] == "" {
		t.Fatalf("outputs %+v", got)
	}
	if !strings.Contains(stdout.String(), "deployed synthetic-decision-1") || !strings.Contains(stdout.String(), "::notice::Decionis verdict: ALLOW") {
		t.Fatalf("stdout %q", stdout.String())
	}
	md, _ := os.ReadFile(summary)
	if !strings.Contains(string(md), "Govern · `production-deploy`: Allowed") {
		t.Fatalf("summary %q", md)
	}
	raw, _ := os.ReadFile(filepath.Join(env["GITHUB_WORKSPACE"], "report.json"))
	var rep map[string]any
	if json.Unmarshal(raw, &rep) != nil || rep["runner"] != "github_actions" || rep["exit"] != float64(0) {
		t.Fatalf("report %s", raw)
	}
	request := double.Requests[0]
	if !strings.HasPrefix(request.Headers.Get("user-agent"), "govern/2.0.0-test (example=govern@2.0.0-test; surface=github_actions; repo=decionis/example)") {
		t.Fatalf("user-agent %q", request.Headers.Get("user-agent"))
	}
	target := request.Body["downstream_target"].(map[string]any)
	if target["environment"] != "production" || target["endpoint"] != "https://github.com/decionis/example/actions/runs/99" {
		t.Fatalf("target %+v", target)
	}
}

func TestRunBlocksOnGitHub(t *testing.T) {
	double := authoritytest.New()
	defer double.Close()
	env, outputs, _ := githubEnvironment(t, double, map[string]string{"GOVERN_PAYLOAD": `{"amountMinor": 500000}`, "GOVERN_RUN": "echo ran-$((1+1))"})
	var stdout bytes.Buffer
	code := Main(context.Background(), Process{Args: []string{"run"}, Env: environment(env), Stdout: &stdout, Stderr: &stdout, Version: "t"})
	if code != 1 || strings.Contains(stdout.String(), "ran-2") || !strings.Contains(stdout.String(), "::error::Decionis BLOCKED execution") {
		t.Fatalf("exit %d\n%s", code, stdout.String())
	}
	if got := parseOutputs(t, outputs); got["decision"] != "BLOCK" || got["executed"] != "false" {
		t.Fatalf("%+v", got)
	}
}

func TestShadowOnGitLabWritesTheDotenvReport(t *testing.T) {
	double := authoritytest.New()
	defer double.Close()
	dir := t.TempDir()
	env := map[string]string{
		"GITLAB_CI": "true", "CI_PROJECT_PATH": "decionis/example", "CI_COMMIT_SHA": "abc", "CI_COMMIT_REF_NAME": "main", "CI_PIPELINE_ID": "5", "CI_JOB_NAME": "deploy", "CI_PROJECT_DIR": dir,
		"GOVERN_OUTPUT_FILE": filepath.Join(dir, "govern.env"), "GOVERN_MODE": "shadow", "GOVERN_ACTION": "production-deploy",
		"DECIONIS_API_KEY": authoritytest.APIKey, "DECIONIS_TENANT_ID": authoritytest.TenantID, "DECIONIS_API_URL": double.URL(), "DECIONIS_ALLOW_INSECURE_LOOPBACK": "true",
	}
	var stdout bytes.Buffer
	code := Main(context.Background(), Process{Args: []string{"run", "--payload", `{"amountMinor": 500000}`, "--", "sh", "-c", "exit 4"}, Env: environment(env), Stdout: &stdout, Stderr: &stdout, Version: "t"})
	if code != 4 {
		t.Fatalf("exit %d\n%s", code, stdout.String())
	}
	dotenv, _ := os.ReadFile(filepath.Join(dir, "govern.env"))
	text := string(dotenv)
	if !strings.Contains(text, "GOVERN_DECISION=BLOCK\n") || !strings.Contains(text, "GOVERN_EXECUTED=true\n") || !strings.Contains(text, "GOVERN_EXIT_CODE=4\n") || !strings.Contains(text, "GOVERN_MODE=SHADOW\n") {
		t.Fatalf("dotenv %q", text)
	}
	if !strings.Contains(stdout.String(), "govern: Decionis verdict: BLOCK") {
		t.Fatalf("%q", stdout.String())
	}
	if double.Grants() != 0 {
		t.Fatal("shadow issued a grant")
	}
}

func TestUsageErrors(t *testing.T) {
	base := map[string]string{"DECIONIS_API_KEY": "k", "DECIONIS_TENANT_ID": authoritytest.TenantID}
	cases := []struct {
		args []string
		env  map[string]string
		want string
	}{
		{[]string{"run", "--mode", "loud"}, base, "--mode must be shadow or enforce"},
		{[]string{"run", "--payload", "[1]"}, base, "--payload must be a JSON object"},
		{[]string{"run", "--fail-on", "sometimes"}, base, "--fail-on must be"},
		{[]string{"run", "--run", "a", "--", "b"}, base, "either as --run or after --"},
		{[]string{"run", "--mode", "shadow", "--escalation", "managed"}, base, "shadow never holds a step"},
		{[]string{"run", "--host", "circle"}, base, "--host must be"},
		{[]string{"run"}, map[string]string{"DECIONIS_API_KEY": "k"}, "DECIONIS_TENANT_ID"},
		{[]string{"run", "--api-url", "http://api.decionis.example"}, base, "DECIONIS_URL_MUST_USE_HTTPS"},
		{[]string{"frobnicate"}, base, "unknown command"},
	}
	for _, c := range cases {
		var stderr bytes.Buffer
		code := Main(context.Background(), Process{Args: c.args, Env: environment(c.env), Stdout: &bytes.Buffer{}, Stderr: &stderr, Version: "t"})
		if code != ExitUsage || !strings.Contains(stderr.String(), c.want) {
			t.Fatalf("%v: exit %d, stderr %q", c.args, code, stderr.String())
		}
	}
	var stdout bytes.Buffer
	if code := Main(context.Background(), Process{Args: []string{"run", "--", "echo", "ran-$((1+1))"}, Env: environment(map[string]string{}), Stdout: &stdout, Stderr: &stdout, Version: "t"}); code != 1 || strings.Contains(stdout.String(), "ran-2") || !strings.Contains(stdout.String(), "enforcement needs DECIONIS_API_KEY") {
		t.Fatalf("enforcement without a key: exit %d %q", code, stdout.String())
	}
}

func TestVersionAndHelp(t *testing.T) {
	var stdout bytes.Buffer
	if code := Main(context.Background(), Process{Args: []string{"version"}, Stdout: &stdout, Version: "2.0.0"}); code != 0 || stdout.String() != "govern 2.0.0\n" {
		t.Fatalf("%d %q", code, stdout.String())
	}
	stdout.Reset()
	if code := Main(context.Background(), Process{Args: []string{"help"}, Stdout: &stdout, Version: "2.0.0"}); code != 0 || !strings.Contains(stdout.String(), "govern run [flags]") {
		t.Fatalf("%d %q", code, stdout.String())
	}
}

func TestShellJoinQuotesWhatNeedsIt(t *testing.T) {
	if got := shellJoin([]string{"./deploy.sh", "--env", "prod us", "it's", "a=b"}); got != `./deploy.sh --env 'prod us' 'it'\''s' a=b` {
		t.Fatalf("%q", got)
	}
}
