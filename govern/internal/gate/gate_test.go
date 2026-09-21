package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/decionis/agent-safe-pipeline/govern/internal/authority"
	"github.com/decionis/agent-safe-pipeline/govern/internal/authority/authoritytest"
	"github.com/decionis/agent-safe-pipeline/govern/internal/command"
	"github.com/decionis/agent-safe-pipeline/govern/internal/host"
)

// fakeHost records every surface the gate writes.
type fakeHost struct {
	facts    host.Facts
	outputs  map[string]string
	summary  string
	comment  string
	lines    []string
	comments bool
}

func newFakeHost() *fakeHost {
	return &fakeHost{facts: host.Facts{System: "github_actions", Repository: "decionis/example", Ref: "refs/heads/main", SHA: "abc", RunID: "7", RunAttempt: "1", Job: "deploy", RunURL: "https://github.example/decionis/example/actions/runs/7", WorkflowRef: "decionis/example/.github/workflows/deploy.yml@refs/heads/main", ChangeRequest: "12"}, outputs: map[string]string{}}
}

func (f *fakeHost) Name() string      { return f.facts.System }
func (f *fakeHost) Facts() host.Facts { return f.facts }
func (f *fakeHost) Outputs(values []host.Output) error {
	for _, v := range values {
		f.outputs[v.Name] = v.Value
	}
	return nil
}
func (f *fakeHost) Summary(markdown string) error { f.summary = markdown; return nil }
func (f *fakeHost) Comment(_ context.Context, body string) (bool, error) {
	f.comment = body
	return f.comments, nil
}
func (f *fakeHost) Notice(m string)   { f.lines = append(f.lines, "notice: "+m) }
func (f *fakeHost) Warning(m string)  { f.lines = append(f.lines, "warning: "+m) }
func (f *fakeHost) Error(m string)    { f.lines = append(f.lines, "error: "+m) }
func (f *fakeHost) Group(t, b string) { f.lines = append(f.lines, "group: "+t) }
func (f *fakeHost) joined() string    { return strings.Join(f.lines, "\n") }

// fakeRunner records the environment the command saw and answers a scripted exit code.
type fakeRunner struct {
	exit   int
	env    map[string]string
	ran    int
	delay  time.Duration
	failed bool
}

func (r *fakeRunner) Run(_ context.Context, spec command.Spec) command.Result {
	r.ran++
	r.env = spec.Env
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	if r.failed {
		return command.Result{Started: false, ExitCode: 127}
	}
	return command.Result{Started: true, ExitCode: r.exit, Duration: 5 * time.Millisecond}
}

func setup(t *testing.T) (*authoritytest.Double, *authority.Client) {
	t.Helper()
	double := authoritytest.New()
	t.Cleanup(double.Close)
	client, err := authority.New(authority.Options{BaseURL: double.URL(), APIKey: func() string { return authoritytest.APIKey }, AllowInsecureLoopback: true, Timeout: 5 * time.Second, UserAgent: "govern/test"})
	if err != nil {
		t.Fatal(err)
	}
	return double, client
}

func config(mode authority.Mode, amountMinor int, cmd string) Config {
	return Config{
		Mode: mode, TenantID: authoritytest.TenantID, ActionType: "production-deploy", Command: cmd, Shell: "sh",
		Parameters: map[string]any{"amountMinor": json.Number(itoa(amountMinor))}, FailOn: FailOnBlock,
		PolicyPath: "", Workspace: ".", Attribution: true, IntentTTL: 2 * time.Minute, Timeout: 5 * time.Second, Credentials: true,
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestEnforcementAllowClaimsRunsAndFinalizes(t *testing.T) {
	double, client := setup(t)
	h, runner := newFakeHost(), &fakeRunner{exit: 0}
	h.comments = true
	cfg := config(authority.Enforcement, 100, "./deploy.sh")
	cfg.Comment = true
	result := Run(context.Background(), cfg, Dependencies{Authority: client, Host: h, Runner: runner, Version: "test", Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if result.Exit != 0 || runner.ran != 1 {
		t.Fatalf("exit %d ran %d\n%s", result.Exit, runner.ran, h.joined())
	}
	rep := result.Report
	if rep.Decision.Verdict != "ALLOW" || !rep.Command.Executed || !rep.Command.Claimed || rep.Command.Outcome != "COMMITTED" || rep.Command.Finalization != "RECORDED" {
		t.Fatalf("report %s", rep.JSON())
	}
	if runner.env["DECIONIS_DECISION_ID"] != rep.Decision.DecisionID || runner.env["DECIONIS_DOSSIER_ID"] != rep.Decision.DossierID || runner.env["DECIONIS_INTENT_HASH"] != rep.Intent.Hash || runner.env["DECIONIS_CLAIM_ATTESTATION"] == "" || runner.env["GOVERN_MODE"] != "enforcement" {
		t.Fatalf("command env %+v", runner.env)
	}
	if _, leaked := runner.env["DECIONIS_EXECUTION_GRANT"]; leaked {
		t.Fatal("the grant must never reach the command")
	}
	if h.outputs["decision"] != "ALLOW" || h.outputs["executed"] != "true" || h.outputs["exit-code"] != "0" || h.outputs["outcome"] != "COMMITTED" || h.outputs["finalization"] != "RECORDED" || h.outputs["claimed"] != "true" {
		t.Fatalf("outputs %+v", h.outputs)
	}
	if !strings.Contains(h.summary, "## ✅ Govern · `production-deploy`: Allowed") || !strings.Contains(h.comment, host.Marker) || !strings.Contains(h.comment, "Governed by") {
		t.Fatalf("summary %q\ncomment %q", h.summary, h.comment)
	}
	if rep.Dossier == nil || !rep.Dossier.Fetched || rep.Dossier.KeyID != "synthetic-key-1" {
		t.Fatalf("dossier %+v", rep.Dossier)
	}
	if outcomes := double.Finalizations(); len(outcomes) != 1 {
		t.Fatalf("finalizations %+v", outcomes)
	}
	// The intent's context carries the runner's facts and the command, never a credential.
	last := double.Requests[0].Body
	ctx := last["context"].(map[string]any)
	if ctx["runner"] != "github_actions" || ctx["repository"] != "decionis/example" || ctx["command"] != "./deploy.sh" || ctx["idempotency_key"] == "" {
		t.Fatalf("context %+v", ctx)
	}
	target := last["downstream_target"].(map[string]any)
	if target["system"] != "github_actions" || target["operation"] != "production-deploy" || target["endpoint"] != h.facts.RunURL {
		t.Fatalf("target %+v", target)
	}
	actor := last["actor"].(map[string]any)
	if actor["id"] != h.facts.WorkflowRef || actor["type"] != "WORKFLOW" || actor["runtime"] != "govern/test" {
		t.Fatalf("actor %+v", actor)
	}
}

func TestEnforcementBlockNeverRunsTheCommand(t *testing.T) {
	_, client := setup(t)
	h, runner := newFakeHost(), &fakeRunner{exit: 0}
	result := Run(context.Background(), config(authority.Enforcement, 500_000, "./deploy.sh"), Dependencies{Authority: client, Host: h, Runner: runner, Version: "test"})
	if result.Exit != 1 || runner.ran != 0 || result.Report.Command.Executed || result.Report.Decision.Verdict != "BLOCK" {
		t.Fatalf("exit %d ran %d %s", result.Exit, runner.ran, result.Report.JSON())
	}
	if !strings.Contains(h.joined(), "BLOCKED execution") || h.outputs["executed"] != "false" || h.outputs["exit-code"] != "" {
		t.Fatalf("lines %s outputs %+v", h.joined(), h.outputs)
	}
}

func TestEnforcementEscalateWithoutAnApproverHoldsTheStep(t *testing.T) {
	_, client := setup(t)
	h, runner := newFakeHost(), &fakeRunner{}
	result := Run(context.Background(), config(authority.Enforcement, 50_000, "./deploy.sh"), Dependencies{Authority: client, Host: h, Runner: runner, Version: "test"})
	if result.Exit != 1 || runner.ran != 0 || result.Report.Decision.Verdict != "ESCALATE" {
		t.Fatalf("%d %d %s", result.Exit, runner.ran, result.Report.JSON())
	}
	if !strings.Contains(h.joined(), "HELD execution") {
		t.Fatal(h.joined())
	}
}

func TestManagedEscalationRunsAfterApproval(t *testing.T) {
	double, client := setup(t)
	double.Lifecycle = []string{"AWAITING_APPROVER", "GRANT_READY"}
	h, runner := newFakeHost(), &fakeRunner{exit: 3}
	cfg := config(authority.Enforcement, 50_000, "./deploy.sh")
	cfg.Managed = &authority.ManagedRequest{ApproverRoleID: "RELEASE_MANAGER"}
	result := Run(context.Background(), cfg, Dependencies{Authority: client, Host: h, Runner: runner, Version: "test"})
	if result.Exit != 3 || runner.ran != 1 || result.Report.Decision.Verdict != "ALLOW" || result.Report.Escalation == nil || result.Report.Escalation.FinalStatus != "GRANT_READY" {
		t.Fatalf("%d %d %s", result.Exit, runner.ran, result.Report.JSON())
	}
	if result.Report.Command.Outcome != "FAILED" || result.Report.Command.Finalization != "RECORDED" {
		t.Fatalf("%s", result.Report.JSON())
	}
}

func TestManagedEscalationRejectedHoldsTheStep(t *testing.T) {
	double, client := setup(t)
	double.Lifecycle = []string{"REJECTED"}
	h, runner := newFakeHost(), &fakeRunner{}
	cfg := config(authority.Enforcement, 50_000, "./deploy.sh")
	cfg.Managed = &authority.ManagedRequest{}
	result := Run(context.Background(), cfg, Dependencies{Authority: client, Host: h, Runner: runner, Version: "test"})
	if result.Exit != 1 || runner.ran != 0 || result.Report.Decision.Verdict != "BLOCK" || result.Report.Decision.ReasonCodes[0] != "PRESENCE_REJECTED" {
		t.Fatalf("%d %d %s", result.Exit, runner.ran, result.Report.JSON())
	}
}

func TestVerdictOnlyStepFollowsFailOn(t *testing.T) {
	_, client := setup(t)
	cases := []struct {
		amount int
		failOn FailOn
		exit   int
	}{
		{100, FailOnBlock, 0}, {50_000, FailOnBlock, 0}, {50_000, FailOnEscalate, 1}, {50_000, FailOnBlockOrEscalate, 1},
		{500_000, FailOnBlock, 1}, {500_000, FailOnNever, 0}, {500_000, FailOnEscalate, 0},
	}
	for _, c := range cases {
		cfg := config(authority.Enforcement, c.amount, "")
		cfg.FailOn = c.failOn
		result := Run(context.Background(), cfg, Dependencies{Authority: client, Host: newFakeHost(), Version: "test"})
		if result.Exit != c.exit {
			t.Fatalf("amount %d fail-on %s: exit %d, want %d", c.amount, c.failOn, result.Exit, c.exit)
		}
		if result.Report.Command != nil {
			t.Fatal("no command, no command record")
		}
	}
}

func TestShadowRunsFirstAndNeverFails(t *testing.T) {
	double, client := setup(t)
	h, runner := newFakeHost(), &fakeRunner{exit: 2}
	result := Run(context.Background(), config(authority.Shadow, 500_000, "./deploy.sh"), Dependencies{Authority: client, Host: h, Runner: runner, Version: "test"})
	if result.Exit != 2 || runner.ran != 1 || result.Report.Decision.Verdict != "BLOCK" || result.Report.Command.Claimed {
		t.Fatalf("%d %d %s", result.Exit, runner.ran, result.Report.JSON())
	}
	if double.Grants() != 0 || len(double.Finalizations()) != 0 {
		t.Fatal("shadow issues no grant and finalizes nothing")
	}
	if runner.env["GOVERN_MODE"] != "shadow" {
		t.Fatalf("env %+v", runner.env)
	}
	if _, present := runner.env["DECIONIS_DECISION_ID"]; present {
		t.Fatal("a speculative command cannot know a decision that has not been made")
	}
	if !strings.Contains(h.summary, "Shadow") || h.outputs["executed"] != "true" || h.outputs["exit-code"] != "2" {
		t.Fatalf("summary %q outputs %+v", h.summary, h.outputs)
	}
}

func TestShadowSurvivesAnUnreachableAuthority(t *testing.T) {
	double, client := setup(t)
	double.Close()
	h, runner := newFakeHost(), &fakeRunner{exit: 0}
	result := Run(context.Background(), config(authority.Shadow, 100, "echo ok"), Dependencies{Authority: client, Host: h, Runner: runner, Version: "test"})
	if result.Exit != 0 || runner.ran != 1 || !result.Report.Decision.FailClosed || result.Report.Decision.ReasonCodes[0] != "AUTHORITY_UNAVAILABLE" {
		t.Fatalf("%d %d %s", result.Exit, runner.ran, result.Report.JSON())
	}
	verdictOnly := Run(context.Background(), config(authority.Shadow, 100, ""), Dependencies{Authority: client, Host: newFakeHost(), Version: "test"})
	if verdictOnly.Exit != 0 {
		t.Fatalf("shadow verdict-only exit %d", verdictOnly.Exit)
	}
}

func TestShadowWithoutCredentialsIsInert(t *testing.T) {
	h, runner := newFakeHost(), &fakeRunner{exit: 0}
	cfg := config(authority.Shadow, 100, "echo ok")
	cfg.Credentials = false
	result := Run(context.Background(), cfg, Dependencies{Host: h, Runner: runner, Version: "test"})
	if result.Exit != 0 || runner.ran != 1 || result.Report.Decision.Asked {
		t.Fatalf("%d %d %s", result.Exit, runner.ran, result.Report.JSON())
	}
	enforce := config(authority.Enforcement, 100, "echo ok")
	enforce.Credentials = false
	blocked := Run(context.Background(), enforce, Dependencies{Host: newFakeHost(), Runner: &fakeRunner{}, Version: "test"})
	if blocked.Exit != 1 || blocked.Report.Decision.ReasonCodes[0] != "CREDENTIALS_MISSING" {
		t.Fatalf("%s", blocked.Report.JSON())
	}
}

func TestEnforcementRefusesWhenTheAuthorityIsUnreachable(t *testing.T) {
	double, client := setup(t)
	double.Close()
	h, runner := newFakeHost(), &fakeRunner{}
	result := Run(context.Background(), config(authority.Enforcement, 100, "./deploy.sh"), Dependencies{Authority: client, Host: h, Runner: runner, Version: "test"})
	if result.Exit != 1 || runner.ran != 0 || !result.Report.Decision.FailClosed {
		t.Fatalf("%d %d %s", result.Exit, runner.ran, result.Report.JSON())
	}
	if !strings.Contains(h.joined(), "REFUSED execution") {
		t.Fatal(h.joined())
	}
}

func TestAShellThatCannotStartFinalizesAsFailed(t *testing.T) {
	_, client := setup(t)
	h, runner := newFakeHost(), &fakeRunner{failed: true}
	result := Run(context.Background(), config(authority.Enforcement, 100, "./deploy.sh"), Dependencies{Authority: client, Host: h, Runner: runner, Version: "test"})
	if result.Exit != 127 || result.Report.Command.Executed || result.Report.Command.Outcome != "FAILED" || result.Report.Command.Finalization != "RECORDED" {
		t.Fatalf("%s", result.Report.JSON())
	}
}

func TestPolicyFileTravelsInTheIntent(t *testing.T) {
	double, client := setup(t)
	dir := t.TempDir()
	writeFile(t, dir+"/DECIONIS_POLICY.md", "# Policy\n")
	cfg := config(authority.Shadow, 100, "")
	cfg.PolicyPath, cfg.Workspace = "DECIONIS_POLICY.md", dir
	h := newFakeHost()
	result := Run(context.Background(), cfg, Dependencies{Authority: client, Host: h, Version: "test"})
	if result.Report.Policy == nil || result.Report.Policy.Path != "DECIONIS_POLICY.md" || h.outputs["policy-sha256"] != result.Report.Policy.SHA256 {
		t.Fatalf("%s %+v", result.Report.JSON(), h.outputs)
	}
	ctx := double.Requests[0].Body["context"].(map[string]any)
	described := ctx["decionis_policy"].(map[string]any)
	if described["sha256"] != result.Report.Policy.SHA256 || described["content"] != "# Policy\n" {
		t.Fatalf("%+v", described)
	}
}

func TestReportIsWrittenWhereAsked(t *testing.T) {
	_, client := setup(t)
	dir := t.TempDir()
	cfg := config(authority.Shadow, 100, "")
	cfg.ReportPath = dir + "/out/report.json"
	Run(context.Background(), cfg, Dependencies{Authority: client, Host: newFakeHost(), Version: "test"})
	var rep map[string]any
	if err := json.Unmarshal(readFile(t, cfg.ReportPath), &rep); err != nil || rep["version"] != "agent-safe.govern-report/1" || rep["mode"] != "SHADOW" {
		t.Fatalf("%v %+v", err, rep)
	}
	var stdout bytes.Buffer
	cfg.ReportPath = "-"
	Run(context.Background(), cfg, Dependencies{Authority: client, Host: newFakeHost(), Version: "test", Stdout: &stdout})
	if !strings.HasPrefix(stdout.String(), `{"version":"agent-safe.govern-report/1"`) {
		t.Fatalf("%q", stdout.String())
	}
}
