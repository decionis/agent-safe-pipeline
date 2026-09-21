// Package gate runs one governed step: capture the intent, ask the authority,
// and let the command run only when the decision says so. In shadow the
// command starts at once and the verdict is recorded beside it; in
// enforcement nothing runs before a grant is claimed, and what happened is
// finalized with the authority afterwards. The gate never authorizes anything
// itself: an authority it cannot reach, or an answer it cannot read, is a
// refusal.
package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/decionis/agent-safe-pipeline/govern/internal/authority"
	"github.com/decionis/agent-safe-pipeline/govern/internal/command"
	"github.com/decionis/agent-safe-pipeline/govern/internal/host"
	"github.com/decionis/agent-safe-pipeline/govern/internal/intent"
	"github.com/decionis/agent-safe-pipeline/govern/internal/policy"
	"github.com/decionis/agent-safe-pipeline/govern/internal/report"
)

// FailOn says which verdict fails a step that wraps no command; a step that
// wraps one fails whenever the command may not run.
type FailOn string

// The fail-on choices.
const (
	FailOnBlock           FailOn = "block"
	FailOnEscalate        FailOn = "escalate"
	FailOnBlockOrEscalate FailOn = "block_or_escalate"
	FailOnNever           FailOn = "never"
)

// Grace bounds how long a shadow run waits for its verdict after the command exits.
const (
	ShadowGraceCap   = 10 * time.Second
	ShadowGraceExtra = 2500 * time.Millisecond
)

// Config is one run's settings, already validated by the caller.
type Config struct {
	Mode        authority.Mode
	TenantID    string
	ActionType  string
	Resource    string
	Parameters  map[string]any
	Environment string
	// Command is the gated command line; empty means verdict only.
	Command string
	Shell   string
	FailOn  FailOn
	// Managed, when set, asks Decionis to orchestrate an ESCALATE and holds the step for it.
	Managed *authority.ManagedRequest
	// PolicyPath names the repository policy file; "" disables it.
	PolicyPath string
	Workspace  string
	Comment    bool
	// Attribution keeps the footer on the comment.
	Attribution bool
	IntentTTL   time.Duration
	Timeout     time.Duration
	ActorID     string
	ActorType   string
	ReportPath  string
	// Credentials is false when no key was configured: shadow then runs the
	// command and records nothing; enforcement refuses.
	Credentials bool
}

// Dependencies are the run's collaborators; tests supply doubles.
type Dependencies struct {
	Authority *authority.Client
	Host      host.Host
	Runner    command.Runner
	Version   string
	Stdout    io.Writer
	Stderr    io.Writer
	Now       func() time.Time
}

// Result is the report and the exit code the process ends with.
type Result struct {
	Report report.Report
	Exit   int
}

type run struct {
	cfg  Config
	deps Dependencies
	rep  report.Report
}

// Run performs the step and returns its report and exit code. It does not exit
// the process and never panics on the authority's answers.
func Run(ctx context.Context, cfg Config, deps Dependencies) Result {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Stdout == nil {
		deps.Stdout = os.Stdout
	}
	if deps.Stderr == nil {
		deps.Stderr = os.Stderr
	}
	if deps.Runner == nil {
		deps.Runner = command.Shell{}
	}
	r := &run{cfg: cfg, deps: deps}
	r.rep = report.Report{
		Version: report.Version,
		At:      report.Now(deps.Now()),
		Runtime: "govern/" + deps.Version,
		Runner:  deps.Host.Name(),
		Mode:    string(cfg.Mode),
		Action:  cfg.ActionType,
		Decision: report.Decision{
			Verdict:     "",
			ReasonCodes: []string{},
		},
	}
	if cfg.Command != "" {
		r.rep.Command = &report.Command{Line: cfg.Command}
	}
	exit := r.execute(ctx)
	r.rep.Exit = exit
	r.publish(ctx)
	return Result{Report: r.rep, Exit: exit}
}

func (r *run) execute(ctx context.Context) int {
	h := r.deps.Host
	source := policy.Load(r.cfg.PolicyPath, r.cfg.Workspace)
	if source != nil {
		r.rep.Policy = &report.Policy{Path: source.Path, SHA256: source.SHA256, Bytes: source.Bytes, Truncated: source.Truncated}
		h.Group("Decionis policy file", fmt.Sprintf("path=%s sha256=%s bytes=%d%s", source.Path, source.SHA256, source.Bytes, map[bool]string{true: " (referenced by hash; over the inline limit)", false: ""}[source.Truncated]))
	}

	// Shadow without a key: the gate is not configured yet and must stay inert.
	if !r.cfg.Credentials {
		if r.cfg.Mode == authority.Shadow {
			h.Notice("Decionis shadow — no DECIONIS_API_KEY and DECIONIS_TENANT_ID yet, so nothing is recorded; shadow never fails the step.")
			r.rep.Notes = append(r.rep.Notes, "Not configured: no key, so the authority was not asked.")
			if r.cfg.Command != "" {
				return r.runCommand(ctx, nil)
			}
			return 0
		}
		h.Error("Decionis enforcement needs DECIONIS_API_KEY and DECIONIS_TENANT_ID; the gated step did not run.")
		r.rep.Decision = report.Decision{Verdict: "BLOCK", ReasonCodes: []string{"CREDENTIALS_MISSING"}, FailClosed: true}
		return 1
	}

	captured, err := r.capture(source)
	if err != nil {
		h.Error("Decionis could not capture the intent: " + err.Error())
		r.rep.Decision = report.Decision{Verdict: "BLOCK", ReasonCodes: []string{firstToken(err.Error())}, FailClosed: true}
		if r.cfg.Mode == authority.Shadow {
			r.rep.Notes = append(r.rep.Notes, "The intent could not be captured; shadow ran the command without a record.")
			if r.cfg.Command != "" {
				return r.runCommand(ctx, nil)
			}
			return 0
		}
		return 1
	}
	r.rep.Intent = &report.Intent{ID: captured.Binding.IntentID, Hash: captured.Hash, ActionType: captured.Binding.Action.Type, Resource: captured.Binding.Action.Resource, CapturedAt: captured.Binding.CapturedAt, ExpiresAt: captured.Binding.ExpiresAt}
	h.Group("Decionis execution intent", fmt.Sprintf("intent_id=%s\nintent_hash=%s\naction=%s\nresource=%s\nmode=%s\nexpires_at=%s", captured.Binding.IntentID, captured.Hash, captured.Binding.Action.Type, captured.Binding.Action.Resource, r.cfg.Mode, captured.Binding.ExpiresAt))

	if r.cfg.Mode == authority.Shadow {
		return r.shadow(ctx, captured)
	}
	return r.enforce(ctx, captured)
}

// shadow records the verdict; the command, when there is one, starts first
// and the step ends with its exit code, whatever the authority said or did not.
func (r *run) shadow(ctx context.Context, captured intent.Captured) int {
	h := r.deps.Host
	if r.cfg.Command == "" {
		decision := r.deps.Authority.EnforceAndBind(ctx, captured, authority.Shadow, nil)
		r.adopt(captured, decision)
		return 0
	}
	h.Notice("🟣 Decionis shadow — the command starts now; the verdict resolves beside it and never changes the exit code.")
	type answer struct{ decision authority.Decision }
	answers := make(chan answer, 1)
	started := r.deps.Now()
	shadowCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		answers <- answer{r.deps.Authority.EnforceAndBind(shadowCtx, captured, authority.Shadow, nil)}
	}()
	exit := r.runCommand(ctx, nil)
	remaining := r.cfg.Timeout - r.deps.Now().Sub(started)
	if remaining < 0 {
		remaining = 0
	}
	grace := remaining + ShadowGraceExtra
	if grace > ShadowGraceCap {
		grace = ShadowGraceCap
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case a := <-answers:
		r.adopt(captured, a.decision)
	case <-timer.C:
		cancel()
		h.Notice(fmt.Sprintf("Decionis shadow verdict still pending after the %s grace window — completing with the command's exit code.", grace.Round(time.Millisecond)))
		r.rep.Decision = report.Decision{Verdict: "", ReasonCodes: []string{"SHADOW_VERDICT_PENDING"}, Asked: true}
		r.rep.Notes = append(r.rep.Notes, "The shadow verdict was still pending when the command finished.")
	}
	return exit
}

// enforce asks for a decision and lets the command run only on a claimed grant.
func (r *run) enforce(ctx context.Context, captured intent.Captured) int {
	h := r.deps.Host
	decision := r.deps.Authority.EnforceAndBind(ctx, captured, authority.Enforcement, r.cfg.Managed)
	if decision.Verdict == authority.Escalate && decision.Managed != nil && !decision.FailClosed {
		h.Notice(fmt.Sprintf("Decionis ESCALATE — Decionis is orchestrating the approval (escalation %s); the step holds until %s.", decision.Managed.EscalationID, captured.Binding.ExpiresAt))
		r.rep.Escalation = &report.Escalation{EscalationID: decision.Managed.EscalationID, FinalStatus: decision.Managed.Status}
		final := r.deps.Authority.WaitForManaged(ctx, captured, decision.Managed, authority.WaitOptions{OnStatus: func(status string, _ []string) {
			r.rep.Escalation.FinalStatus = status
			h.Notice("Decionis escalation " + strings.ToLower(strings.ReplaceAll(status, "_", " ")))
		}})
		if final.DecisionID == "" {
			final.DecisionID, final.DossierID = decision.DecisionID, decision.DossierID
		}
		decision = final
	}
	r.adopt(captured, decision)

	if r.cfg.Command == "" {
		if r.fails(decision) {
			h.Error(fmt.Sprintf("Decionis %s this step (verdict=%s, reasons=%s, fail-on=%s).", verb(decision), decision.Verdict, strings.Join(decision.ReasonCodes, ","), r.cfg.FailOn))
			return 1
		}
		return 0
	}
	if !decision.Executable() {
		r.rep.Command.Executed = false
		h.Error(fmt.Sprintf("Decionis %s execution (verdict=%s, reasons=%s). The gated command was NOT run.%s", verb(decision), decision.Verdict, strings.Join(decision.ReasonCodes, ","), dossierNote(decision)))
		return 1
	}
	claim, code := r.deps.Authority.ClaimGrant(ctx, captured, decision)
	if claim == nil {
		r.rep.Decision.FailClosed = true
		r.rep.Decision.ReasonCodes = append(r.rep.Decision.ReasonCodes, code)
		r.rep.Command.Executed = false
		h.Error(fmt.Sprintf("Decionis refused the claim (%s). The gated command was NOT run.%s", code, dossierNote(decision)))
		return 1
	}
	r.rep.Command.Claimed = true
	h.Notice(fmt.Sprintf("Decionis authorized execution — grant %s claimed for decision %s; running the gated command.", claim.GrantID, claim.DecisionID))
	exit := r.runCommand(ctx, claim)
	outcome := authority.Committed
	switch {
	case !r.rep.Command.Executed:
		outcome = authority.Failed
	case r.rep.Command.Signal != "":
		outcome = authority.Indeterminate
	case exit != 0:
		outcome = authority.Failed
	}
	evidence := authority.Evidence{"observer": "govern/" + r.deps.Version, "exit_code": exit, "duration_ms": r.rep.Command.DurationMs, "runner": r.deps.Host.Name()}
	if r.rep.Command.Signal != "" {
		evidence["signal"] = r.rep.Command.Signal
	}
	finalization := r.deps.Authority.Finalize(ctx, claim, outcome, evidence)
	r.rep.Command.Outcome = string(outcome)
	r.rep.Command.Finalization = string(finalization)
	if finalization == authority.Pending {
		h.Warning("Decionis did not record the finalization (PENDING); the authority's lease recovery owns it. The command's outcome is unchanged.")
	} else {
		h.Notice(fmt.Sprintf("Decionis recorded the outcome %s for decision %s.", outcome, claim.DecisionID))
	}
	return exit
}

func (r *run) fails(decision authority.Decision) bool {
	if decision.FailClosed {
		return r.cfg.FailOn != FailOnNever
	}
	switch r.cfg.FailOn {
	case FailOnNever:
		return false
	case FailOnEscalate:
		return decision.Verdict == authority.Escalate
	case FailOnBlockOrEscalate:
		return decision.Verdict == authority.Block || decision.Verdict == authority.Escalate
	}
	return decision.Verdict == authority.Block
}

// runCommand runs the gated command with the decision's identifiers in its
// environment and records what was observed.
func (r *run) runCommand(ctx context.Context, claim *authority.Claim) int {
	env := map[string]string{"GOVERN_MODE": strings.ToLower(string(r.cfg.Mode))}
	if r.rep.Intent != nil {
		env["DECIONIS_INTENT_ID"] = r.rep.Intent.ID
		env["DECIONIS_INTENT_HASH"] = r.rep.Intent.Hash
	}
	if r.rep.Decision.DecisionID != "" {
		env["DECIONIS_DECISION_ID"] = r.rep.Decision.DecisionID
		env["DECIONIS_DOSSIER_ID"] = r.rep.Decision.DossierID
	}
	if claim != nil {
		env["DECIONIS_DECISION_ID"] = claim.DecisionID
		env["DECIONIS_DOSSIER_ID"] = claim.DossierID
		env["DECIONIS_GRANT_ID"] = claim.GrantID
		if claim.Attestation != "" {
			// The authority's own proof of the claim, for a target that verifies
			// before it acts; the grant itself never leaves the gate.
			env["DECIONIS_CLAIM_ATTESTATION"] = claim.Attestation
		}
	}
	result := r.deps.Runner.Run(ctx, command.Spec{Shell: r.cfg.Shell, Line: r.cfg.Command, Env: env, Dir: r.cfg.Workspace, Stdout: r.deps.Stdout, Stderr: r.deps.Stderr})
	code := result.ExitCode
	r.rep.Command.Executed = result.Started
	r.rep.Command.ExitCode = &code
	r.rep.Command.DurationMs = result.Duration.Milliseconds()
	r.rep.Command.Signal = result.Signal
	if !result.Started {
		r.deps.Host.Error("Decionis could not start the gated command's shell.")
	}
	return code
}

// adopt records the authority's answer in the report.
func (r *run) adopt(captured intent.Captured, decision authority.Decision) {
	r.rep.Decision = report.Decision{
		Verdict:         string(decision.Verdict),
		DecisionID:      decision.DecisionID,
		DossierID:       decision.DossierID,
		ReasonCodes:     append([]string{}, decision.ReasonCodes...),
		PolicyVersion:   decision.PolicyVersion,
		FailClosed:      decision.FailClosed,
		VerificationURL: decision.VerificationURL,
		DossierURL:      decision.DossierURL,
		Asked:           true,
	}
	if decision.IntentHash != "" && decision.IntentHash != captured.Hash {
		r.rep.Decision.FailClosed = true
	}
	h := r.deps.Host
	if decision.FailClosed {
		status := ""
		if decision.HTTPStatus != 0 {
			status = fmt.Sprintf(" (HTTP %d)", decision.HTTPStatus)
		}
		h.Warning(fmt.Sprintf("Decionis gave no authoritative decision%s: %s.", status, strings.Join(decision.ReasonCodes, ",")))
		return
	}
	h.Notice(fmt.Sprintf("Decionis verdict: %s (decision %s, dossier %s%s)", decision.Verdict, orDash(decision.DecisionID), orDash(decision.DossierID), func() string {
		if decision.PolicyVersion == "" {
			return ""
		}
		return ", policy " + decision.PolicyVersion
	}()))
}

// publish writes every surface once: outputs, summary, comment, the record.
func (r *run) publish(ctx context.Context) {
	h := r.deps.Host
	if r.rep.Decision.DossierID != "" && r.deps.Authority != nil && r.cfg.Credentials {
		summary, err := r.deps.Authority.FetchDossier(ctx, r.cfg.TenantID, r.rep.Decision.DossierID)
		if err != nil {
			r.rep.Dossier = &report.Dossier{Fetched: false, Error: err.Error()}
		} else {
			r.rep.Dossier = &report.Dossier{Fetched: true, Algorithm: summary.Algorithm, KeyID: summary.KeyID, IssuerTier: summary.IssuerTier, Artifacts: summary.Artifacts}
			if r.rep.Decision.PolicyVersion == "" {
				r.rep.Decision.PolicyVersion = summary.PolicyVersion
			}
			h.Notice(fmt.Sprintf("Decision Dossier %s read back: %s, key %s, %d artifact(s), issuer tier %s.", summary.DossierID, orDash(summary.Algorithm), orDash(summary.KeyID), summary.Artifacts, orDash(summary.IssuerTier)))
		}
	}
	if err := h.Outputs(r.rep.Outputs()); err != nil {
		h.Warning("Decionis could not write the step outputs: " + err.Error())
	}
	if err := h.Summary(r.rep.Summary()); err != nil {
		h.Warning("Decionis could not write the run summary: " + err.Error())
	}
	if r.cfg.Comment {
		posted, err := h.Comment(ctx, r.rep.Comment(r.cfg.Attribution))
		switch {
		case err != nil:
			h.Warning("Decionis could not post the comment: " + err.Error())
		case posted:
			h.Notice("Decionis posted the verdict on the change request.")
		}
	}
	if r.cfg.ReportPath != "" {
		if err := writeReport(r.cfg.ReportPath, r.rep, r.deps.Stdout); err != nil {
			h.Warning("Decionis could not write the report: " + err.Error())
		}
	}
}

func writeReport(path string, rep report.Report, stdout io.Writer) error {
	if path == "-" {
		_, err := fmt.Fprintln(stdout, rep.JSON())
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o644)
}

// capture builds the intent from the run's facts and the configuration.
func (r *run) capture(source *policy.Source) (intent.Captured, error) {
	facts := r.deps.Host.Facts()
	context := facts.Context()
	context["govern"] = map[string]any{"version": r.deps.Version}
	if source != nil {
		context["decionis_policy"] = source.Context()
	}
	if r.cfg.Command != "" {
		context["command"] = r.cfg.Command
	}
	resource := r.cfg.Resource
	if resource == "" {
		resource = r.cfg.Command
	}
	if resource == "" {
		resource = r.cfg.ActionType
	}
	if len(resource) > 500 {
		resource = resource[:500]
	}
	actorID := r.cfg.ActorID
	if actorID == "" {
		actorID = facts.WorkflowRef
	}
	if actorID == "" {
		actorID = facts.Repository
	}
	if actorID == "" {
		actorID = "workflow"
	}
	if len(actorID) > 200 {
		actorID = actorID[:200]
	}
	actorType := r.cfg.ActorType
	if actorType == "" {
		actorType = "WORKFLOW"
	}
	environment := r.cfg.Environment
	if environment == "" {
		environment = facts.Environment
	}
	target := intent.DownstreamTarget{System: facts.System, Operation: r.cfg.ActionType, Environment: environment}
	if facts.RunURL != "" {
		target.Endpoint = facts.RunURL
	} else if facts.ServerURL != "" && facts.Repository != "" {
		target.Endpoint = strings.TrimRight(facts.ServerURL, "/") + "/" + facts.Repository
	}
	key := strings.Join(compact(facts.System, facts.RunID, facts.RunAttempt, facts.Job), ":")
	if key == "" || key == facts.System {
		key = facts.System + ":" + report.Now(r.deps.Now())
	}
	suffix, err := shortID()
	if err != nil {
		return intent.Captured{}, err
	}
	key += ":" + suffix
	if len(key) > 180 {
		key = key[len(key)-180:]
	}
	return intent.Capture(
		intent.Proposal{ActionType: r.cfg.ActionType, Resource: resource, Parameters: r.cfg.Parameters},
		intent.Trusted{
			TenantID:         r.cfg.TenantID,
			Actor:            intent.Actor{ID: actorID, Type: actorType, Runtime: "govern/" + r.deps.Version},
			DownstreamTarget: target,
			Context:          context,
			IdempotencyKey:   key,
			TTL:              r.cfg.IntentTTL,
			Now:              r.deps.Now,
		},
	)
}

func shortID() (string, error) {
	var b [6]byte
	if _, err := io.ReadFull(randReader, b[:]); err != nil {
		return "", fmt.Errorf("RANDOMNESS_UNAVAILABLE: %w", err)
	}
	return fmt.Sprintf("%x", b), nil
}

func compact(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func verb(decision authority.Decision) string {
	if decision.FailClosed {
		return "REFUSED"
	}
	switch decision.Verdict {
	case authority.Escalate:
		return "HELD"
	case authority.Block:
		return "BLOCKED"
	}
	return "did not authorize"
}

func dossierNote(decision authority.Decision) string {
	if decision.DossierID == "" {
		return ""
	}
	return " Dossier: " + decision.DossierID
}

func orDash(value string) string {
	if value == "" {
		return "—"
	}
	return value
}

func firstToken(message string) string {
	if i := strings.Index(message, ":"); i > 0 {
		return message[:i]
	}
	return message
}
