// Package report is what one governed run says about itself, once, in every
// form a runner shows: the outputs a later step reads, the run summary, the
// change-request comment, the badge, and the JSON record. The same facts in
// each; nothing here is decision input.
package report

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/decionis/agent-safe-pipeline/govern/v2/internal/host"
)

// Version names the record's shape.
const Version = "agent-safe.govern-report/1"

// ActionURL is where the badge and the comment send a reader.
const ActionURL = "https://github.com/decionis/agent-safe-pipeline/tree/master/govern"

const brandURL = "https://decionis.com"

// Intent is the intent the run captured.
type Intent struct {
	ID         string `json:"id"`
	Hash       string `json:"hash"`
	ActionType string `json:"action_type"`
	Resource   string `json:"resource"`
	CapturedAt string `json:"captured_at"`
	ExpiresAt  string `json:"expires_at"`
}

// Decision is what the authority said, or what the gate refused on its behalf.
type Decision struct {
	Verdict         string   `json:"verdict"`
	DecisionID      string   `json:"decision_id,omitempty"`
	DossierID       string   `json:"dossier_id,omitempty"`
	ReasonCodes     []string `json:"reason_codes"`
	PolicyVersion   string   `json:"policy_version,omitempty"`
	FailClosed      bool     `json:"fail_closed"`
	VerificationURL string   `json:"verification_url,omitempty"`
	DossierURL      string   `json:"dossier_url,omitempty"`
	// Asked is false when the authority was never asked (shadow without credentials).
	Asked bool `json:"asked"`
}

// Escalation is the managed escalation the run waited on, when it did.
type Escalation struct {
	EscalationID string `json:"escalation_id"`
	FinalStatus  string `json:"final_status"`
}

// Policy is the repository policy file the intent carried.
type Policy struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
}

// Command is what happened to the gated command.
type Command struct {
	Line         string `json:"line"`
	Executed     bool   `json:"executed"`
	ExitCode     *int   `json:"exit_code,omitempty"`
	DurationMs   int64  `json:"duration_ms,omitempty"`
	Signal       string `json:"signal,omitempty"`
	Outcome      string `json:"outcome,omitempty"`
	Finalization string `json:"finalization,omitempty"`
	// Claimed is whether a grant was consumed for the run.
	Claimed bool `json:"claimed"`
}

// Dossier is what the signed record said when it was read back.
type Dossier struct {
	Fetched    bool   `json:"fetched"`
	Error      string `json:"error,omitempty"`
	Algorithm  string `json:"algorithm,omitempty"`
	KeyID      string `json:"key_id,omitempty"`
	IssuerTier string `json:"issuer_tier,omitempty"`
	Artifacts  int    `json:"artifacts"`
}

// Report is the record of one run.
type Report struct {
	Version    string      `json:"version"`
	At         string      `json:"at"`
	Runtime    string      `json:"runtime"`
	Runner     string      `json:"runner"`
	Mode       string      `json:"mode"`
	Action     string      `json:"action"`
	Intent     *Intent     `json:"intent,omitempty"`
	Decision   Decision    `json:"decision"`
	Escalation *Escalation `json:"escalation,omitempty"`
	Policy     *Policy     `json:"policy,omitempty"`
	Command    *Command    `json:"command,omitempty"`
	Dossier    *Dossier    `json:"dossier,omitempty"`
	Notes      []string    `json:"notes,omitempty"`
	Exit       int         `json:"exit"`
}

// JSON is the record on one line.
func (r Report) JSON() string {
	encoded, err := json.Marshal(r)
	if err != nil {
		return `{"version":"` + Version + `","error":"REPORT_NOT_SERIALIZABLE"}`
	}
	return string(encoded)
}

// Outputs are the values a later step reads; every one is present, empty when unknown.
func (r Report) Outputs() []host.Output {
	executed, exit, outcome, finalization, claimed := "", "", "", "", "false"
	if r.Command != nil {
		executed = fmt.Sprint(r.Command.Executed)
		if r.Command.ExitCode != nil {
			exit = fmt.Sprint(*r.Command.ExitCode)
		}
		outcome, finalization = r.Command.Outcome, r.Command.Finalization
		claimed = fmt.Sprint(r.Command.Claimed)
	}
	intentID, intentHash := "", ""
	if r.Intent != nil {
		intentID, intentHash = r.Intent.ID, r.Intent.Hash
	}
	policySHA, policyPath := "", ""
	if r.Policy != nil {
		policySHA, policyPath = r.Policy.SHA256, r.Policy.Path
	}
	return []host.Output{
		{Name: "decision", Value: r.Decision.Verdict},
		{Name: "decision-id", Value: r.Decision.DecisionID},
		{Name: "dossier-id", Value: r.Decision.DossierID},
		{Name: "dossier-url", Value: r.Decision.DossierURL},
		{Name: "verify-url", Value: r.Decision.VerificationURL},
		{Name: "intent-id", Value: intentID},
		{Name: "intent-hash", Value: intentHash},
		{Name: "reason-codes", Value: strings.Join(r.Decision.ReasonCodes, ",")},
		{Name: "policy-version", Value: r.Decision.PolicyVersion},
		{Name: "policy-sha256", Value: policySHA},
		{Name: "policy-path", Value: policyPath},
		{Name: "mode", Value: r.Mode},
		{Name: "fail-closed", Value: fmt.Sprint(r.Decision.FailClosed)},
		{Name: "executed", Value: executed},
		{Name: "claimed", Value: claimed},
		{Name: "exit-code", Value: exit},
		{Name: "outcome", Value: outcome},
		{Name: "finalization", Value: finalization},
		{Name: "badge-markdown", Value: BadgeMarkdown(r.ProofLink())},
	}
}

// ProofLink is where a reader verifies the decision: the public page when the
// authority attached one, otherwise the gate's own page.
func (r Report) ProofLink() string {
	if r.Decision.VerificationURL != "" {
		return r.Decision.VerificationURL
	}
	return ActionURL
}

// BadgeMarkdown is the "Governed by Decionis" badge, linking where it is told.
func BadgeMarkdown(link string) string {
	image := "https://img.shields.io/badge/Governed%20by-Decionis-6D28D9?logo=shield&logoColor=white"
	return "[![Governed by Decionis](" + image + ")](" + link + ")"
}

type theme struct {
	emoji, label, color string
}

func themeOf(verdict string, failClosed bool) theme {
	switch {
	case failClosed:
		return theme{"🛑", "Refused", "d1242f"}
	case verdict == "ALLOW":
		return theme{"✅", "Allowed", "2ea043"}
	case verdict == "BLOCK":
		return theme{"🛑", "Blocked", "d1242f"}
	case verdict == "ESCALATE":
		return theme{"⚠️", "Escalated", "bf8700"}
	}
	return theme{"🛡️", "Not decided", "6D28D9"}
}

// VerdictBadgeURL is the shield that heads the summary and the comment.
func VerdictBadgeURL(verdict string, failClosed bool) string {
	t := themeOf(verdict, failClosed)
	return "https://img.shields.io/badge/Decionis-" + url.PathEscape(t.label) + "-" + t.color + "?style=for-the-badge&logo=shield&logoColor=white"
}

func code(value string) string {
	if value == "" {
		return "—"
	}
	return "`" + strings.ReplaceAll(value, "`", "'") + "`"
}

func (r Report) rows() []string {
	rows := []string{
		fmt.Sprintf("| **Verdict** | %s |", code(r.Decision.Verdict)),
		fmt.Sprintf("| **Mode** | %s |", code(strings.ToLower(r.Mode))),
	}
	if len(r.Decision.ReasonCodes) > 0 {
		rows = append(rows, fmt.Sprintf("| **Reasons** | %s |", code(strings.Join(r.Decision.ReasonCodes, ", "))))
	}
	if r.Decision.PolicyVersion != "" {
		rows = append(rows, fmt.Sprintf("| **Policy** | %s |", code(r.Decision.PolicyVersion)))
	}
	if r.Policy != nil {
		rows = append(rows, fmt.Sprintf("| **Policy file** | %s at `sha256:%s` |", code(r.Policy.Path), r.Policy.SHA256))
	}
	if r.Intent != nil {
		rows = append(rows, fmt.Sprintf("| **Intent** | %s |", code(r.Intent.Hash)))
	}
	if r.Decision.DecisionID != "" {
		rows = append(rows, fmt.Sprintf("| **Decision** | %s |", code(r.Decision.DecisionID)))
	}
	if r.Decision.DossierID != "" {
		rows = append(rows, fmt.Sprintf("| **Dossier** | %s |", code(r.Decision.DossierID)))
	}
	if r.Command != nil {
		state := "not run"
		if r.Command.Executed {
			state = "ran"
			if r.Command.ExitCode != nil {
				state += fmt.Sprintf(", exit %d", *r.Command.ExitCode)
			}
			if r.Command.Outcome != "" {
				state += fmt.Sprintf(", %s", strings.ToLower(r.Command.Outcome))
				if r.Command.Finalization != "" {
					state += fmt.Sprintf(" (finalization %s)", strings.ToLower(r.Command.Finalization))
				}
			}
		}
		rows = append(rows, fmt.Sprintf("| **Command** | %s |", state))
	}
	return rows
}

func (r Report) proofLine() string {
	switch {
	case r.Decision.VerificationURL != "":
		return fmt.Sprintf("**[🔎 Verify this decision →](%s)** — the signed Decision Dossier.", r.Decision.VerificationURL)
	case r.Decision.DossierID != "":
		return fmt.Sprintf("The signed Decision Dossier is `%s`, readable with the workspace's key at `%s`.", r.Decision.DossierID, r.Decision.DossierURL)
	}
	return ""
}

func (r Report) modeNote() string {
	if r.Mode == "SHADOW" {
		return "> 🟣 **Shadow** — recorded only. This step never fails a build in shadow."
	}
	return "> Enforcing — the command runs only on an `ALLOW` with a claimed grant."
}

// Summary is the run summary in Markdown.
func (r Report) Summary() string {
	t := themeOf(r.Decision.Verdict, r.Decision.FailClosed)
	title := "## " + t.emoji + " Govern"
	if r.Action != "" {
		title += " · `" + r.Action + "`"
	}
	title += ": " + t.label
	lines := []string{
		title,
		"",
		fmt.Sprintf("<img alt=\"Decionis verdict: %s\" src=\"%s\" />", t.label, VerdictBadgeURL(r.Decision.Verdict, r.Decision.FailClosed)),
		"",
		"| | |",
		"| --- | --- |",
	}
	lines = append(lines, r.rows()...)
	lines = append(lines, "")
	if proof := r.proofLine(); proof != "" {
		lines = append(lines, proof, "")
	}
	lines = append(lines, r.modeNote())
	for _, note := range r.Notes {
		lines = append(lines, "", "> "+note)
	}
	lines = append(lines,
		"",
		"<details><summary>📌 Add the “Governed by Decionis” badge to your README</summary>",
		"",
		"```markdown",
		BadgeMarkdown(ActionURL),
		"```",
		"",
		"</details>",
	)
	return strings.Join(lines, "\n")
}

// Comment is the change-request comment, carrying the marker that finds it
// again on the next run so a thread holds one comment, not one per push.
func (r Report) Comment(attribution bool) string {
	t := themeOf(r.Decision.Verdict, r.Decision.FailClosed)
	heading := "### " + t.emoji + " Governed step — " + t.label
	if r.Action != "" {
		heading = "### " + t.emoji + " Govern · `" + r.Action + "` — " + t.label
	}
	lines := []string{
		host.Marker,
		fmt.Sprintf("<img alt=\"Decionis verdict: %s\" src=\"%s\" />", t.label, VerdictBadgeURL(r.Decision.Verdict, r.Decision.FailClosed)),
		"",
		heading,
		"",
		"| | |",
		"| --- | --- |",
	}
	lines = append(lines, r.rows()...)
	lines = append(lines, "")
	if proof := r.proofLine(); proof != "" {
		lines = append(lines, proof, "")
	}
	lines = append(lines, r.modeNote())
	if attribution {
		lines = append(lines, "", "---",
			fmt.Sprintf("<sub>🛡️ Governed by <a href=\"%s/?source=govern_comment\">Decionis</a> — one verdict before a deploy, a migration or an infrastructure change runs, with a signed record of it. <a href=\"%s\">govern</a></sub>", brandURL, ActionURL))
	}
	return strings.Join(lines, "\n")
}

// Now is the record's own timestamp.
func Now(at time.Time) string { return at.UTC().Format("2006-01-02T15:04:05.000Z") }
