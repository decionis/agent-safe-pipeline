package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/decionis/agent-safe-pipeline/govern/v2/internal/host"
)

func sample() Report {
	exit := 0
	return Report{
		Version: Version, At: "2026-09-21T00:00:00.000Z", Runtime: "govern/2.0.0", Runner: "github_actions", Mode: "ENFORCEMENT", Action: "production-deploy",
		Intent:   &Intent{ID: "i", Hash: "sha256:" + strings.Repeat("a", 64), ActionType: "production-deploy", Resource: "./deploy.sh"},
		Decision: Decision{Verdict: "ALLOW", DecisionID: "d", DossierID: "s", ReasonCodes: []string{"POLICY_AUTONOMOUS_LIMIT"}, PolicyVersion: "p1", DossierURL: "/v1/protocol/dossiers/s", Asked: true},
		Policy:   &Policy{Path: "DECIONIS_POLICY.md", SHA256: strings.Repeat("b", 64), Bytes: 9},
		Command:  &Command{Line: "./deploy.sh", Executed: true, ExitCode: &exit, Outcome: "COMMITTED", Finalization: "RECORDED", Claimed: true},
	}
}

func TestOutputsCoverEveryValue(t *testing.T) {
	outputs := sample().Outputs()
	seen := map[string]string{}
	for _, o := range outputs {
		if !host.ValidOutputName(o.Name) {
			t.Fatalf("output name %q", o.Name)
		}
		seen[o.Name] = o.Value
	}
	for name, want := range map[string]string{"decision": "ALLOW", "decision-id": "d", "dossier-id": "s", "executed": "true", "exit-code": "0", "outcome": "COMMITTED", "finalization": "RECORDED", "policy-sha256": strings.Repeat("b", 64), "claimed": "true", "fail-closed": "false", "mode": "ENFORCEMENT"} {
		if seen[name] != want {
			t.Fatalf("%s = %q, want %q", name, seen[name], want)
		}
	}
	if !strings.HasPrefix(seen["badge-markdown"], "[![Governed by Decionis](") || !strings.Contains(seen["badge-markdown"], ActionURL) {
		t.Fatalf("%q", seen["badge-markdown"])
	}
}

func TestSummaryAndCommentSayTheSameThing(t *testing.T) {
	r := sample()
	summary, comment := r.Summary(), r.Comment(true)
	for _, text := range []string{summary, comment} {
		for _, want := range []string{"Allowed", "`ALLOW`", "`production-deploy`", "`p1`", "`d`", "`s`", "ran, exit 0, committed (finalization recorded)", "Enforcing"} {
			if !strings.Contains(text, want) {
				t.Fatalf("missing %q in %q", want, text)
			}
		}
	}
	if !strings.HasPrefix(comment, host.Marker) || !strings.Contains(comment, "Governed by") {
		t.Fatalf("%q", comment)
	}
	if bare := r.Comment(false); strings.Contains(bare, "Governed by <a") {
		t.Fatal("attribution was not dropped")
	}
	r.Decision.VerificationURL = "https://decionis.example/verify/s?sig=x"
	if !strings.Contains(r.Summary(), "[🔎 Verify this decision →](https://decionis.example/verify/s?sig=x)") {
		t.Fatal("the public page must be the proof link when the authority gave one")
	}
	if r.ProofLink() != r.Decision.VerificationURL {
		t.Fatal("badge link")
	}
	refused := Report{Mode: "ENFORCEMENT", Decision: Decision{Verdict: "BLOCK", FailClosed: true, ReasonCodes: []string{"AUTHORITY_UNAVAILABLE"}}}
	if !strings.Contains(refused.Summary(), "Refused") || !strings.Contains(refused.Summary(), "`AUTHORITY_UNAVAILABLE`") {
		t.Fatalf("%q", refused.Summary())
	}
	shadow := Report{Mode: "SHADOW", Decision: Decision{Verdict: "BLOCK", ReasonCodes: []string{}}}
	if !strings.Contains(shadow.Summary(), "Shadow") || !strings.Contains(shadow.Comment(true), "never fails a build in shadow") {
		t.Fatal(shadow.Summary())
	}
}

func TestJSONRoundTrips(t *testing.T) {
	var back Report
	if err := json.Unmarshal([]byte(sample().JSON()), &back); err != nil || back.Version != Version || back.Command == nil || *back.Command.ExitCode != 0 {
		t.Fatalf("%v %+v", err, back)
	}
}
