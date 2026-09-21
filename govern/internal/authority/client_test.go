package authority

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/decionis/agent-safe-pipeline/govern/v2/internal/authority/authoritytest"
	"github.com/decionis/agent-safe-pipeline/govern/v2/internal/intent"
)

func capture(t *testing.T, amountMinor int) intent.Captured {
	t.Helper()
	captured, err := intent.Capture(
		intent.Proposal{ActionType: "production-deploy", Resource: "./deploy.sh", Parameters: map[string]any{"amountMinor": json.Number(itoa(amountMinor))}},
		intent.Trusted{
			TenantID:         authoritytest.TenantID,
			Actor:            intent.Actor{ID: "decionis/example", Type: "WORKFLOW", Runtime: "govern/test"},
			DownstreamTarget: intent.DownstreamTarget{System: "github_actions", Operation: "production-deploy"},
			IdempotencyKey:   "run-1",
			TTL:              2 * time.Minute,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return captured
}

func itoa(n int) string { return strconv.Itoa(n) }

func client(t *testing.T, double *authoritytest.Double, options ...func(*Options)) *Client {
	t.Helper()
	opts := Options{BaseURL: double.URL(), APIKey: func() string { return authoritytest.APIKey }, AllowInsecureLoopback: true, UserAgent: "govern/test (example=govern@test; surface=test)", Timeout: 5 * time.Second}
	for _, apply := range options {
		apply(&opts)
	}
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBaseURLRules(t *testing.T) {
	for _, bad := range []string{"http://api.decionis.example", "https://user:pw@api.decionis.example", "https://api.decionis.example/?x=1", "https://api.decionis.example/#f", "not a url"} {
		if _, err := NormalizeBaseURL(bad, false); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if got, err := NormalizeBaseURL("https://api.decionis.example/v1/", false); err != nil || got != "https://api.decionis.example/v1" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := NormalizeBaseURL("http://127.0.0.1:8080", false); err == nil {
		t.Fatal("loopback over http accepted without the allowance")
	}
	if _, err := NormalizeBaseURL("http://127.0.0.1:8080", true); err != nil {
		t.Fatal(err)
	}
}

func TestShadowRecordsWithoutAGrant(t *testing.T) {
	double := authoritytest.New()
	defer double.Close()
	double.Verification = true
	c := client(t, double)
	captured := capture(t, 100)
	decision := c.EnforceAndBind(context.Background(), captured, Shadow, nil)
	if decision.Verdict != Allow || decision.FailClosed || decision.Grant != nil || decision.Executable() {
		t.Fatalf("shadow decision %+v", decision)
	}
	if decision.DecisionID != "synthetic-decision-1" || decision.DossierID != "synthetic-dossier-1" || decision.PolicyVersion != "synthetic-policy-v1" {
		t.Fatalf("decision %+v", decision)
	}
	if !strings.HasPrefix(decision.VerificationURL, double.URL()+"/verify/") {
		t.Fatalf("verification %q", decision.VerificationURL)
	}
	last := double.Requests[len(double.Requests)-1]
	if last.Headers.Get("idempotency-key") != captured.Binding.IntentID || last.Headers.Get("user-agent") != "govern/test (example=govern@test; surface=test)" || last.Body["mode"] != "SHADOW" {
		t.Fatalf("request %+v", last)
	}
	summary, err := c.FetchDossier(context.Background(), authoritytest.TenantID, decision.DossierID)
	if err != nil || summary.Outcome != "ALLOW" || summary.Algorithm != "Ed25519" || summary.KeyID != "synthetic-key-1" || summary.IssuerTier != "synthetic_loopback" {
		t.Fatalf("dossier %+v %v", summary, err)
	}
}

func TestEnforcementAllowClaimsAndFinalizes(t *testing.T) {
	double := authoritytest.New()
	defer double.Close()
	c := client(t, double)
	captured := capture(t, 100)
	decision := c.EnforceAndBind(context.Background(), captured, Enforcement, nil)
	if !decision.Executable() || decision.Grant.token == "" || decision.Grant.ExpiresAt.IsZero() {
		t.Fatalf("decision %+v", decision)
	}
	claim, code := c.ClaimGrant(context.Background(), captured, decision)
	if claim == nil {
		t.Fatalf("claim refused: %s", code)
	}
	if claim.DecisionID != decision.DecisionID || claim.DossierID != decision.DossierID || claim.IntentHash != captured.Hash || claim.Attestation == "" || claim.LeaseExpiresAt.IsZero() || claim.PayloadDigest == "" {
		t.Fatalf("claim %+v", claim)
	}
	// One grant, one claim.
	if again, code := c.ClaimGrant(context.Background(), captured, decision); again != nil || code != "NONCE_REPLAY_DETECTED" {
		t.Fatalf("second claim %+v %s", again, code)
	}
	if got := c.Finalize(context.Background(), claim, Committed, Evidence{"exit_code": 0}); got != Recorded {
		t.Fatalf("finalize %s", got)
	}
	// The finalization is once as well; the client forgets the claim material.
	if got := c.Finalize(context.Background(), claim, Committed, nil); got != Pending {
		t.Fatalf("second finalize %s", got)
	}
	if outcomes := double.Finalizations(); len(outcomes) != 1 {
		t.Fatalf("finalizations %+v", outcomes)
	}
}

func TestEscalateAndBlockCarryNoGrant(t *testing.T) {
	double := authoritytest.New()
	defer double.Close()
	c := client(t, double)
	escalate := c.EnforceAndBind(context.Background(), capture(t, 50_000), Enforcement, nil)
	if escalate.Verdict != Escalate || escalate.Executable() || escalate.FailClosed || escalate.ReasonCodes[0] != "HUMAN_APPROVAL_REQUIRED" {
		t.Fatalf("escalate %+v", escalate)
	}
	block := c.EnforceAndBind(context.Background(), capture(t, 500_000), Enforcement, nil)
	if block.Verdict != Block || block.Executable() || block.FailClosed || block.ReasonCodes[0] != "POLICY_HARD_LIMIT_EXCEEDED" {
		t.Fatalf("block %+v", block)
	}
	if _, code := c.ClaimGrant(context.Background(), capture(t, 100), block); code != "AUTHORIZATION_INVALID" {
		t.Fatalf("claim of a block: %s", code)
	}
}

func TestManagedEscalationWaitsForTheGrant(t *testing.T) {
	double := authoritytest.New()
	defer double.Close()
	double.Lifecycle = []string{"AWAITING_APPROVER", "PRESENCE_VERIFIED", "GRANT_READY"}
	c := client(t, double, func(o *Options) { o.Sleep = func(context.Context, time.Duration) error { return nil } })
	captured := capture(t, 50_000)
	decision := c.EnforceAndBind(context.Background(), captured, Enforcement, &ManagedRequest{ApproverRoleID: "RELEASE_MANAGER"})
	if decision.Verdict != Escalate || decision.Managed == nil || decision.Managed.Status != "PENDING_PRESENCE" {
		t.Fatalf("opening %+v", decision)
	}
	var seen []string
	final := c.WaitForManaged(context.Background(), captured, decision.Managed, WaitOptions{OnStatus: func(status string, _ []string) { seen = append(seen, status) }})
	if !final.Executable() {
		t.Fatalf("final %+v", final)
	}
	if strings.Join(seen, ",") != "AWAITING_APPROVER,PRESENCE_VERIFIED,GRANT_READY" {
		t.Fatalf("statuses %v", seen)
	}
	claim, code := c.ClaimGrant(context.Background(), captured, final)
	if claim == nil {
		t.Fatalf("claim after escalation: %s", code)
	}
	if c.Finalize(context.Background(), claim, Failed, nil) != Recorded {
		t.Fatal("finalize")
	}
}

func TestManagedEscalationRejectedIsABlock(t *testing.T) {
	double := authoritytest.New()
	defer double.Close()
	double.Lifecycle = []string{"AWAITING_APPROVER", "REJECTED"}
	c := client(t, double, func(o *Options) { o.Sleep = func(context.Context, time.Duration) error { return nil } })
	captured := capture(t, 50_000)
	decision := c.EnforceAndBind(context.Background(), captured, Enforcement, &ManagedRequest{ApproverPrincipalID: "synthetic-approver"})
	final := c.WaitForManaged(context.Background(), captured, decision.Managed, WaitOptions{})
	if final.Verdict != Block || final.Executable() || final.ReasonCodes[0] != "PRESENCE_REJECTED" {
		t.Fatalf("final %+v", final)
	}
	if shadow := c.EnforceAndBind(context.Background(), captured, Shadow, &ManagedRequest{}); shadow.ReasonCodes[0] != "MANAGED_ESCALATION_SHADOW_FORBIDDEN" {
		t.Fatalf("shadow with escalation %+v", shadow)
	}
}

func TestManagedEscalationRunsOutOfTime(t *testing.T) {
	double := authoritytest.New()
	defer double.Close()
	double.Lifecycle = []string{"AWAITING_APPROVER"}
	now := time.Now()
	c := client(t, double, func(o *Options) {
		o.Sleep = func(context.Context, time.Duration) error { now = now.Add(time.Minute); return nil }
		o.Now = func() time.Time { return now }
	})
	captured := capture(t, 50_000)
	decision := c.EnforceAndBind(context.Background(), captured, Enforcement, &ManagedRequest{})
	final := c.WaitForManaged(context.Background(), captured, decision.Managed, WaitOptions{})
	if final.Verdict != Block || !final.FailClosed || final.ReasonCodes[0] != "MANAGED_ESCALATION_EXPIRED" {
		t.Fatalf("final %+v", final)
	}
}

func TestFailuresAreFailClosed(t *testing.T) {
	double := authoritytest.New()
	defer double.Close()
	c := client(t, double)
	captured := capture(t, 100)
	double.Fail = 503
	if d := c.EnforceAndBind(context.Background(), captured, Enforcement, nil); d.Verdict != Block || !d.FailClosed || d.ReasonCodes[0] != "AUTHORITY_REQUEST_FAILED" || d.HTTPStatus != 503 {
		t.Fatalf("503 → %+v", d)
	}
	double.Close()
	if d := c.EnforceAndBind(context.Background(), captured, Enforcement, nil); !d.FailClosed || d.ReasonCodes[0] != "AUTHORITY_UNAVAILABLE" {
		t.Fatalf("unreachable → %+v", d)
	}
	// An expired intent is refused before the authority is asked.
	expired := captured
	expired.Binding.ExpiresAt = intent.Timestamp(time.Now().Add(-time.Second))
	if d := c.EnforceAndBind(context.Background(), expired, Enforcement, nil); d.ReasonCodes[0] != "INTENT_EXPIRED" {
		t.Fatalf("expired → %+v", d)
	}
}

// A response outside the contract, or one about another intent, never executes.
func TestResponsesOutsideTheContractFailClosed(t *testing.T) {
	captured := capture(t, 100)
	base := func() map[string]any {
		return map[string]any{
			"decision_id": "d1", "chain_id": nil, "status": "ALLOW", "should_execute": true, "reason_codes": []string{},
			"action_hash": captured.Hash, "mode": "ENFORCEMENT", "execution_token": "grant", "execution_token_expires_at": intent.Timestamp(time.Now().Add(30 * time.Second)),
			"dossier_id": "dossier", "dossier_url": "/v1/protocol/dossiers/dossier", "authority_classification": "AUTHORITATIVE", "execution_eligible": true,
			"execution_binding_digest": captured.Hash, "execution_token_jti": "jti", "execution_token_key_id": "kid",
		}
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
		code   string
	}{
		{"unknown field", func(m map[string]any) { m["surprise"] = true }, "AUTHORITY_RESPONSE_INVALID"},
		{"another intent", func(m map[string]any) {
			m["action_hash"] = "sha256:" + strings.Repeat("0", 64)
			m["execution_binding_digest"] = m["action_hash"]
		}, "AUTHORITY_BINDING_MISMATCH"},
		{"shadow answer to enforcement", func(m map[string]any) { m["mode"] = "SHADOW" }, "AUTHORITY_MODE_MISMATCH"},
		{"allow without a token", func(m map[string]any) { m["execution_token"] = nil }, "AUTHORITY_GRANT_MISSING"},
		{"allow not eligible", func(m map[string]any) { m["execution_eligible"] = false }, "AUTHORITY_GRANT_MISSING"},
		{"observational allow", func(m map[string]any) { m["authority_classification"] = "OBSERVATIONAL" }, "AUTHORITY_GRANT_MISSING"},
		{"grant outliving the intent", func(m map[string]any) { m["execution_token_expires_at"] = intent.Timestamp(time.Now().Add(time.Hour)) }, "AUTHORITY_GRANT_MISSING"},
		{"unknown status", func(m map[string]any) { m["status"] = "MAYBE" }, "AUTHORITY_RESPONSE_INVALID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := base()
			tc.mutate(body)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("content-type", "application/json")
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer server.Close()
			c, err := New(Options{BaseURL: server.URL, APIKey: func() string { return "k" }, AllowInsecureLoopback: true})
			if err != nil {
				t.Fatal(err)
			}
			d := c.EnforceAndBind(context.Background(), captured, Enforcement, nil)
			if !d.FailClosed || d.Executable() || d.ReasonCodes[0] != tc.code {
				t.Fatalf("%+v", d)
			}
		})
	}
}

func TestOversizedResponseFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ALLOW","pad":"` + strings.Repeat("x", maxResponseBytes) + `"}`))
	}))
	defer server.Close()
	c, _ := New(Options{BaseURL: server.URL, APIKey: func() string { return "k" }, AllowInsecureLoopback: true})
	d := c.EnforceAndBind(context.Background(), capture(t, 1), Shadow, nil)
	if d.ReasonCodes[0] != "AUTHORITY_RESPONSE_TOO_LARGE" {
		t.Fatalf("%+v", d)
	}
}
