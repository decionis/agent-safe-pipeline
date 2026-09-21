// Package authority is the executor's half of the Decionis execution contract:
// enforce-and-bind for a decision on an exact intent, the managed escalation
// it may open, the claim that consumes the grant immediately before the
// effect, and the finalization that records what happened. Every refusal is a
// fail-closed decision with a reason code and never an authorization; nothing
// here interprets a response beyond the contract's positive assertions.
package authority

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/decionis/agent-safe-pipeline/govern/internal/intent"
)

// Mode is how the authority is asked: to record only, or to decide and grant.
type Mode string

const (
	Shadow      Mode = "SHADOW"
	Enforcement Mode = "ENFORCEMENT"
)

// Verdict is the contract's decision vocabulary; REVIEW_REQUIRED reads as
// ESCALATE and ERROR as BLOCK, as the reference gate reads them.
type Verdict string

const (
	Allow    Verdict = "ALLOW"
	Escalate Verdict = "ESCALATE"
	Block    Verdict = "BLOCK"
)

// Outcome is what the executor tells the authority about the attempt.
type Outcome string

const (
	Committed     Outcome = "COMMITTED"
	Failed        Outcome = "FAILED"
	Indeterminate Outcome = "INDETERMINATE"
)

// Finalization is whether the authority recorded the outcome.
type Finalization string

const (
	Recorded Finalization = "RECORDED"
	Pending  Finalization = "PENDING"
)

const (
	maxResponseBytes  = 100 * 1024
	maxDossierBytes   = 2 * 1024 * 1024
	defaultTimeout    = 20 * time.Second
	maxTimeout        = 60 * time.Second
	pollInitialDelay  = 500 * time.Millisecond
	pollMaxDelay      = 5 * time.Second
	maxPollAttempts   = 1_000
	jcsProfile        = "RFC8785/JCS"
	dossierIDPattern  = `^[\w-]{1,200}$`
	claimTokenPattern = `^[\w-]{43,128}$`
)

var (
	dossierID  = regexp.MustCompile(dossierIDPattern)
	claimToken = regexp.MustCompile(claimTokenPattern)
	compactJWS = regexp.MustCompile(`^[\w-]+\.[\w-]+\.[\w-]+$`)
)

// Options configure a client. The base URL must be https, or http on the
// loopback interface when AllowInsecureLoopback says so (tests and doubles).
type Options struct {
	BaseURL string
	// APIKey is read at each request, so a rotated credential is the next request's.
	APIKey                func() string
	Timeout               time.Duration
	UserAgent             string
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
	Now                   func() time.Time
	Sleep                 func(context.Context, time.Duration) error
}

// Client speaks the contract to one authority.
type Client struct {
	baseURL   string
	apiKey    func() string
	timeout   time.Duration
	userAgent string
	http      *http.Client
	now       func() time.Time
	sleep     func(context.Context, time.Duration) error
}

// New validates the options and returns a client.
func New(options Options) (*Client, error) {
	base, err := NormalizeBaseURL(options.BaseURL, options.AllowInsecureLoopback)
	if err != nil {
		return nil, err
	}
	if options.APIKey == nil {
		return nil, errors.New("DECIONIS_API_KEY_MISSING")
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout > maxTimeout {
		timeout = maxTimeout
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{
			// A redirect could carry the credential elsewhere; the contract has none.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	sleep := options.Sleep
	if sleep == nil {
		sleep = func(ctx context.Context, d time.Duration) error {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	return &Client{baseURL: base, apiKey: options.APIKey, timeout: timeout, userAgent: options.UserAgent, http: client, now: now, sleep: sleep}, nil
}

// NormalizeBaseURL applies the reference client's rules: https only, unless a
// loopback address and the caller allowed it; no credentials, query or
// fragment; no trailing slash.
func NormalizeBaseURL(value string, allowInsecureLoopback bool) (string, error) {
	trimmed := strings.TrimSpace(value)
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		return "", errors.New("DECIONIS_URL_INVALID")
	}
	if parsed.User != nil {
		return "", errors.New("DECIONIS_URL_MUST_NOT_CONTAIN_CREDENTIALS")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("DECIONIS_URL_MUST_NOT_CONTAIN_QUERY_OR_FRAGMENT")
	}
	host := parsed.Hostname()
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		loopback = true
	}
	if parsed.Scheme != "https" && !(allowInsecureLoopback && loopback && parsed.Scheme == "http") {
		return "", errors.New("DECIONIS_URL_MUST_USE_HTTPS")
	}
	return strings.TrimRight(trimmed, "/"), nil
}

// Grant is the single-use execution token an ALLOW in enforcement carries.
// The token is never logged, never exported and never shown to the command.
type Grant struct {
	token     string
	ExpiresAt time.Time
}

// ManagedEscalation is the locator of an escalation Decionis orchestrates.
type ManagedEscalation struct {
	EscalationID string
	IntentID     string
	Status       string
	Outcome      string
	ExpiresAt    time.Time
	ReasonCodes  []string
}

// Decision is what the authority said about one intent, or what this client
// refused on its behalf: a fail-closed decision is a BLOCK with a reason.
type Decision struct {
	Verdict     Verdict
	DecisionID  string
	DossierID   string
	IntentHash  string
	ReasonCodes []string
	// PolicyVersion is the version the dossier records; empty when unsaid.
	PolicyVersion string
	Mode          Mode
	// FailClosed is true when nothing authoritative was decided: an error
	// status, a refused response, an unreachable authority.
	FailClosed bool
	Grant      *Grant
	Managed    *ManagedEscalation
	// VerificationURL is the page a person can open without an account, when
	// the authority attached one; DossierURL is the authenticated record.
	VerificationURL string
	DossierURL      string
	// HTTPStatus is the response status when there was one, for the log.
	HTTPStatus int
}

// Executable is whether this decision carries an unexpired grant.
func (d Decision) Executable() bool {
	return d.Verdict == Allow && !d.FailClosed && d.Grant != nil
}

// ManagedRequest asks the authority to orchestrate an escalation itself.
type ManagedRequest struct {
	ApproverPrincipalID string
	ApproverRoleID      string
	Methods             []string
	Level               string
}

func (r *ManagedRequest) wire() map[string]any {
	body := map[string]any{"mode": "MANAGED"}
	approver := map[string]any{}
	if r.ApproverPrincipalID != "" {
		approver["principal_id"] = r.ApproverPrincipalID
	}
	if r.ApproverRoleID != "" {
		approver["role_id"] = r.ApproverRoleID
	}
	if len(approver) > 0 {
		body["approver"] = approver
	}
	if len(r.Methods) > 0 || r.Level != "" {
		requirements := map[string]any{}
		if len(r.Methods) > 0 {
			requirements["methods"] = r.Methods
		}
		if r.Level != "" {
			requirements["level"] = r.Level
		}
		body["verification_requirements"] = requirements
	}
	return body
}

// wireDecision mirrors ExecutionAuthorityDecision, additionalProperties false:
// an undocumented field fails closed rather than being read as semantics.
type wireDecision struct {
	DecisionID              string          `json:"decision_id"`
	ChainID                 *string         `json:"chain_id"`
	Status                  string          `json:"status"`
	ShouldExecute           bool            `json:"should_execute"`
	ReasonCodes             []string        `json:"reason_codes"`
	ActionHash              string          `json:"action_hash"`
	PolicyVersion           *string         `json:"policy_version,omitempty"`
	Mode                    *string         `json:"mode,omitempty"`
	ExecutionToken          *string         `json:"execution_token"`
	ExecutionTokenExpires   *string         `json:"execution_token_expires_at"`
	DossierID               *string         `json:"dossier_id"`
	DossierSHA256           *string         `json:"dossier_sha256,omitempty"`
	DossierURL              *string         `json:"dossier_url"`
	ApprovalRequestID       *string         `json:"approval_request_id,omitempty"`
	LedgerEntryID           *string         `json:"ledger_entry_id,omitempty"`
	AuthorityClassification *string         `json:"authority_classification,omitempty"`
	ExecutionEligible       *bool           `json:"execution_eligible,omitempty"`
	ExecutionBindingDigest  *string         `json:"execution_binding_digest,omitempty"`
	ExecutionTokenJTI       *string         `json:"execution_token_jti,omitempty"`
	ExecutionTokenKeyID     *string         `json:"execution_token_key_id,omitempty"`
	ManagedEscalation       *wireManaged    `json:"managed_escalation,omitempty"`
	Verification            json.RawMessage `json:"verification,omitempty"`
}

type wireManaged struct {
	Outcome      string   `json:"outcome"`
	EscalationID string   `json:"escalation_id"`
	IntentID     string   `json:"intent_id"`
	Status       string   `json:"status"`
	ExpiresAt    string   `json:"expires_at"`
	ReasonCodes  []string `json:"reason_codes"`
}

type wireStatus struct {
	EscalationID string        `json:"escalation_id"`
	IntentID     string        `json:"intent_id"`
	ActionHash   string        `json:"action_hash"`
	Status       string        `json:"status"`
	Outcome      string        `json:"outcome"`
	ExpiresAt    string        `json:"expires_at"`
	ReasonCodes  []string      `json:"reason_codes"`
	Decision     *wireDecision `json:"decision"`
}

var pendingStatuses = map[string]bool{
	"PENDING_PRESENCE": true, "PRESENCE_REQUESTED": true, "AWAITING_APPROVER": true,
	"PRESENCE_VERIFIED": true, "REAUTHORIZING": true,
}

func failClosed(hash string, code string, status int) Decision {
	return Decision{Verdict: Block, IntentHash: hash, ReasonCodes: []string{code}, FailClosed: true, HTTPStatus: status}
}

// EnforceAndBind asks the authority to decide on the captured intent in the
// given mode. It never returns an error: an authority that cannot be reached,
// answers outside the contract or refuses is a fail-closed BLOCK.
func (c *Client) EnforceAndBind(ctx context.Context, captured intent.Captured, mode Mode, managed *ManagedRequest) Decision {
	if mode != Shadow && mode != Enforcement {
		return failClosed(captured.Hash, "DECIONIS_GATE_MODE_INVALID", 0)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, captured.Binding.ExpiresAt)
	if err != nil || !expiresAt.After(c.now()) {
		return failClosed(captured.Hash, "INTENT_EXPIRED", 0)
	}
	if managed != nil && mode != Enforcement {
		return failClosed(captured.Hash, "MANAGED_ESCALATION_SHADOW_FORBIDDEN", 0)
	}
	body := map[string]any{}
	if err := remarshal(captured.Binding, &body); err != nil {
		return failClosed(captured.Hash, "INTENT_NOT_JSON", 0)
	}
	body["intent_hash"] = captured.Hash
	body["mode"] = string(mode)
	if managed != nil {
		body["escalation"] = managed.wire()
	}
	status, text, err := c.post(ctx, "/v1/authority/enforce-and-bind", body, map[string]string{"idempotency-key": captured.Binding.IntentID}, maxResponseBytes)
	if err != nil {
		if errors.Is(err, errResponseTooLarge) {
			return failClosed(captured.Hash, "AUTHORITY_RESPONSE_TOO_LARGE", status)
		}
		return failClosed(captured.Hash, "AUTHORITY_UNAVAILABLE", 0)
	}
	var wire wireDecision
	if status < 200 || status >= 300 {
		if strictDecode(text, &wire) != nil || wire.Status != "ERROR" || wire.ActionHash != captured.Hash {
			return failClosed(captured.Hash, "AUTHORITY_REQUEST_FAILED", status)
		}
		codes := wire.ReasonCodes
		if len(codes) == 0 {
			codes = []string{"AUTHORITY_REQUEST_FAILED"}
		}
		return Decision{Verdict: Block, DecisionID: wire.DecisionID, DossierID: deref(wire.DossierID), IntentHash: captured.Hash, ReasonCodes: codes, FailClosed: true, HTTPStatus: status}
	}
	if err := strictDecode(text, &wire); err != nil {
		return failClosed(captured.Hash, "AUTHORITY_RESPONSE_INVALID", status)
	}
	decision := c.decisionFrom(captured, mode, wire, status)
	if managed != nil && wire.ManagedEscalation != nil && decision.Managed == nil && !decision.FailClosed {
		return failClosed(captured.Hash, "MANAGED_ESCALATION_STATE_INVALID", status)
	}
	return decision
}

func (c *Client) decisionFrom(captured intent.Captured, mode Mode, wire wireDecision, status int) Decision {
	if wire.ActionHash != captured.Hash {
		return failClosed(captured.Hash, "AUTHORITY_BINDING_MISMATCH", status)
	}
	if wire.Mode != nil && *wire.Mode != string(mode) {
		return failClosed(captured.Hash, "AUTHORITY_MODE_MISMATCH", status)
	}
	verdict := Block
	switch wire.Status {
	case "ALLOW":
		verdict = Allow
	case "ESCALATE", "REVIEW_REQUIRED":
		verdict = Escalate
	case "BLOCK", "ERROR":
		verdict = Block
	default:
		return failClosed(captured.Hash, "AUTHORITY_RESPONSE_INVALID", status)
	}
	decision := Decision{
		Verdict:       verdict,
		DecisionID:    wire.DecisionID,
		DossierID:     deref(wire.DossierID),
		IntentHash:    wire.ActionHash,
		ReasonCodes:   append([]string{}, wire.ReasonCodes...),
		PolicyVersion: deref(wire.PolicyVersion),
		Mode:          mode,
		FailClosed:    wire.Status == "ERROR",
		DossierURL:    deref(wire.DossierURL),
		HTTPStatus:    status,
	}
	if len(wire.Verification) > 0 && string(wire.Verification) != "null" {
		var envelope struct {
			PageURL string `json:"verification_page_url"`
		}
		if json.Unmarshal(wire.Verification, &envelope) == nil && len(envelope.PageURL) <= 2_000 {
			if page, err := url.Parse(envelope.PageURL); err == nil && (page.Scheme == "https" || page.Scheme == "http") && page.Host != "" {
				decision.VerificationURL = envelope.PageURL
			}
		}
	}
	if wire.ManagedEscalation != nil {
		m := wire.ManagedEscalation
		expires, err := time.Parse(time.RFC3339Nano, m.ExpiresAt)
		if err != nil || m.IntentID != captured.Binding.IntentID || !consistentManaged(m.Status, m.Outcome) {
			return failClosed(captured.Hash, "MANAGED_ESCALATION_STATE_INVALID", status)
		}
		decision.Managed = &ManagedEscalation{EscalationID: m.EscalationID, IntentID: m.IntentID, Status: m.Status, Outcome: m.Outcome, ExpiresAt: expires, ReasonCodes: append([]string{}, m.ReasonCodes...)}
	}
	if mode == Shadow {
		return decision
	}
	if verdict != Allow {
		return decision
	}
	// The grant is real only when every positive assertion holds; an ALLOW
	// without one is a refusal, never an execution.
	intentExpires, err := time.Parse(time.RFC3339Nano, captured.Binding.ExpiresAt)
	if err != nil {
		return failClosed(captured.Hash, "INTENT_EXPIRED", status)
	}
	var tokenExpires time.Time
	if wire.ExecutionTokenExpires != nil {
		tokenExpires, err = time.Parse(time.RFC3339Nano, *wire.ExecutionTokenExpires)
		if err != nil {
			return failClosed(captured.Hash, "AUTHORITY_GRANT_MISSING", status)
		}
	}
	canExecute := wire.ShouldExecute &&
		wire.Mode != nil && *wire.Mode == string(Enforcement) &&
		(wire.AuthorityClassification == nil || *wire.AuthorityClassification == "AUTHORITATIVE") &&
		(wire.ExecutionEligible == nil || *wire.ExecutionEligible) &&
		(wire.ExecutionBindingDigest == nil || *wire.ExecutionBindingDigest != "") &&
		(wire.ExecutionTokenJTI == nil || *wire.ExecutionTokenJTI != "") &&
		(wire.ExecutionTokenKeyID == nil || *wire.ExecutionTokenKeyID != "") &&
		wire.DossierID != nil && *wire.DossierID != "" &&
		wire.ExecutionToken != nil && *wire.ExecutionToken != "" &&
		wire.ExecutionTokenExpires != nil &&
		tokenExpires.After(c.now()) && !tokenExpires.After(intentExpires)
	if !canExecute {
		return failClosed(captured.Hash, "AUTHORITY_GRANT_MISSING", status)
	}
	decision.Grant = &Grant{token: *wire.ExecutionToken, ExpiresAt: tokenExpires}
	return decision
}

func consistentManaged(status, outcome string) bool {
	switch {
	case status == "GRANT_READY":
		return outcome == "ALLOW"
	case status == "FAILED":
		return outcome == "ERROR"
	case pendingStatuses[status]:
		return outcome == "ESCALATE_PENDING"
	case status == "EXPIRED" || status == "REJECTED" || status == "BLOCKED" || status == "CANCELLED":
		return outcome == "BLOCK"
	}
	return false
}

// WaitOptions bound a managed escalation wait; zero values take the defaults.
type WaitOptions struct {
	InitialDelay time.Duration
	MaxDelay     time.Duration
	// Deadline caps the wait; the intent's expiry always does.
	Deadline time.Time
	// OnStatus, when set, hears every status the authority reported.
	OnStatus func(status string, reasonCodes []string)
}

// WaitForManaged polls the escalation the authority opened until it ends or
// the intent expires. A GRANT_READY carries the decision with the grant; every
// other end is a BLOCK with the authority's reason codes; running out of time
// is MANAGED_ESCALATION_EXPIRED.
func (c *Client) WaitForManaged(ctx context.Context, captured intent.Captured, managed *ManagedEscalation, options WaitOptions) Decision {
	if managed == nil {
		return failClosed(captured.Hash, "MANAGED_ESCALATION_MISSING", 0)
	}
	delay := options.InitialDelay
	if delay <= 0 {
		delay = pollInitialDelay
	}
	maxDelay := options.MaxDelay
	if maxDelay <= 0 || maxDelay > pollMaxDelay {
		maxDelay = pollMaxDelay
	}
	deadline := managed.ExpiresAt
	if intentExpires, err := time.Parse(time.RFC3339Nano, captured.Binding.ExpiresAt); err == nil && intentExpires.Before(deadline) {
		deadline = intentExpires
	}
	if !options.Deadline.IsZero() && options.Deadline.Before(deadline) {
		deadline = options.Deadline
	}
	for attempt := 0; attempt < maxPollAttempts; attempt++ {
		if !c.now().Before(deadline) {
			return failClosed(captured.Hash, "MANAGED_ESCALATION_EXPIRED", 0)
		}
		if err := c.sleep(ctx, delay); err != nil {
			return failClosed(captured.Hash, "MANAGED_ESCALATION_ABORTED", 0)
		}
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
		status, text, err := c.get(ctx, "/v1/authority/escalations/"+url.PathEscape(managed.EscalationID), maxResponseBytes)
		if err != nil {
			continue // a transient failure is a retry; the deadline ends it
		}
		if status != 200 {
			if status == 404 {
				return failClosed(captured.Hash, "MANAGED_ESCALATION_UNKNOWN", status)
			}
			continue
		}
		var wire wireStatus
		if err := strictDecode(text, &wire); err != nil {
			return failClosed(captured.Hash, "MANAGED_ESCALATION_STATUS_INVALID", status)
		}
		if wire.EscalationID != managed.EscalationID || wire.IntentID != captured.Binding.IntentID || wire.ActionHash != captured.Hash || !consistentManaged(wire.Status, wire.Outcome) {
			return failClosed(captured.Hash, "MANAGED_ESCALATION_STATUS_INVALID", status)
		}
		if options.OnStatus != nil {
			options.OnStatus(wire.Status, wire.ReasonCodes)
		}
		switch wire.Outcome {
		case "ESCALATE_PENDING":
			continue
		case "ALLOW":
			if wire.Decision == nil {
				return failClosed(captured.Hash, "AUTHORITY_GRANT_MISSING", status)
			}
			decision := c.decisionFrom(captured, Enforcement, *wire.Decision, status)
			if decision.Verdict != Allow || decision.FailClosed {
				return failClosed(captured.Hash, "AUTHORITY_GRANT_MISSING", status)
			}
			return decision
		case "ERROR":
			return failClosed(captured.Hash, firstOr(wire.ReasonCodes, "MANAGED_ESCALATION_FAILED"), status)
		default:
			codes := wire.ReasonCodes
			if len(codes) == 0 {
				codes = []string{"MANAGED_ESCALATION_" + wire.Status}
			}
			return Decision{Verdict: Block, IntentHash: captured.Hash, ReasonCodes: codes, Mode: Enforcement, HTTPStatus: status}
		}
	}
	return failClosed(captured.Hash, "MANAGED_ESCALATION_EXPIRED", 0)
}

// Claim is a consumed grant: the authority's word that this exact intent may
// run once, now. The claim material stays private to the client.
type Claim struct {
	DecisionID     string
	DossierID      string
	GrantID        string
	IntentHash     string
	ExpiresAt      time.Time
	LeaseExpiresAt time.Time
	// Attestation is the compact JWS a system of record can verify without
	// trusting this process; empty when the authority predates it.
	Attestation   string
	PayloadDigest string

	token         string
	claimToken    string
	correlationID string
}

type wireClaim struct {
	Valid         bool     `json:"valid"`
	ReasonCodes   []string `json:"reason_codes"`
	ShouldExecute *bool    `json:"should_execute"`
	Claims        *struct {
		Iss        string  `json:"iss"`
		Sub        *string `json:"sub"`
		Aud        *string `json:"aud"`
		OrgID      string  `json:"org_id"`
		DossierID  string  `json:"dossier_id"`
		DecisionID string  `json:"decision_id"`
		Action     string  `json:"action"`
		Decision   string  `json:"decision"`
		Scope      string  `json:"scope"`
		Binding    struct {
			IntentHash             string          `json:"intent_hash"`
			ExpectedEffectDigest   json.RawMessage `json:"expected_effect_digest"`
			ExecutionPayloadDigest json.RawMessage `json:"execution_payload_digest"`
			Profile                json.RawMessage `json:"execution_payload_canonicalization_profile"`
		} `json:"binding"`
		JTI string `json:"jti"`
		Iat int64  `json:"iat"`
		Nbf int64  `json:"nbf"`
		Exp int64  `json:"exp"`
	} `json:"claims"`
	ClaimToken       *string `json:"claim_token"`
	ClaimLeaseExpiry *string `json:"claim_lease_expires_at"`
	ClaimAttestation *string `json:"claim_attestation"`
}

// ClaimGrant consumes the decision's grant through claim-token immediately
// before the command runs. A nil claim with a reason code means nothing may
// run: the claim is the authority, not the grant.
func (c *Client) ClaimGrant(ctx context.Context, captured intent.Captured, decision Decision) (*Claim, string) {
	if !decision.Executable() || decision.IntentHash != captured.Hash || decision.DossierID == "" {
		return nil, "AUTHORIZATION_INVALID"
	}
	binding := map[string]any{}
	if err := remarshal(captured.Binding, &binding); err != nil {
		return nil, "INTENT_NOT_JSON"
	}
	correlationID := captured.Binding.IntentID
	body := map[string]any{
		"execution_token":       decision.Grant.token,
		"intent_hash":           captured.Hash,
		"intent":                binding,
		"consumed_by":           captured.Binding.Actor.ID,
		"commit_correlation_id": correlationID,
	}
	status, text, err := c.post(ctx, "/v1/execution/claim-token", body, nil, maxResponseBytes)
	if err != nil {
		return nil, "AUTHORITY_UNAVAILABLE"
	}
	var wire wireClaim
	if status != 200 || json.Unmarshal(text, &wire) != nil {
		if status == 200 {
			return nil, "AUTHORITY_RESPONSE_INVALID"
		}
		var refused struct {
			ReasonCodes []string `json:"reason_codes"`
		}
		_ = json.Unmarshal(text, &refused)
		return nil, firstOr(refused.ReasonCodes, "AUTHORIZATION_INVALID")
	}
	claims := wire.Claims
	if !wire.Valid || claims == nil || (wire.ShouldExecute != nil && !*wire.ShouldExecute) || wire.ClaimToken == nil || !claimToken.MatchString(*wire.ClaimToken) {
		return nil, "AUTHORIZATION_INVALID"
	}
	audience := captured.Binding.DownstreamTarget.System + ":" + captured.Binding.DownstreamTarget.Operation
	payloadDigest, digestKnown := optionalDigest(claims.Binding.ExecutionPayloadDigest)
	profile, profileKnown := optionalString(claims.Binding.Profile)
	if digestKnown {
		own, err := intent.HashValue(captured.Binding.Action.Parameters)
		if err != nil || !profileKnown || profile != jcsProfile || payloadDigest != own {
			return nil, "AUTHORIZATION_INVALID"
		}
	}
	committed, committedKnown := optionalDigest(claims.Binding.ExpectedEffectDigest)
	if committedKnown != (captured.Binding.ExpectedEffectDigest != "") || (committedKnown && committed != captured.Binding.ExpectedEffectDigest) {
		return nil, "AUTHORIZATION_INVALID"
	}
	expiry := time.Unix(claims.Exp, 0)
	intentExpires, _ := time.Parse(time.RFC3339Nano, captured.Binding.ExpiresAt)
	if claims.Binding.IntentHash != captured.Hash ||
		claims.DecisionID != decision.DecisionID ||
		claims.DossierID != decision.DossierID ||
		claims.OrgID != captured.Binding.TenantID ||
		claims.Sub == nil || *claims.Sub != captured.Binding.Actor.ID ||
		claims.Action != captured.Binding.Action.Type ||
		claims.Decision != "allow" || claims.Scope != "execute" ||
		(claims.Aud != nil && *claims.Aud != audience) ||
		claims.Exp != decision.Grant.ExpiresAt.Unix() ||
		!expiry.After(c.now()) || expiry.After(intentExpires) {
		return nil, "AUTHORIZATION_INVALID"
	}
	claim := &Claim{
		DecisionID:    claims.DecisionID,
		DossierID:     claims.DossierID,
		GrantID:       claims.JTI,
		IntentHash:    claims.Binding.IntentHash,
		ExpiresAt:     expiry,
		PayloadDigest: payloadDigest,
		token:         decision.Grant.token,
		claimToken:    *wire.ClaimToken,
		correlationID: correlationID,
	}
	if wire.ClaimLeaseExpiry != nil {
		if lease, err := time.Parse(time.RFC3339Nano, *wire.ClaimLeaseExpiry); err == nil {
			claim.LeaseExpiresAt = lease
		}
	}
	if wire.ClaimAttestation != nil && compactJWS.MatchString(*wire.ClaimAttestation) && len(*wire.ClaimAttestation) <= 8_192 {
		claim.Attestation = *wire.ClaimAttestation
	}
	return claim, ""
}

// Evidence is what the executor observed of the attempt, recorded beside the
// outcome; nothing in it is an interpretation of the effect itself.
type Evidence map[string]any

// Finalize records the attempt's outcome with the authority. PENDING means
// the authority did not record it, and the record says so; it never changes
// what happened.
func (c *Client) Finalize(ctx context.Context, claim *Claim, outcome Outcome, evidence Evidence) Finalization {
	if claim == nil || claim.claimToken == "" {
		return Pending
	}
	body := map[string]any{
		"execution_token":       claim.token,
		"claim_token":           claim.claimToken,
		"outcome":               string(outcome),
		"commit_correlation_id": claim.correlationID,
	}
	if len(evidence) > 0 {
		body["downstream_evidence"] = evidence
	}
	status, text, err := c.post(ctx, "/v1/execution/finalize-token", body, nil, maxResponseBytes)
	if err != nil || status != 200 {
		return Pending
	}
	var wire struct {
		Finalized bool `json:"finalized"`
	}
	if json.Unmarshal(text, &wire) != nil || !wire.Finalized {
		return Pending
	}
	claim.claimToken = ""
	return Recorded
}

// DossierSummary is what the signed record says about itself.
type DossierSummary struct {
	DossierID     string
	Outcome       string
	GeneratedAt   string
	Algorithm     string
	KeyID         string
	IssuedAt      string
	Artifacts     int
	IssuerTier    string
	Bytes         int
	PolicyVersion string
}

// FetchDossier reads the Decision Dossier the decision left, with the run's
// own key. An error names why it could not be read; the decision stands.
func (c *Client) FetchDossier(ctx context.Context, tenantID, id string) (DossierSummary, error) {
	if !dossierID.MatchString(id) {
		return DossierSummary{}, errors.New("DOSSIER_RESPONSE_INVALID")
	}
	status, text, err := c.get(ctx, "/v1/protocol/dossiers/"+url.PathEscape(id)+"?org_id="+url.QueryEscape(tenantID), maxDossierBytes)
	switch {
	case err != nil:
		return DossierSummary{}, errors.New("DOSSIER_UNAVAILABLE")
	case status == 404:
		return DossierSummary{}, errors.New("DOSSIER_NOT_FOUND")
	case status == 401 || status == 403:
		return DossierSummary{}, errors.New("DOSSIER_REFUSED")
	case status >= 500:
		return DossierSummary{}, errors.New("DOSSIER_UNAVAILABLE")
	case status != 200:
		return DossierSummary{}, errors.New("DOSSIER_RESPONSE_INVALID")
	}
	var body struct {
		Dossier struct {
			Payload struct {
				DossierID   string `json:"dossier_id"`
				GeneratedAt string `json:"generated_at"`
				Routing     struct {
					Outcome       string `json:"outcome"`
					PolicyVersion string `json:"policy_version"`
				} `json:"routing_decision"`
				Portable struct {
					Issuer struct {
						Tier string `json:"tier"`
					} `json:"issuer_context"`
				} `json:"portable_artifact"`
				Integrity struct {
					Bundle struct {
						Algorithm string `json:"algorithm"`
						KeyID     string `json:"key_id"`
						IssuedAt  string `json:"issued_at"`
						Artifacts []any  `json:"artifacts"`
					} `json:"proof_bundle"`
				} `json:"integrity"`
			} `json:"dossier_payload"`
		} `json:"dossier"`
	}
	if json.Unmarshal(text, &body) != nil || body.Dossier.Payload.DossierID == "" {
		return DossierSummary{}, errors.New("DOSSIER_RESPONSE_INVALID")
	}
	p := body.Dossier.Payload
	return DossierSummary{
		DossierID: p.DossierID, Outcome: p.Routing.Outcome, GeneratedAt: p.GeneratedAt,
		Algorithm: p.Integrity.Bundle.Algorithm, KeyID: p.Integrity.Bundle.KeyID, IssuedAt: p.Integrity.Bundle.IssuedAt,
		Artifacts: len(p.Integrity.Bundle.Artifacts), IssuerTier: p.Portable.Issuer.Tier, Bytes: len(text),
		PolicyVersion: p.Routing.PolicyVersion,
	}, nil
}

var errResponseTooLarge = errors.New("response too large")

func (c *Client) post(ctx context.Context, path string, body any, headers map[string]string, limit int64) (int, []byte, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	request, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("content-type", "application/json")
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	return c.do(ctx, request, limit)
}

func (c *Client) get(ctx context.Context, path string, limit int64) (int, []byte, error) {
	request, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("accept", "application/json")
	return c.do(ctx, request, limit)
}

func (c *Client) do(ctx context.Context, request *http.Request, limit int64) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request = request.WithContext(ctx)
	request.Header.Set("authorization", "Bearer "+c.apiKey())
	if c.userAgent != "" {
		request.Header.Set("user-agent", c.userAgent)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	text, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return response.StatusCode, nil, err
	}
	if int64(len(text)) > limit {
		return response.StatusCode, nil, errResponseTooLarge
	}
	return response.StatusCode, text, nil
}

// strictDecode refuses unknown fields at every level, as the reference gate's
// strict schema does: a field the contract does not name cannot carry semantics.
func strictDecode(text []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing content")
	}
	return nil
}

func remarshal(from any, into any) error {
	encoded, err := json.Marshal(from)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	return decoder.Decode(into)
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func firstOr(values []string, fallback string) string {
	if len(values) > 0 && values[0] != "" {
		return values[0]
	}
	return fallback
}

var sha256Digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// optionalDigest reads a nullable digest the loose claim envelope may carry:
// absent, null or unreadable all mean "none", exactly as the reference does.
func optionalDigest(raw json.RawMessage) (string, bool) {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil || !sha256Digest.MatchString(value) {
		return "", false
	}
	return value, true
}

func optionalString(raw json.RawMessage) (string, bool) {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil || value == "" || len(value) > 200 {
		return "", false
	}
	return value, true
}
