// Package authoritytest is a loopback double of the Decionis execution
// authority for this module's tests, shaped after the pipeline's
// LocalAuthority fixture: it re-hashes the binding with its own
// canonicalizer, decides on `action.parameters.amountMinor` exactly as that
// fixture does (ALLOW to 10 000, ESCALATE to 100 000, BLOCK above), issues
// synthetic grants that one claim consumes, scripts managed escalations, and
// records finalizations. Nothing here is a policy, a tenant or a credential.
package authoritytest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

const (
	// APIKey is the credential the double accepts; letters only, as the
	// repository's secret scanner wants a synthetic key.
	APIKey = "synthetic-key-aaaaaaaaaaaaaaaa"
	// TenantID is the reserved fixture tenant.
	TenantID          = "00000000-0000-4000-8000-000000000002"
	AutonomousLimit   = 10_000
	HumanLimit        = 100_000
	Issuer            = "synthetic-authority"
	grantTTL          = 60 * time.Second
	claimLease        = 30 * time.Second
	jcsProfile        = "RFC8785/JCS"
	maxIntentLifetime = 300 * time.Second
)

// Request is one request the double saw, body decoded.
type Request struct {
	Method  string
	Path    string
	Headers http.Header
	Body    map[string]any
}

type grant struct {
	jti, tenant, actor, action, audience, decisionID, dossierID, intentHash string
	issued, expires                                                         int64
	payloadDigest                                                           string
	claimed                                                                 bool
	claimToken, correlationID                                               string
	finalized                                                               *finalization
}

type finalization struct {
	Outcome  string
	Evidence map[string]any
}

type managed struct {
	escalationID string
	request      map[string]any
	intentHash   string
	lifecycle    []string
	lookup       int
	final        map[string]any
	initial      map[string]any
}

// Double is the authority; use New and its URL.
type Double struct {
	Server *httptest.Server
	mu     sync.Mutex
	// Requests is every request seen, oldest first.
	Requests []Request
	// Lifecycle scripts the next managed escalation's statuses, one per
	// status lookup; the last entry repeats. Empty means AWAITING_APPROVER
	// then GRANT_READY.
	Lifecycle []string
	// Fail, when set, is returned as the status of the next enforce-and-bind.
	Fail int
	// Delay holds every enforce-and-bind for this long before answering.
	Delay time.Duration
	// Verification attaches a page URL to decisions, as the hosted
	// evaluate-decision does and enforce-and-bind may.
	Verification bool
	decisions    int
	grants       map[string]*grant
	dossiers     map[string]map[string]any
	escalations  map[string]*managed
	byIntent     map[string]*managed
	now          func() time.Time
}

// New starts the double on the loopback interface.
func New() *Double {
	d := &Double{grants: map[string]*grant{}, dossiers: map[string]map[string]any{}, escalations: map[string]*managed{}, byIntent: map[string]*managed{}, now: time.Now}
	d.Server = httptest.NewServer(http.HandlerFunc(d.handle))
	return d
}

// Close stops the server.
func (d *Double) Close() { d.Server.Close() }

// URL is the double's base URL, http on loopback.
func (d *Double) URL() string { return d.Server.URL }

// Grants counts grants issued.
func (d *Double) Grants() int { d.mu.Lock(); defer d.mu.Unlock(); return len(d.grants) }

// Finalizations returns the recorded outcomes by grant jti.
func (d *Double) Finalizations() map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string]string{}
	for _, g := range d.grants {
		if g.finalized != nil {
			out[g.jti] = g.finalized.Outcome
		}
	}
	return out
}

// Decisions counts decisions minted.
func (d *Double) Decisions() int { d.mu.Lock(); defer d.mu.Unlock(); return d.decisions }

func (d *Double) send(w http.ResponseWriter, status int, body any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (d *Double) handle(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	raw, _ := readAll(r)
	if len(raw) > 0 {
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()
		if err := decoder.Decode(&body); err != nil {
			d.send(w, 400, map[string]any{"error": "REQUEST_MALFORMED"})
			return
		}
	}
	d.mu.Lock()
	d.Requests = append(d.Requests, Request{Method: r.Method, Path: r.URL.Path, Headers: r.Header.Clone(), Body: body})
	d.mu.Unlock()
	if r.Header.Get("authorization") != "Bearer "+APIKey {
		d.send(w, 401, map[string]any{"error": "UNAUTHORIZED"})
		return
	}
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/protocol/dossiers/") {
		d.mu.Lock()
		record, ok := d.dossiers[strings.TrimPrefix(r.URL.Path, "/v1/protocol/dossiers/")]
		d.mu.Unlock()
		if !ok || r.URL.Query().Get("org_id") != record["tenant_id"] {
			d.send(w, 404, map[string]any{"error": "DOSSIER_NOT_FOUND"})
			return
		}
		d.send(w, 200, record["record"])
		return
	}
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/authority/escalations/") {
		d.mu.Lock()
		defer d.mu.Unlock()
		status, response := d.managedStatus(strings.TrimPrefix(r.URL.Path, "/v1/authority/escalations/"))
		d.send(w, status, response)
		return
	}
	if r.Method != http.MethodPost {
		d.send(w, 405, map[string]any{"error": "METHOD_NOT_ALLOWED"})
		return
	}
	if r.Header.Get("content-type") != "application/json" {
		d.send(w, 415, map[string]any{"error": "UNSUPPORTED_MEDIA_TYPE"})
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch r.URL.Path {
	case "/v1/authority/enforce-and-bind":
		if d.Delay > 0 {
			d.mu.Unlock()
			time.Sleep(d.Delay)
			d.mu.Lock()
		}
		if d.Fail != 0 {
			status := d.Fail
			d.Fail = 0
			d.send(w, status, map[string]any{"error": "SYNTHETIC_FAILURE"})
			return
		}
		status, response := d.enforceAndBind(r, body)
		d.send(w, status, response)
	case "/v1/execution/claim-token", "/v1/execution/consume-token":
		status, response := d.claim(body)
		d.send(w, status, response)
	case "/v1/execution/finalize-token":
		status, response := d.finalize(body)
		d.send(w, status, response)
	default:
		d.send(w, 404, map[string]any{"error": "NOT_FOUND"})
	}
}

var sha256Form = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (d *Double) bindingError(body map[string]any) string {
	binding := map[string]any{}
	for key, value := range body {
		switch key {
		case "intent_hash", "mode", "evidence", "escalation":
			continue
		}
		binding[key] = value
	}
	hash, _ := body["intent_hash"].(string)
	if !sha256Form.MatchString(hash) {
		return "REQUEST_INVALID"
	}
	if HashBinding(binding) != hash {
		return "INTENT_HASH_MISMATCH"
	}
	captured, err1 := time.Parse(time.RFC3339Nano, str(binding["captured_at"]))
	expires, err2 := time.Parse(time.RFC3339Nano, str(binding["expires_at"]))
	if err1 != nil || err2 != nil {
		return "REQUEST_INVALID"
	}
	now := d.now()
	switch {
	case captured.After(now.Add(5 * time.Second)):
		return "INTENT_CAPTURED_IN_FUTURE"
	case !expires.After(now):
		return "INTENT_EXPIRED"
	case !expires.After(captured):
		return "INTENT_TIME_ORDER_INVALID"
	case expires.Sub(captured) > maxIntentLifetime:
		return "INTENT_LIFETIME_TOO_LONG"
	}
	return ""
}

func (d *Double) policy(body map[string]any) (string, string) {
	action, _ := body["action"].(map[string]any)
	parameters, _ := action["parameters"].(map[string]any)
	amount := 0.0
	if n, ok := parameters["amountMinor"].(json.Number); ok {
		f, _ := n.Float64()
		amount = f
	}
	switch {
	case amount > HumanLimit:
		return "BLOCK", "POLICY_HARD_LIMIT_EXCEEDED"
	case amount > AutonomousLimit:
		return "ESCALATE", "HUMAN_APPROVAL_REQUIRED"
	}
	return "ALLOW", "POLICY_AUTONOMOUS_LIMIT"
}

func (d *Double) enforceAndBind(r *http.Request, body map[string]any) (int, any) {
	intentID := str(body["intent_id"])
	if r.Header.Get("idempotency-key") != intentID {
		return 400, map[string]any{"error": "IDEMPOTENCY_KEY_MISMATCH"}
	}
	if code := d.bindingError(body); code != "" {
		return 400, map[string]any{"error": code}
	}
	mode := str(body["mode"])
	if mode != "SHADOW" && mode != "ENFORCEMENT" {
		return 400, map[string]any{"error": "REQUEST_INVALID"}
	}
	verdict, reason := d.policy(body)
	d.decisions++
	decision := d.baseDecision(body, verdict, []string{reason})
	escalation, _ := body["escalation"].(map[string]any)
	if verdict == "ESCALATE" && str(escalation["mode"]) == "MANAGED" {
		if mode != "ENFORCEMENT" {
			return 400, map[string]any{"error": "REQUEST_INVALID"}
		}
		return 200, d.remember(body, d.openManaged(body, decision))
	}
	if verdict != "ALLOW" || mode != "ENFORCEMENT" {
		return 200, d.remember(body, decision)
	}
	return 200, d.remember(body, d.grantDecision(body, decision))
}

func (d *Double) baseDecision(body map[string]any, verdict string, reasons []string) map[string]any {
	sequence := d.decisions
	dossierID := fmt.Sprintf("synthetic-dossier-%d", sequence)
	sum := sha256.Sum256([]byte(dossierID))
	mode := str(body["mode"])
	classification := "OBSERVATIONAL"
	if mode == "ENFORCEMENT" {
		classification = "AUTHORITATIVE"
	}
	var approval any
	if verdict == "ESCALATE" {
		approval = fmt.Sprintf("synthetic-approval-%d", sequence)
	}
	return map[string]any{
		"decision_id":                fmt.Sprintf("synthetic-decision-%d", sequence),
		"chain_id":                   "synthetic-chain-1",
		"status":                     verdict,
		"should_execute":             false,
		"reason_codes":               reasons,
		"action_hash":                str(body["intent_hash"]),
		"policy_version":             "synthetic-policy-v1",
		"mode":                       mode,
		"execution_token":            nil,
		"execution_token_expires_at": nil,
		"dossier_id":                 dossierID,
		"dossier_sha256":             "sha256:" + hex.EncodeToString(sum[:]),
		"dossier_url":                "/v1/protocol/dossiers/" + dossierID,
		"approval_request_id":        approval,
		"ledger_entry_id":            fmt.Sprintf("synthetic-ledger-%d", sequence),
		"authority_classification":   classification,
		"execution_eligible":         false,
		"execution_binding_digest":   nil,
		"execution_token_jti":        nil,
		"execution_token_key_id":     nil,
	}
}

func (d *Double) grantDecision(body map[string]any, decision map[string]any) map[string]any {
	now := d.now()
	expires, _ := time.Parse(time.RFC3339Nano, str(body["expires_at"]))
	tokenExpires := now.Add(grantTTL)
	if expires.Before(tokenExpires) {
		tokenExpires = expires
	}
	tokenExpires = tokenExpires.Truncate(time.Second)
	jti := "synthetic-jti-" + randomHex(8)
	token := "synthetic-grant." + jti
	actor, _ := body["actor"].(map[string]any)
	action, _ := body["action"].(map[string]any)
	target, _ := body["downstream_target"].(map[string]any)
	parameters, _ := action["parameters"].(map[string]any)
	hashSum := sha256.Sum256([]byte(str(body["intent_hash"])))
	g := &grant{
		jti: jti, tenant: str(body["tenant_id"]), actor: str(actor["id"]), action: str(action["type"]),
		audience:   str(target["system"]) + ":" + str(target["operation"]),
		decisionID: str(decision["decision_id"]), dossierID: str(decision["dossier_id"]),
		intentHash: str(body["intent_hash"]), issued: now.Unix(), expires: tokenExpires.Unix(),
		payloadDigest: HashBinding(parameters),
	}
	d.grants[token] = g
	out := map[string]any{}
	for k, v := range decision {
		out[k] = v
	}
	out["should_execute"] = true
	out["execution_token"] = token
	out["execution_token_expires_at"] = tokenExpires.UTC().Format("2006-01-02T15:04:05.000Z")
	out["execution_eligible"] = true
	out["execution_binding_digest"] = "sha256:" + hex.EncodeToString(hashSum[:])
	out["execution_token_jti"] = jti
	out["execution_token_key_id"] = "synthetic-key-1"
	return out
}

func (d *Double) openManaged(body map[string]any, decision map[string]any) map[string]any {
	intentID := str(body["intent_id"])
	if existing, ok := d.byIntent[intentID]; ok {
		return existing.initial
	}
	escalationID := "synthetic-escalation-" + randomHex(8)
	initial := map[string]any{}
	for k, v := range decision {
		initial[k] = v
	}
	initial["managed_escalation"] = map[string]any{
		"outcome": "ESCALATE_PENDING", "escalation_id": escalationID, "intent_id": intentID,
		"status": "PENDING_PRESENCE", "expires_at": str(body["expires_at"]), "reason_codes": []string{"PRESENCE_PENDING"},
	}
	lifecycle := d.Lifecycle
	d.Lifecycle = nil
	if len(lifecycle) == 0 {
		lifecycle = []string{"AWAITING_APPROVER", "GRANT_READY"}
	}
	m := &managed{escalationID: escalationID, request: body, intentHash: str(body["intent_hash"]), lifecycle: lifecycle, initial: initial}
	d.escalations[escalationID] = m
	d.byIntent[intentID] = m
	return initial
}

func (d *Double) managedStatus(escalationID string) (int, any) {
	m, ok := d.escalations[escalationID]
	if !ok {
		return 404, map[string]any{"error": "NOT_FOUND"}
	}
	index := m.lookup
	if index >= len(m.lifecycle) {
		index = len(m.lifecycle) - 1
	}
	m.lookup++
	status := m.lifecycle[index]
	outcome := "ESCALATE_PENDING"
	reasons := []string{"PRESENCE_PENDING"}
	var decision any
	switch status {
	case "GRANT_READY":
		outcome = "ALLOW"
		reasons = []string{"PRESENCE_RECEIPT_VERIFIED"}
		if m.final == nil {
			d.decisions++
			request := map[string]any{}
			for k, v := range m.request {
				request[k] = v
			}
			request["mode"] = "ENFORCEMENT"
			m.final = d.grantDecision(request, d.baseDecision(request, "ALLOW", reasons))
			d.remember(request, m.final)
		}
		decision = m.final
	case "EXPIRED":
		outcome, reasons = "BLOCK", []string{"INTENT_EXPIRED", "RECAPTURE_REQUIRED"}
	case "REJECTED":
		outcome, reasons = "BLOCK", []string{"PRESENCE_REJECTED"}
	case "CANCELLED":
		outcome, reasons = "BLOCK", []string{"CANCELLED"}
	case "BLOCKED":
		outcome, reasons = "BLOCK", []string{"REAUTHORIZATION_BLOCKED"}
	case "FAILED":
		outcome, reasons = "ERROR", []string{"PRESENCE_VERIFICATION_FAILED"}
	}
	return 200, map[string]any{
		"escalation_id": m.escalationID, "intent_id": str(m.request["intent_id"]), "action_hash": m.intentHash,
		"status": status, "outcome": outcome, "expires_at": str(m.request["expires_at"]), "reason_codes": reasons,
		"decision": decision,
	}
}

func (d *Double) remember(body map[string]any, decision map[string]any) map[string]any {
	dossierID := str(decision["dossier_id"])
	if d.Verification {
		out := map[string]any{}
		for k, v := range decision {
			out[k] = v
		}
		out["verification"] = map[string]any{
			"verification_page_url": d.Server.URL + "/verify/" + dossierID + "?sig=synthetic",
			"signature_scheme":      "synthetic",
		}
		decision = out
	}
	actor, _ := body["actor"].(map[string]any)
	action, _ := body["action"].(map[string]any)
	generated := d.now().UTC().Format("2006-01-02T15:04:05.000Z")
	d.dossiers[dossierID] = map[string]any{
		"tenant_id": str(body["tenant_id"]),
		"record": map[string]any{
			"service": "synthetic-authority", "protocol_version": "synthetic",
			"dossier": map[string]any{"dossier_payload": map[string]any{
				"schema_version": "decionis.decision_dossier/2.0", "dossier_id": dossierID, "generated_at": generated,
				"routing_decision":  map[string]any{"decision_id": decision["decision_id"], "outcome": decision["status"], "authority": decision["authority_classification"], "policy_version": decision["policy_version"], "reason_codes": decision["reason_codes"]},
				"inputs_snapshot":   map[string]any{"tenant_id": body["tenant_id"], "actor_id": actor["id"], "action": action["type"], "target": action["resource"]},
				"portable_artifact": map[string]any{"issuer_context": map[string]any{"tier": "synthetic_loopback"}},
				"integrity":         map[string]any{"proof_bundle": map[string]any{"bundle_type": "decionis.decision_dossier.proof_bundle", "version": "2.0", "issued_at": generated, "algorithm": "Ed25519", "key_id": "synthetic-key-1", "artifacts": []any{}}},
			}},
		},
	}
	return decision
}

func (d *Double) claim(body map[string]any) (int, any) {
	rejected := func(code string) (int, any) {
		return 409, map[string]any{"valid": false, "reason_codes": []string{code}, "claims": nil}
	}
	binding, _ := body["intent"].(map[string]any)
	if binding == nil {
		return 400, map[string]any{"error": "REQUEST_INVALID"}
	}
	check := map[string]any{}
	for k, v := range binding {
		check[k] = v
	}
	check["intent_hash"] = body["intent_hash"]
	if code := d.bindingError(check); code != "" {
		return rejected(code)
	}
	g, ok := d.grants[str(body["execution_token"])]
	if !ok {
		return rejected("GRANT_INVALID")
	}
	if g.expires <= d.now().Unix() {
		return rejected("GRANT_EXPIRED")
	}
	if g.intentHash != str(body["intent_hash"]) {
		return rejected("GRANT_BINDING_MISMATCH")
	}
	if g.claimed {
		return rejected("NONCE_REPLAY_DETECTED")
	}
	g.claimed = true
	g.claimToken = base64.RawURLEncoding.EncodeToString(randomBytes(32))
	g.correlationID = str(body["commit_correlation_id"])
	if g.correlationID == "" {
		g.correlationID = str(binding["intent_id"])
	}
	validated := d.now().UTC().Format("2006-01-02T15:04:05.000Z")
	lease := d.now().Add(claimLease).UTC().Format("2006-01-02T15:04:05.000Z")
	tokenDigest := sha256.Sum256([]byte(g.claimToken))
	attestation := compactJWS(map[string]any{
		"iss": Issuer, "sub": g.jti, "org_id": g.tenant, "dossier_id": g.dossierID, "decision_id": g.decisionID,
		"binding":            map[string]any{"intent_hash": g.intentHash, "execution_payload_digest": g.payloadDigest, "execution_payload_canonicalization_profile": jcsProfile, "execution_nonce": randomHex(16), "execution_correlation_id": g.correlationID},
		"claim_token_digest": "sha256:" + hex.EncodeToString(tokenDigest[:]), "claim_validated_at": validated,
		"jti": randomHex(16), "iat": d.now().Unix(), "nbf": d.now().Unix(), "exp": g.expires,
	})
	return 200, map[string]any{
		"valid": true, "should_execute": true, "would_block": false, "verdict": "ALLOW", "reason_codes": []string{},
		"claims": map[string]any{
			"iss": Issuer, "sub": g.actor, "aud": g.audience, "org_id": g.tenant, "dossier_id": g.dossierID, "decision_id": g.decisionID,
			"chain_id": "synthetic-chain-1", "action": g.action, "decision": "allow", "scope": "execute",
			"binding": map[string]any{
				"intent_hash": g.intentHash, "execution_binding_digest": "sha256:" + hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte(g.intentHash)); return s[:] }()),
				"execution_payload_digest": g.payloadDigest, "execution_payload_canonicalization_profile": jcsProfile,
				"execution_nonce": randomHex(16), "execution_correlation_id": g.correlationID,
			},
			"jti": g.jti, "iat": g.issued, "nbf": g.issued, "exp": g.expires,
		},
		"claim_token": g.claimToken, "claim_validated_at": validated, "claim_lease_expires_at": lease,
		"claim_attestation": attestation,
		"evidence":          map[string]any{"nonce_claim_state": "CLAIMED", "commit_correlation_id": g.correlationID},
	}
}

func (d *Double) finalize(body map[string]any) (int, any) {
	rejected := func(code string) (int, any) {
		return 409, map[string]any{"finalized": false, "reason_codes": []string{code}}
	}
	g, ok := d.grants[str(body["execution_token"])]
	if !ok {
		return rejected("GRANT_INVALID")
	}
	if !g.claimed || g.claimToken != str(body["claim_token"]) {
		return rejected("NONCE_REPLAY_DETECTED")
	}
	if g.correlationID != str(body["commit_correlation_id"]) {
		return rejected("EXECUTION_CORRELATION_MISMATCH")
	}
	if g.finalized != nil {
		return rejected("NONCE_REPLAY_DETECTED")
	}
	outcome := str(body["outcome"])
	if outcome != "COMMITTED" && outcome != "FAILED" && outcome != "INDETERMINATE" {
		return 400, map[string]any{"error": "REQUEST_INVALID"}
	}
	evidence, _ := body["downstream_evidence"].(map[string]any)
	g.finalized = &finalization{Outcome: outcome, Evidence: evidence}
	return 200, map[string]any{"finalized": true, "reason_codes": []string{}, "outcome": outcome, "effect_evidence_recorded": false, "effect_confirmation": "UNCONFIRMED"}
}

// HashBinding is the double's own canonicalization, deliberately not the
// module's: keys sorted by UTF-16 code unit, values as JSON, no whitespace.
func HashBinding(value any) string {
	sum := sha256.Sum256([]byte(StableStringify(value)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// StableStringify mirrors the LocalAuthority fixture's stableStringify.
func StableStringify(value any) string {
	switch typed := value.(type) {
	case []any:
		parts := make([]string, len(typed))
		for i, item := range typed {
			parts[i] = StableStringify(item)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			encodedKey, _ := marshalNoEscape(key)
			parts = append(parts, string(encodedKey)+":"+StableStringify(typed[key]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		encoded, _ := marshalNoEscape(value)
		return string(encoded)
	}
}

func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func marshalNoEscape(value any) ([]byte, error) {
	var buffer strings.Builder
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(buffer.String(), "\n")), nil
}

func compactJWS(claims map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": "synthetic-key-1"})
	payload, _ := json.Marshal(claims)
	encode := base64.RawURLEncoding.EncodeToString
	return encode(header) + "." + encode(payload) + "." + encode(randomBytes(64))
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randomHex(n int) string { return hex.EncodeToString(randomBytes(n)) }

func str(value any) string {
	s, _ := value.(string)
	return s
}

func readAll(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	buffer := make([]byte, 0, 4096)
	for {
		chunk := make([]byte, 4096)
		n, err := r.Body.Read(chunk)
		buffer = append(buffer, chunk[:n]...)
		if err != nil {
			break
		}
		if len(buffer) > 1<<20 {
			break
		}
	}
	return buffer, nil
}
