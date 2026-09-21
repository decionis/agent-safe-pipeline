// Package intent captures one execution intent in the agent-safe.intent/1
// contract and hashes its canonical form: the binding the authority decides
// on, RFC 8785 over the binding, SHA-256 over the bytes. The hash is what
// every later record names, so the bytes here must equal the reference
// implementation's byte for byte; the conformance vectors hold them to it.
package intent

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/gowebpki/jcs"
)

// ProtocolVersion is the contract the binding is written in.
const ProtocolVersion = "agent-safe.intent/1"

// ReservedContextIdempotencyKey is the context key the idempotency key rides
// in; a caller's context may not use it for anything else.
const ReservedContextIdempotencyKey = "idempotency_key"

// Bounds mirror the reference hasher's: a binding past them is refused, not
// truncated, because a truncated intent would hash to something the authority
// never saw.
const (
	MaxCanonicalBytes = 100 * 1024
	MaxDepth          = 20
	MaxEntries        = 5_000
	MaxArrayLength    = 1_000
	// MaxLifetime is the longest an intent may stay decidable; the authority
	// refuses a longer one as INTENT_LIFETIME_TOO_LONG.
	MaxLifetime = 300 * time.Second
)

var (
	actionTypePattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]*$`)
	uuidPattern       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	forbiddenKeys     = map[string]bool{"__proto__": true, "constructor": true, "prototype": true}
)

// Actor is who proposes the action: for a workflow, the workflow itself.
type Actor struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Runtime    string `json:"runtime,omitempty"`
	TrustLevel string `json:"trust_level,omitempty"`
}

// Action is what is proposed: a type, the resource it touches, its parameters.
type Action struct {
	Type       string         `json:"type"`
	Resource   string         `json:"resource"`
	Parameters map[string]any `json:"parameters"`
}

// DownstreamTarget names the system the effect lands in.
type DownstreamTarget struct {
	System      string `json:"system"`
	Operation   string `json:"operation"`
	Environment string `json:"environment,omitempty"`
	Endpoint    string `json:"endpoint,omitempty"`
}

// Binding is the exact wire form the authority hashes and decides on. Field
// order here is irrelevant: canonicalization sorts keys.
type Binding struct {
	ProtocolVersion      string           `json:"protocol_version"`
	TenantID             string           `json:"tenant_id"`
	IntentID             string           `json:"intent_id"`
	CapturedAt           string           `json:"captured_at"`
	ExpiresAt            string           `json:"expires_at"`
	Actor                Actor            `json:"actor"`
	Action               Action           `json:"action"`
	Context              map[string]any   `json:"context"`
	DownstreamTarget     DownstreamTarget `json:"downstream_target"`
	ExpectedEffectDigest string           `json:"expected_effect_digest,omitempty"`
}

// Captured is a binding with its canonical bytes and their digest.
type Captured struct {
	Binding   Binding
	Canonical []byte
	// Hash is `sha256:` and 64 lowercase hex digits.
	Hash string
}

// Proposal is the caller's half of an intent: the action and what it acts on.
type Proposal struct {
	ActionType string
	Resource   string
	Parameters map[string]any
}

// Trusted is the executor's half: who is acting, for which tenant, where the
// effect lands, and the context the record keeps beside the action.
type Trusted struct {
	TenantID         string
	Actor            Actor
	DownstreamTarget DownstreamTarget
	Context          map[string]any
	IdempotencyKey   string
	// TTL bounds the intent's life; it is clamped to [1s, MaxLifetime].
	TTL time.Duration
	// Now and NewID are the clock and the identifier source; nil means real ones.
	Now   func() time.Time
	NewID func() (string, error)
}

// Capture builds and hashes an intent from a proposal and the trusted context.
func Capture(proposal Proposal, trusted Trusted) (Captured, error) {
	if !actionTypePattern.MatchString(proposal.ActionType) || len(proposal.ActionType) > 120 {
		return Captured{}, fmt.Errorf("ACTION_TYPE_INVALID: %q is not a lowercase action name of at most 120 characters ([a-z][a-z0-9._:-]*)", proposal.ActionType)
	}
	resource := strings.TrimSpace(proposal.Resource)
	if resource == "" || len(resource) > 500 {
		return Captured{}, errors.New("ACTION_RESOURCE_INVALID: the resource is empty or longer than 500 characters")
	}
	if !uuidPattern.MatchString(trusted.TenantID) {
		return Captured{}, errors.New("TENANT_ID_INVALID: the tenant is not a UUID")
	}
	if err := boundedIdentifier("actor.id", trusted.Actor.ID); err != nil {
		return Captured{}, err
	}
	if err := boundedIdentifier("actor.type", trusted.Actor.Type); err != nil {
		return Captured{}, err
	}
	if err := boundedIdentifier("downstream_target.system", trusted.DownstreamTarget.System); err != nil {
		return Captured{}, err
	}
	if err := boundedIdentifier("downstream_target.operation", trusted.DownstreamTarget.Operation); err != nil {
		return Captured{}, err
	}
	key := strings.TrimSpace(trusted.IdempotencyKey)
	if key == "" || len(key) > 180 {
		return Captured{}, errors.New("IDEMPOTENCY_KEY_INVALID: the idempotency key is empty or longer than 180 characters")
	}
	if _, reserved := trusted.Context[ReservedContextIdempotencyKey]; reserved {
		return Captured{}, errors.New("INTENT_CONTEXT_KEY_RESERVED: the context may not carry idempotency_key itself")
	}
	now := time.Now
	if trusted.Now != nil {
		now = trusted.Now
	}
	newID := randomUUID
	if trusted.NewID != nil {
		newID = trusted.NewID
	}
	ttl := trusted.TTL
	if ttl < time.Second {
		ttl = time.Second
	}
	if ttl > MaxLifetime {
		ttl = MaxLifetime
	}
	id, err := newID()
	if err != nil {
		return Captured{}, err
	}
	capturedAt := now().UTC()
	parameters := proposal.Parameters
	if parameters == nil {
		parameters = map[string]any{}
	}
	context := make(map[string]any, len(trusted.Context)+1)
	for k, v := range trusted.Context {
		context[k] = v
	}
	context[ReservedContextIdempotencyKey] = key
	binding := Binding{
		ProtocolVersion:  ProtocolVersion,
		TenantID:         trusted.TenantID,
		IntentID:         id,
		CapturedAt:       Timestamp(capturedAt),
		ExpiresAt:        Timestamp(capturedAt.Add(ttl)),
		Actor:            trusted.Actor,
		Action:           Action{Type: proposal.ActionType, Resource: resource, Parameters: parameters},
		Context:          context,
		DownstreamTarget: trusted.DownstreamTarget,
	}
	return Hash(binding)
}

// Hash canonicalizes a binding and digests it, refusing one past the bounds.
func Hash(binding Binding) (Captured, error) {
	canonical, err := Canonical(binding)
	if err != nil {
		return Captured{}, err
	}
	sum := sha256.Sum256(canonical)
	return Captured{Binding: binding, Canonical: canonical, Hash: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// Canonical is RFC 8785 over any JSON value: keys sorted by UTF-16 code unit,
// numbers in ECMAScript's shortest form, strings escaped as JSON.stringify
// would, no whitespace. Bounded first, so an unbounded caller value is refused
// before it is walked.
func Canonical(value any) ([]byte, error) {
	encoded, err := encode(value)
	if err != nil {
		return nil, err
	}
	var generic any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		return nil, fmt.Errorf("INTENT_NOT_JSON: %w", err)
	}
	entries := 0
	if err := assertBounded(generic, 0, &entries); err != nil {
		return nil, err
	}
	canonical, err := jcs.Transform(encoded)
	if err != nil {
		return nil, fmt.Errorf("INTENT_CANONICALIZATION_FAILED: %w", err)
	}
	if len(canonical) > MaxCanonicalBytes {
		return nil, errors.New("INTENT_TOO_LARGE")
	}
	return canonical, nil
}

// HashValue is the digest the authority binds over a JSON value, in the
// contract's `sha256:<hex>` form; the payload digest in a claim is one.
func HashValue(value any) (string, error) {
	canonical, err := Canonical(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Timestamp is the contract's timestamp: ISO 8601, UTC, millisecond precision.
func Timestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func encode(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	// JSON.stringify does not escape HTML characters; canonical bytes must not either.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, fmt.Errorf("INTENT_NOT_JSON: %w", err)
	}
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}

func assertBounded(value any, depth int, entries *int) error {
	if depth > MaxDepth {
		return errors.New("INTENT_TOO_DEEP")
	}
	switch typed := value.(type) {
	case []any:
		if len(typed) > MaxArrayLength {
			return errors.New("INTENT_ARRAY_TOO_LARGE")
		}
		for _, child := range typed {
			*entries++
			if *entries > MaxEntries {
				return errors.New("INTENT_TOO_COMPLEX")
			}
			if err := assertBounded(child, depth+1, entries); err != nil {
				return err
			}
		}
	case map[string]any:
		for key, child := range typed {
			if forbiddenKeys[key] {
				return errors.New("UNSAFE_INTENT_KEY")
			}
			*entries++
			if *entries > MaxEntries {
				return errors.New("INTENT_TOO_COMPLEX")
			}
			if err := assertBounded(child, depth+1, entries); err != nil {
				return err
			}
		}
	}
	return nil
}

func boundedIdentifier(name, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > 200 {
		return fmt.Errorf("%s: empty or longer than 200 characters", strings.ToUpper(strings.NewReplacer(".", "_").Replace(name))+"_INVALID")
	}
	return nil
}

// randomUUID is a version 4 UUID from the operating system's randomness.
func randomUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("RANDOMNESS_UNAVAILABLE: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
