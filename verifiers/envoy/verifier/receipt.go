package verifier

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/gowebpki/jcs"
)

// ReceiptType is the protected header `typ` of an effect receipt, and
// ReceiptHeader the response header it travels in (the profile, VP-3).
const (
	ReceiptType   = "decionis-effect-receipt+jwt"
	ReceiptHeader = "x-agent-safe-effect-receipt"
)

// The effect statuses a receipt can report. A signed refusal is evidence too.
const (
	Effected      = "EFFECTED"
	Refused       = "REFUSED"
	Indeterminate = "INDETERMINATE"
)

var sha256Digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Effect is what the provider did with the claimed request.
type Effect struct {
	Status string
	// The provider's own reference for the effect; empty for none.
	Reference string
	// The digest of the effect in the grant's terms (expected_effect_digest);
	// empty for none. Equality is what confirms the effect at the authority.
	Digest string
	// When the effect took place.
	EffectedAt time.Time
}

// Receipt is everything a provider signs after effecting, or refusing, a
// claimed request: the attestation it verified, which names the grant, the
// decision, the dossier and the claim answered; and the effect. The header
// and the payload are serialised in RFC 8785 canonical form, so every
// implementation of the profile signs the same bytes for the same receipt.
type Receipt struct {
	// The `kid` the organisation registered the key under at the authority.
	KeyID string
	// The `iss` registered with the key.
	Issuer string
	// The authority the receipt is for: its issuer, https://decionis.com for the hosted one.
	Audience string
	// The claims of the attestation this provider verified, as Verify returned them.
	Attestation *Claims
	// The idempotency key of the request effected; empty for none.
	IdempotencyKey string
	Effect         Effect
	// `iat`, as an epoch second.
	IssuedAt int64
	// Unique per receipt.
	JTI string
}

// Claims returns the payload of the receipt as the authority reads it.
func (r Receipt) Claims() (map[string]any, error) {
	if r.Effect.Status != Effected && r.Effect.Status != Refused && r.Effect.Status != Indeterminate {
		return nil, errors.New("EFFECT_STATUS_UNKNOWN")
	}
	if r.Effect.Digest != "" && !sha256Digest.MatchString(r.Effect.Digest) {
		return nil, errors.New("EFFECT_DIGEST_MALFORMED")
	}
	if r.Effect.EffectedAt.IsZero() {
		return nil, errors.New("EFFECTED_AT_MALFORMED")
	}
	if r.IssuedAt < 0 {
		return nil, errors.New("ISSUED_AT_MALFORMED")
	}
	if r.Attestation == nil {
		return nil, errors.New("ATTESTATION_MISSING")
	}
	for name, value := range map[string]string{
		"KID": r.KeyID, "ISSUER": r.Issuer, "AUDIENCE": r.Audience, "JTI": r.JTI,
	} {
		if value == "" {
			return nil, errors.New(name + "_EMPTY")
		}
	}
	effect := map[string]any{
		"status":      r.Effect.Status,
		"effected_at": r.Effect.EffectedAt.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
	}
	if r.Effect.Reference != "" {
		effect["reference"] = r.Effect.Reference
	}
	if r.Effect.Digest != "" {
		effect["digest"] = r.Effect.Digest
	}
	claims := map[string]any{
		"iss":                r.Issuer,
		"aud":                r.Audience,
		"sub":                r.Attestation.Sub,
		"decision_id":        r.Attestation.DecisionID,
		"dossier_id":         r.Attestation.DossierID,
		"claim_token_digest": r.Attestation.ClaimTokenDigest,
		"attestation_jti":    r.Attestation.JTI,
		"intent_hash":        r.Attestation.Binding.IntentHash,
		"effect":             effect,
		"iat":                r.IssuedAt,
		"jti":                r.JTI,
	}
	if r.IdempotencyKey != "" {
		claims["idempotency_key"] = r.IdempotencyKey
	}
	return claims, nil
}

// SigningInput is the `header.payload` the signature covers: both segments
// RFC 8785 canonical, base64url without padding.
func (r Receipt) SigningInput() (string, error) {
	claims, err := r.Claims()
	if err != nil {
		return "", err
	}
	header, err := canonicalSegment(map[string]any{"alg": "EdDSA", "kid": r.KeyID, "typ": ReceiptType})
	if err != nil {
		return "", err
	}
	payload, err := canonicalSegment(claims)
	if err != nil {
		return "", err
	}
	return header + "." + payload, nil
}

// Sign returns the receipt as a compact EdDSA JWS under the provider's key,
// the value of the x-agent-safe-effect-receipt response header.
func (r Receipt) Sign(key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("KEY_NOT_ED25519")
	}
	signingInput, err := r.SigningInput()
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(key, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func canonicalSegment(value map[string]any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Transform(encoded)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(canonical), nil
}
