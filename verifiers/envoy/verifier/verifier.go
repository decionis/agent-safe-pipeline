// Package verifier is an independent implementation of the Verifying
// Provider Profile (docs/authority/verifying-provider.md in the
// agent-safe-pipeline repository), VP-1 and VP-2, written against the
// profile's text and held to its vectors. It shares no code with the
// executor; that is the point of a second implementation.
package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

// The refusal codes the profile names.
const (
	SignatureInvalidOrIncomplete          = "SIGNATURE_INVALID_OR_INCOMPLETE"
	AttestationInvalid                    = "ATTESTATION_INVALID"
	AttestationDoesNotDescribeThisRequest = "ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST"
	GrantReplayed                         = "GRANT_REPLAYED"
)

const (
	// AttestationType is the protected header typ of a claim attestation.
	AttestationType = "decionis-claim-attestation+jwt"
	// JCSProfile is the one canonicalization profile this version defines.
	JCSProfile = "RFC8785/JCS"
	label      = "agentsafe"
)

var (
	baseComponents  = []string{"@method", "@path", "content-digest", "idempotency-key", "x-agent-safe-intent-hash"}
	grantComponents = []string{"x-agent-safe-grant-id", "x-agent-safe-decision-id", "x-agent-safe-claim-attestation"}
	known           = append(append([]string{}, baseComponents...), grantComponents...)
	createdParam    = regexp.MustCompile(`;created=(\d{1,12})(?:;|$)`)
	keyIDParam      = regexp.MustCompile(`;keyid="([^"]*)"(?:;|$)`)
	algParam        = regexp.MustCompile(`;alg="([a-z0-9-]+)"(?:;|$)`)
	signatureValue  = regexp.MustCompile(`^agentsafe=:(.*):$`)
)

// ExecutorKey is a key the provider issued to, or registered for, the
// executor, by the keyid a signature names. Exactly one of PublicKey and
// Secret is set, by Algorithm: "ed25519" or "hmac-sha256".
type ExecutorKey struct {
	KeyID     string
	Algorithm string
	PublicKey ed25519.PublicKey
	Secret    []byte
}

// JWK is one key of the authority's execution-grant JWKS, as served.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// JWKS is the authority's execution-grant key set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// ReplayStore keeps the grants a provider accepted until their attestation
// expires. Record answers true when the grant was not there and is now, and
// false when it was: the second presentation. The profile's step 8.
type ReplayStore interface {
	Record(grantID string, expiresAt time.Time) bool
}

// Options configures a provider.
type Options struct {
	// Effects says whether this endpoint effects anything; an effecting
	// provider requires all eight components covered.
	Effects         bool
	ExecutorKeys    []ExecutorKey
	AuthorityJWKS   JWKS
	AuthorityIssuer string
	// ClockWindow is how far `created` may lie from now, each way.
	ClockWindow time.Duration
	Replay      ReplayStore
	Now         func() time.Time
}

// Request is what the provider received. Header names are lower case; a
// covered header received more than once is a refusal and must not be
// collapsed into this map. Body is nil when the request carried none.
type Request struct {
	Method  string
	Path    string
	Body    []byte
	Headers map[string]string
}

// Binding is the part of the attestation's binding the provider reads.
type Binding struct {
	IntentHash                              string `json:"intent_hash"`
	ExecutionPayloadDigest                  string `json:"execution_payload_digest"`
	ExecutionPayloadCanonicalizationProfile string `json:"execution_payload_canonicalization_profile"`
}

// Claims is the part of the attestation the provider reads; the authority's
// schema has more.
type Claims struct {
	Iss        string  `json:"iss"`
	Sub        string  `json:"sub"`
	DecisionID string  `json:"decision_id"`
	Binding    Binding `json:"binding"`
	Exp        float64 `json:"exp"`
}

// Verdict is the outcome of the procedure for one request. Attestation is
// set on an accepted dispatch, and nil for a read a non-effecting provider
// verified at VP-1 alone.
type Verdict struct {
	Accepted    bool
	ReasonCode  string
	Attestation *Claims
}

func refuse(code string) Verdict { return Verdict{ReasonCode: code} }

// Verify runs the whole procedure for one received request.
func Verify(request Request, options Options) Verdict {
	now := time.Now
	if options.Now != nil {
		now = options.Now
	}
	nowSeconds := now().Unix()
	if !signatureHolds(request, options, nowSeconds) {
		return refuse(SignatureInvalidOrIncomplete)
	}
	if !options.Effects {
		return Verdict{Accepted: true}
	}
	raw, err := attestationOf(request.Headers["x-agent-safe-claim-attestation"], options)
	if err != nil {
		return refuse(AttestationInvalid)
	}
	claims, err := described(raw, request, nowSeconds)
	if err != nil {
		return refuse(AttestationDoesNotDescribeThisRequest)
	}
	if !options.Replay.Record(claims.Sub, time.Unix(int64(claims.Exp), 0)) {
		return refuse(GrantReplayed)
	}
	return Verdict{Accepted: true, Attestation: claims}
}

// ContentDigest is the RFC 9530 value the executor sends for a body, the
// empty body included.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// Steps 0 to 5.
func signatureHolds(request Request, options Options, nowSeconds int64) bool {
	input, ok := request.Headers["signature-input"]
	if !ok || !strings.HasPrefix(input, label+"=") {
		return false
	}
	parameters := strings.TrimPrefix(input, label+"=")
	encoded := signatureValue.FindStringSubmatch(request.Headers["signature"])
	if encoded == nil {
		return false
	}
	if request.Headers["content-digest"] != ContentDigest(request.Body) {
		return false
	}
	covered := coveredComponents(parameters)
	if covered == nil {
		return false
	}
	required := baseComponents
	if options.Effects {
		required = known
	}
	for _, component := range required {
		if !contains(covered, component) {
			return false
		}
	}
	created, err := strconv.ParseInt(submatch(createdParam, parameters), 10, 64)
	if err != nil {
		return false
	}
	window := int64(options.ClockWindow / time.Second)
	if created < nowSeconds-window || created > nowSeconds+window {
		return false
	}
	keyID := submatch(keyIDParam, parameters)
	algorithm := submatch(algParam, parameters)
	var key *ExecutorKey
	for index := range options.ExecutorKeys {
		if options.ExecutorKeys[index].KeyID == keyID && options.ExecutorKeys[index].Algorithm == algorithm {
			key = &options.ExecutorKeys[index]
			break
		}
	}
	if key == nil {
		return false
	}
	base, ok := signatureBase(request, covered, parameters)
	if !ok {
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(encoded[1])
	if err != nil {
		return false
	}
	switch key.Algorithm {
	case "ed25519":
		return len(key.PublicKey) == ed25519.PublicKeySize && ed25519.Verify(key.PublicKey, base, signature)
	case "hmac-sha256":
		mac := hmac.New(sha256.New, key.Secret)
		mac.Write(base)
		return hmac.Equal(mac.Sum(nil), signature)
	default:
		return false
	}
}

// The covered components a signature-input names, or nil when the list is
// not one, names a component this profile does not know, or names one twice.
func coveredComponents(parameters string) []string {
	if !strings.HasPrefix(parameters, "(") {
		return nil
	}
	end := strings.IndexByte(parameters, ')')
	if end < 0 {
		return nil
	}
	inner := parameters[1:end]
	if inner == "" {
		return []string{}
	}
	names := strings.Split(inner, " ")
	seen := map[string]bool{}
	for index, quoted := range names {
		if len(quoted) < 3 || quoted[0] != '"' || quoted[len(quoted)-1] != '"' {
			return nil
		}
		name := quoted[1 : len(quoted)-1]
		if !contains(known, name) || seen[name] {
			return nil
		}
		seen[name] = true
		names[index] = name
	}
	return names
}

// The base, exactly as both sides build it.
func signatureBase(request Request, covered []string, parameters string) ([]byte, bool) {
	lines := make([]string, 0, len(covered)+1)
	for _, component := range covered {
		var value string
		switch component {
		case "@method":
			value = strings.ToUpper(request.Method)
		case "@path":
			value = request.Path
		case "content-digest":
			value = ContentDigest(request.Body)
		default:
			header, ok := request.Headers[component]
			if !ok {
				return nil, false
			}
			value = header
		}
		lines = append(lines, `"`+component+`": `+value)
	}
	lines = append(lines, `"@signature-params": `+parameters)
	return []byte(strings.Join(lines, "\n")), true
}

type protectedHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Step 6: the attestation by form, key, signature and issuer; its claims as
// raw JSON when it is the authority's.
func attestationOf(compact string, options Options) (json.RawMessage, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, errors.New("form")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[0], "="))
	if err != nil {
		return nil, err
	}
	var header protectedHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	if header.Alg != "EdDSA" || header.Typ != AttestationType {
		return nil, errors.New("header")
	}
	var key ed25519.PublicKey
	for _, jwk := range options.AuthorityJWKS.Keys {
		if jwk.Kid == header.Kid && jwk.Kty == "OKP" && jwk.Crv == "Ed25519" {
			x, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(jwk.X, "="))
			if err != nil || len(x) != ed25519.PublicKeySize {
				return nil, errors.New("key")
			}
			key = ed25519.PublicKey(x)
			break
		}
	}
	if key == nil {
		return nil, errors.New("kid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[2], "="))
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return nil, errors.New("signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, err
	}
	var issued struct {
		Iss *string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &issued); err != nil {
		return nil, err
	}
	if issued.Iss == nil || *issued.Iss != options.AuthorityIssuer {
		return nil, errors.New("issuer")
	}
	return json.RawMessage(payload), nil
}

// Step 7: whether the attestation describes this request.
func described(raw json.RawMessage, request Request, nowSeconds int64) (*Claims, error) {
	var shape struct {
		Iss        *string `json:"iss"`
		Sub        *string `json:"sub"`
		DecisionID *string `json:"decision_id"`
		Binding    *struct {
			IntentHash                              *string `json:"intent_hash"`
			ExecutionPayloadDigest                  *string `json:"execution_payload_digest"`
			ExecutionPayloadCanonicalizationProfile *string `json:"execution_payload_canonicalization_profile"`
		} `json:"binding"`
		Exp *float64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return nil, err
	}
	if shape.Iss == nil || shape.Sub == nil || shape.DecisionID == nil || shape.Binding == nil ||
		shape.Binding.IntentHash == nil || shape.Binding.ExecutionPayloadDigest == nil ||
		shape.Binding.ExecutionPayloadCanonicalizationProfile == nil || shape.Exp == nil {
		return nil, errors.New("shape")
	}
	if request.Body == nil {
		return nil, errors.New("no body")
	}
	digest, err := CanonicalDigest(request.Body)
	if err != nil {
		return nil, err
	}
	claims := &Claims{
		Iss:        *shape.Iss,
		Sub:        *shape.Sub,
		DecisionID: *shape.DecisionID,
		Binding: Binding{
			IntentHash:                              *shape.Binding.IntentHash,
			ExecutionPayloadDigest:                  *shape.Binding.ExecutionPayloadDigest,
			ExecutionPayloadCanonicalizationProfile: *shape.Binding.ExecutionPayloadCanonicalizationProfile,
		},
		Exp: *shape.Exp,
	}
	if claims.Sub != request.Headers["x-agent-safe-grant-id"] ||
		claims.DecisionID != request.Headers["x-agent-safe-decision-id"] ||
		claims.Binding.IntentHash != request.Headers["x-agent-safe-intent-hash"] ||
		claims.Binding.ExecutionPayloadCanonicalizationProfile != JCSProfile ||
		claims.Binding.ExecutionPayloadDigest != digest ||
		!(claims.Exp > float64(nowSeconds)) {
		return nil, errors.New("describes another request")
	}
	return claims, nil
}

// CanonicalDigest is "sha256:" and the hex SHA-256 over the RFC 8785
// canonical form of a JSON object, or an error when the text is not one that
// is I-JSON: not valid UTF-8, not an object, a name repeated within one
// object, or a lone surrogate escape, each of which another parser would
// read differently.
func CanonicalDigest(body []byte) (string, error) {
	if !utf8.Valid(body) {
		return "", errors.New("not UTF-8")
	}
	if len(bytes.TrimLeft(body, " \n\r\t")) == 0 || bytes.TrimLeft(body, " \n\r\t")[0] != '{' {
		return "", errors.New("not a JSON object")
	}
	if hasRepeatedName(body) {
		return "", errors.New("repeated name")
	}
	if hasLoneSurrogate(body) {
		return "", errors.New("lone surrogate")
	}
	canonical, err := jcs.Transform(body)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// A name repeated within one object, found by walking the tokens; also true
// for a text that is not JSON at all, which has no canonical form either.
func hasRepeatedName(body []byte) bool {
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	var repeated bool
	var walk func() bool
	walk = func() bool {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		delim, isDelim := token.(json.Delim)
		if !isDelim {
			return true
		}
		switch delim {
		case '{':
			names := map[string]bool{}
			for decoder.More() {
				name, err := decoder.Token()
				if err != nil {
					return false
				}
				text, _ := name.(string)
				if names[text] {
					repeated = true
					return false
				}
				names[text] = true
				if !walk() {
					return false
				}
			}
			_, err := decoder.Token()
			return err == nil
		case '[':
			for decoder.More() {
				if !walk() {
					return false
				}
			}
			_, err := decoder.Token()
			return err == nil
		}
		return false
	}
	if !walk() {
		return true
	}
	if _, err := decoder.Token(); err == nil {
		return true
	}
	return repeated
}

// A \uD800-\uDFFF escape without its partner, read the way a JSON string is
// read, so an escaped backslash before a "u" is not mistaken for one. Go's
// decoder would replace a lone surrogate with U+FFFD and canonicalise
// something the authority never digested. Only strings carry escapes, and
// the grammar was checked before this runs.
func hasLoneSurrogate(body []byte) bool {
	inString := false
	pendingHigh := false
	for index := 0; index < len(body); index++ {
		char := body[index]
		if !inString {
			if char == '"' {
				inString = true
			}
			continue
		}
		unit, isEscape := escapedUnit(body, index)
		switch {
		case isEscape && unit >= 0xD800 && unit <= 0xDBFF:
			if pendingHigh {
				return true
			}
			pendingHigh = true
			index += 5
			continue
		case isEscape && unit >= 0xDC00 && unit <= 0xDFFF:
			if !pendingHigh {
				return true
			}
			pendingHigh = false
			index += 5
			continue
		}
		if pendingHigh {
			return true
		}
		switch {
		case isEscape:
			index += 5
		case char == '\\':
			index++
		case char == '"':
			inString = false
		}
	}
	return pendingHigh
}

// The code unit of a \uXXXX escape starting at index, when there is one.
func escapedUnit(body []byte, index int) (int64, bool) {
	if body[index] != '\\' || index+5 >= len(body) || body[index+1] != 'u' {
		return 0, false
	}
	unit, err := strconv.ParseInt(string(body[index+2:index+6]), 16, 32)
	if err != nil {
		return 0, false
	}
	return unit, true
}

func submatch(pattern *regexp.Regexp, text string) string {
	match := pattern.FindStringSubmatch(text)
	if match == nil {
		return ""
	}
	return match[1]
}

func contains(list []string, item string) bool {
	for _, candidate := range list {
		if candidate == item {
			return true
		}
	}
	return false
}
