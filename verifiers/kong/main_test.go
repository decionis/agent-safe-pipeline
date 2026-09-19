package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kong/go-pdk/test"
	"github.com/decionis/agent-safe-pipeline/verifiers/envoy/verifier"
)

type vectorRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    *string           `json:"body"`
	Expect  struct {
		Outcome    string `json:"outcome"`
		ReasonCode string `json:"reason_code"`
	} `json:"expect"`
}

type vector struct {
	Provider struct {
		Now             string `json:"now"`
		AuthorityIssuer string `json:"authority_issuer"`
		Effects         bool   `json:"effects"`
	} `json:"provider"`
	ExecutorKeys  json.RawMessage `json:"executor_keys"`
	AuthorityJWKS json.RawMessage `json:"authority_jwks"`
	Requests      []vectorRequest `json:"requests"`
}

func loadVector(t *testing.T, name string) vector {
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		candidate := filepath.Join(directory, "conformance", "provider", "vectors", name+".json")
		if raw, err := os.ReadFile(candidate); err == nil {
			var v vector
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			return v
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatalf("vector %s not found above this module", name)
		}
		directory = parent
	}
}

// A plugin configured the way Kong configures one, from the vector's keys,
// with the vector's clock.
func configFor(t *testing.T, v vector) *Config {
	directory := t.TempDir()
	keysFile := filepath.Join(directory, "executor-keys.json")
	jwksFile := filepath.Join(directory, "jwks.json")
	if err := os.WriteFile(keysFile, v.ExecutorKeys, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jwksFile, v.AuthorityJWKS, 0o600); err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, v.Provider.Now)
	if err != nil {
		t.Fatal(err)
	}
	effects := v.Provider.Effects
	return &Config{
		ExecutorKeysFile: keysFile,
		AuthorityJWKS:    jwksFile,
		AuthorityIssuer:  v.Provider.AuthorityIssuer,
		Effects:          &effects,
		replay:           verifier.NewMemoryReplayStore(func() time.Time { return now }),
		now:              func() time.Time { return now },
	}
}

func access(t *testing.T, conf *Config, request vectorRequest) test.Response {
	headers := http.Header{}
	for name, value := range request.Headers {
		headers.Set(name, value)
	}
	var body []byte
	if request.Body != nil {
		body = []byte(*request.Body)
	}
	env, err := test.New(t, test.Request{Method: request.Method, Url: "http://provider.invalid" + request.Path + "?trace=1", Headers: headers, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	env.DoAccess(conf)
	return env.ClientRes
}

func TestThePluginAnswersTheVectorsOutcomes(t *testing.T) {
	for _, name := range []string{"dispatch-replayed-within-lease", "payload-changed-after-claim", "copied-headers-unsigned", "read-base-components-accepts-for-read"} {
		v := loadVector(t, name)
		conf := configFor(t, v)
		for index, request := range v.Requests {
			response := access(t, conf, request)
			switch request.Expect.Outcome {
			case "ACCEPT":
				// An accepted request is not answered by the plugin: Kong proxies it.
				if response.Status != 0 && response.Status != http.StatusOK {
					t.Fatalf("%s request %d: %d %s", name, index, response.Status, response.Body)
				}
			case "REFUSE":
				if response.Status != http.StatusConflict {
					t.Fatalf("%s request %d: %d %s", name, index, response.Status, response.Body)
				}
				var refusal map[string]string
				if err := json.Unmarshal(response.Body, &refusal); err != nil {
					t.Fatal(err)
				}
				if refusal["status"] != "REJECTED" || refusal["reason_code"] != request.Expect.ReasonCode {
					t.Fatalf("%s request %d: %v", name, index, refusal)
				}
				if response.Headers.Get("Content-Type") != "application/json" {
					t.Fatalf("%s request %d: content-type %q", name, index, response.Headers.Get("Content-Type"))
				}
			}
		}
	}
}

func TestThePluginRefusesACoveredHeaderReceivedTwiceAndABodyBeyondTheBound(t *testing.T) {
	v := loadVector(t, "dispatch-attested-accepts")
	request := v.Requests[0]
	conf := configFor(t, v)
	headers := http.Header{}
	for name, value := range request.Headers {
		headers.Set(name, value)
	}
	headers.Add("x-agent-safe-grant-id", request.Headers["x-agent-safe-grant-id"])
	env, err := test.New(t, test.Request{Method: request.Method, Url: "http://provider.invalid" + request.Path, Headers: headers, Body: []byte(*request.Body)})
	if err != nil {
		t.Fatal(err)
	}
	env.DoAccess(conf)
	if env.ClientRes.Status != http.StatusConflict || !strings.Contains(string(env.ClientRes.Body), verifier.SignatureInvalidOrIncomplete) {
		t.Fatalf("twice: %d %s", env.ClientRes.Status, env.ClientRes.Body)
	}
	bounded := configFor(t, v)
	bounded.MaxBodyBytes = 8
	response := access(t, bounded, request)
	if response.Status != http.StatusRequestEntityTooLarge || !strings.Contains(string(response.Body), "BODY_BEYOND_BOUND") {
		t.Fatalf("bound: %d %s", response.Status, response.Body)
	}
}

func TestAMisconfiguredPluginRefusesEverything(t *testing.T) {
	v := loadVector(t, "dispatch-attested-accepts")
	conf := &Config{}
	response := access(t, conf, v.Requests[0])
	if response.Status != http.StatusServiceUnavailable || !strings.Contains(string(response.Body), "VERIFIER_NOT_CONFIGURED") {
		t.Fatalf("%d %s", response.Status, response.Body)
	}
}

// A plugin that also signs receipts: the vector's verifier configuration,
// and a receipt key made for the test, registered under a known kid.
func receiptConfigFor(t *testing.T, v vector) (*Config, ed25519.PublicKey) {
	conf := configFor(t, v)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "receipt-key.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatal(err)
	}
	conf.ReceiptKeyFile = keyFile
	conf.ReceiptKid = "kong-receipts-1"
	conf.ReceiptIssuer = "https://core.example"
	conf.receiptJTI = func() string { return "test-receipt-1" }
	return conf, public
}

// One request through the access phase, then the upstream's answer through
// the response phase.
func roundTrip(t *testing.T, conf *Config, request vectorRequest, upstream test.Response) *test.TestEnv {
	headers := http.Header{}
	for name, value := range request.Headers {
		headers.Set(name, value)
	}
	var body []byte
	if request.Body != nil {
		body = []byte(*request.Body)
	}
	env, err := test.New(t, test.Request{Method: request.Method, Url: "http://provider.invalid" + request.Path, Headers: headers, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	env.DoAccess(conf)
	env.ServiceRes = upstream
	env.DoResponse(conf)
	return env
}

func decodeSegment(t *testing.T, segment string) map[string]any {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestTheResponsePhaseSignsAReceiptUnderTheClaimTheAccessPhaseVerified(t *testing.T) {
	v := loadVector(t, "dispatch-attested-accepts")
	request := v.Requests[0]
	conf, public := receiptConfigFor(t, v)
	upstream := test.Response{
		Status: http.StatusCreated,
		Headers: http.Header{
			"Content-Type":                  {"application/json"},
			"X-Agent-Safe-Effect-Status":    {"EFFECTED"},
			"X-Agent-Safe-Effect-Reference": {"ledger:entry:9081"},
			"X-Agent-Safe-Effect-Digest":    {"sha256:" + strings.Repeat("a", 64)},
			"X-Agent-Safe-Effected-At":      {"2026-09-19T12:00:01Z"},
		},
		Body: []byte(`{"posted":true}`),
	}
	env := roundTrip(t, conf, request, upstream)
	token := env.ClientRes.Headers.Get(verifier.ReceiptHeader)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("no receipt on the answer: %q", token)
	}
	// The receipt is the hop's signature, under the registered kid.
	header := decodeSegment(t, parts[0])
	if header["alg"] != "EdDSA" || header["typ"] != verifier.ReceiptType || header["kid"] != "kong-receipts-1" {
		t.Fatalf("header %v", header)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("the receipt does not verify under the hop's key")
	}
	// It answers exactly the claim the access phase verified: the
	// attestation's grant, decision, dossier, claim-token digest and id.
	attestationParts := strings.Split(request.Headers["x-agent-safe-claim-attestation"], ".")
	attestation := decodeSegment(t, attestationParts[1])
	claims := decodeSegment(t, parts[1])
	for receipt, attested := range map[string]string{"sub": "sub", "decision_id": "decision_id", "dossier_id": "dossier_id", "claim_token_digest": "claim_token_digest", "attestation_jti": "jti"} {
		if claims[receipt] != attestation[attested] {
			t.Fatalf("%s: %v != %v", receipt, claims[receipt], attestation[attested])
		}
	}
	if claims["intent_hash"] != attestation["binding"].(map[string]any)["intent_hash"] {
		t.Fatalf("intent_hash %v", claims["intent_hash"])
	}
	if claims["iss"] != "https://core.example" || claims["aud"] != v.Provider.AuthorityIssuer || claims["jti"] != "test-receipt-1" {
		t.Fatalf("issuer, audience or jti: %v", claims)
	}
	if claims["idempotency_key"] != request.Headers["idempotency-key"] {
		t.Fatalf("idempotency_key %v", claims["idempotency_key"])
	}
	effect := claims["effect"].(map[string]any)
	if effect["status"] != "EFFECTED" || effect["reference"] != "ledger:entry:9081" ||
		effect["digest"] != "sha256:"+strings.Repeat("a", 64) || effect["effected_at"] != "2026-09-19T12:00:01.000Z" {
		t.Fatalf("effect %v", effect)
	}
	// The upstream's report never leaves the hop; the receipt stands in its place.
	for _, name := range []string{effectStatusHeader, effectReferenceHeader, effectDigestHeader, effectedAtHeader} {
		if env.ClientRes.Headers.Get(name) != "" {
			t.Fatalf("%s left the hop", name)
		}
	}
	if env.ClientRes.Status != http.StatusCreated || string(env.ClientRes.Body) != `{"posted":true}` {
		t.Fatalf("the answer changed: %d %s", env.ClientRes.Status, env.ClientRes.Body)
	}
}

func TestTheResponsePhaseReadsTheEffectFromTheStatusWhenTheUpstreamReportsNothing(t *testing.T) {
	v := loadVector(t, "dispatch-attested-accepts")
	for status, expected := range map[int]string{http.StatusOK: verifier.Effected, http.StatusUnprocessableEntity: verifier.Refused, http.StatusBadGateway: verifier.Indeterminate} {
		conf, _ := receiptConfigFor(t, v)
		env := roundTrip(t, conf, v.Requests[0], test.Response{Status: status, Headers: http.Header{}})
		parts := strings.Split(env.ClientRes.Headers.Get(verifier.ReceiptHeader), ".")
		if len(parts) != 3 {
			t.Fatalf("%d: no receipt", status)
		}
		effect := decodeSegment(t, parts[1])["effect"].(map[string]any)
		if effect["status"] != expected {
			t.Fatalf("%d: %v", status, effect)
		}
		if _, present := effect["reference"]; present {
			t.Fatalf("%d: a reference was invented", status)
		}
		if _, present := effect["digest"]; present {
			t.Fatalf("%d: a digest was invented", status)
		}
		// The clock is the plugin's when the upstream names no instant.
		if effect["effected_at"] != "2026-09-19T12:00:00.000Z" {
			t.Fatalf("%d: effected_at %v", status, effect["effected_at"])
		}
	}
}

func TestTheResponsePhaseSignsNothingForARefusedDispatchAReadOrAnUnsignedPlugin(t *testing.T) {
	// A dispatch the access phase refused: nothing was claimed of the hop.
	refused := loadVector(t, "payload-changed-after-claim")
	conf, _ := receiptConfigFor(t, refused)
	env := roundTrip(t, conf, refused.Requests[0], test.Response{Status: http.StatusOK, Headers: http.Header{}})
	if env.ClientRes.Headers.Get(verifier.ReceiptHeader) != "" {
		t.Fatal("a refused dispatch was receipted")
	}
	// A read verified at VP-1 alone: there is no claim to answer.
	read := loadVector(t, "read-base-components-accepts-for-read")
	conf, _ = receiptConfigFor(t, read)
	env = roundTrip(t, conf, read.Requests[0], test.Response{Status: http.StatusOK, Headers: http.Header{}})
	if env.ClientRes.Headers.Get(verifier.ReceiptHeader) != "" {
		t.Fatal("a read was receipted")
	}
	// No receipt key: the hop verifies and signs nothing, and the upstream's
	// report is left as it was.
	accepted := loadVector(t, "dispatch-attested-accepts")
	unsigned := configFor(t, accepted)
	env = roundTrip(t, unsigned, accepted.Requests[0], test.Response{Status: http.StatusOK, Headers: http.Header{"X-Agent-Safe-Effect-Status": {"EFFECTED"}}})
	if env.ClientRes.Headers.Get(verifier.ReceiptHeader) != "" || env.ClientRes.Headers.Get(effectStatusHeader) != "EFFECTED" {
		t.Fatal("an unsigned plugin touched the answer")
	}
}

func TestTheResponsePhaseLeavesTheUpstreamsOwnReceiptAlone(t *testing.T) {
	v := loadVector(t, "dispatch-attested-accepts")
	conf, _ := receiptConfigFor(t, v)
	own := "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJnMSJ9.c2ln"
	env := roundTrip(t, conf, v.Requests[0], test.Response{Status: http.StatusOK, Headers: http.Header{
		"X-Agent-Safe-Effect-Receipt": {own},
		"X-Agent-Safe-Effect-Status":  {"EFFECTED"},
	}})
	if env.ClientRes.Headers.Get(verifier.ReceiptHeader) != own {
		t.Fatal("the hop replaced the system of record's own receipt")
	}
}

func TestAReceiptKeyWithoutItsRegistrationRefusesEverything(t *testing.T) {
	v := loadVector(t, "dispatch-attested-accepts")
	conf, _ := receiptConfigFor(t, v)
	conf.ReceiptKid = ""
	response := access(t, conf, v.Requests[0])
	if response.Status != http.StatusServiceUnavailable || !strings.Contains(string(response.Body), "VERIFIER_NOT_CONFIGURED") {
		t.Fatalf("%d %s", response.Status, response.Body)
	}
	broken, _ := receiptConfigFor(t, v)
	if err := os.WriteFile(broken.ReceiptKeyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	response = access(t, broken, v.Requests[0])
	if response.Status != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", response.Status, response.Body)
	}
}
