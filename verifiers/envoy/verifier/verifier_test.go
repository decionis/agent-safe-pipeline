package verifier

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type vectorKey struct {
	KeyID          string `json:"keyid"`
	Alg            string `json:"alg"`
	PublicPEM      string `json:"public_pem"`
	SharedMaterial string `json:"shared_material_utf8"`
}

type vectorRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    *string           `json:"body"`
	// The provider's own read of the target, for step 9: absent for none,
	// null when it no longer exists.
	TargetVersion json.RawMessage `json:"target_version"`
	Expect        struct {
		Outcome    string `json:"outcome"`
		ReasonCode string `json:"reason_code"`
		// The version the attestation names, handed back on an acceptance or
		// a step 9 refusal.
		ExpectedStateVersion *string `json:"expected_state_version"`
	} `json:"expect"`
}

func (request vectorRequest) received() Request {
	var body []byte
	if request.Body != nil {
		body = []byte(*request.Body)
	}
	return Request{Method: request.Method, Path: request.Path, Body: body, Headers: request.Headers}
}

func (request vectorRequest) target(t *testing.T) *Target {
	if request.TargetVersion == nil {
		return nil
	}
	var version *string
	if err := json.Unmarshal(request.TargetVersion, &version); err != nil {
		t.Fatal(err)
	}
	return &Target{Version: version}
}

type vector struct {
	Profile  string `json:"profile"`
	Version  string `json:"version"`
	Vector   string `json:"vector"`
	Level    string `json:"level"`
	Provider struct {
		Effects            bool   `json:"effects"`
		ClockWindowSeconds int    `json:"clock_window_seconds"`
		Now                string `json:"now"`
		AuthorityIssuer    string `json:"authority_issuer"`
	} `json:"provider"`
	ExecutorKeys  []vectorKey     `json:"executor_keys"`
	AuthorityJWKS JWKS            `json:"authority_jwks"`
	Requests      []vectorRequest `json:"requests"`
}

// The vectors live at the repository root; walk up to them from this package.
func vectorsDirectory(t *testing.T) string {
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		candidate := filepath.Join(directory, "conformance", "provider", "vectors")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("conformance/provider/vectors not found above this package")
		}
		directory = parent
	}
}

func executorKey(t *testing.T, key vectorKey) ExecutorKey {
	switch key.Alg {
	case "ed25519":
		block, _ := pem.Decode([]byte(key.PublicPEM))
		if block == nil {
			t.Fatalf("%s: not PEM", key.KeyID)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		public, ok := parsed.(ed25519.PublicKey)
		if !ok {
			t.Fatalf("%s: not an Ed25519 key", key.KeyID)
		}
		return ExecutorKey{KeyID: key.KeyID, Algorithm: "ed25519", PublicKey: public}
	case "hmac-sha256":
		return ExecutorKey{KeyID: key.KeyID, Algorithm: "hmac-sha256", Secret: []byte(key.SharedMaterial)}
	default:
		t.Fatalf("%s: unknown algorithm %q", key.KeyID, key.Alg)
		return ExecutorKey{}
	}
}

func readVector(t *testing.T, file string) vector {
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return v
}

// A provider at the vector's instant, with the vector's keys and a replay
// store of its own.
func optionsFor(t *testing.T, v vector) Options {
	now, err := time.Parse(time.RFC3339Nano, v.Provider.Now)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]ExecutorKey, 0, len(v.ExecutorKeys))
	for _, key := range v.ExecutorKeys {
		keys = append(keys, executorKey(t, key))
	}
	return Options{
		Effects:         v.Provider.Effects,
		ExecutorKeys:    keys,
		AuthorityJWKS:   v.AuthorityJWKS,
		AuthorityIssuer: v.Provider.AuthorityIssuer,
		ClockWindow:     time.Duration(v.Provider.ClockWindowSeconds) * time.Second,
		Replay:          NewMemoryReplayStore(func() time.Time { return now }),
		Now:             func() time.Time { return now },
	}
}

// The version a verdict's attestation names, or nil when it names none or
// the verdict carries no attestation.
func stateVersion(verdict Verdict) *string {
	if verdict.Attestation == nil {
		return nil
	}
	return verdict.Attestation.Binding.ExpectedStateVersion
}

func sameVersion(got, want *string) bool {
	if got == nil || want == nil {
		return got == want
	}
	return *got == *want
}

func TestVectors(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(vectorsDirectory(t), "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 20 {
		t.Fatalf("found %d vectors", len(files))
	}
	for _, file := range files {
		v := readVector(t, file)
		t.Run(v.Vector, func(t *testing.T) {
			if v.Profile != "agent-safe.verifying-provider/1" || v.Version != "0.1" {
				t.Fatalf("profile %s version %s", v.Profile, v.Version)
			}
			options := optionsFor(t, v)
			for index, request := range v.Requests {
				verdict := Verify(request.received(), options, request.target(t))
				switch request.Expect.Outcome {
				case "ACCEPT":
					if !verdict.Accepted || verdict.ReasonCode != "" {
						t.Fatalf("request %d: expected ACCEPT, got %+v", index, verdict)
					}
					if v.Provider.Effects && verdict.Attestation == nil {
						t.Fatalf("request %d: an accepted dispatch carries its attestation", index)
					}
				case "REFUSE":
					if verdict.Accepted || verdict.ReasonCode != request.Expect.ReasonCode {
						t.Fatalf("request %d: expected %s, got %+v", index, request.Expect.ReasonCode, verdict)
					}
					// Only the provider's own refusal at step 9 hands the claims back.
					if (verdict.Attestation != nil) != (verdict.ReasonCode == TargetStateChanged) {
						t.Fatalf("request %d: %s with attestation %+v", index, verdict.ReasonCode, verdict.Attestation)
					}
				default:
					t.Fatalf("request %d: unknown outcome %q", index, request.Expect.Outcome)
				}
				if !sameVersion(stateVersion(verdict), request.Expect.ExpectedStateVersion) {
					t.Fatalf("request %d: expected_state_version %v, want %v", index, stateVersion(verdict), request.Expect.ExpectedStateVersion)
				}
			}
		})
	}
}

func TestStepNineHoldsTheEffectToTheVersionTheGrantWasDecidedOn(t *testing.T) {
	v := readVector(t, filepath.Join(vectorsDirectory(t), "state-version-unchanged-accepts.json"))
	request := v.Requests[0].received()
	decided, other, weak := `"17"`, `"18"`, `W/"17"`
	accepted := Verify(request, optionsFor(t, v), nil)
	if !accepted.Accepted || !sameVersion(stateVersion(accepted), &decided) {
		t.Fatalf("no target: %+v", accepted)
	}
	if same := Verify(request, optionsFor(t, v), &Target{Version: &decided}); !reflect.DeepEqual(same, accepted) {
		t.Fatalf("the same version: %+v", same)
	}
	for name, target := range map[string]*Target{
		"another version":                {Version: &other},
		"the weak tag of the same value": {Version: &weak},
		"a target that no longer exists": {},
	} {
		options := optionsFor(t, v)
		refused := Verify(request, options, target)
		if refused.Accepted || refused.ReasonCode != TargetStateChanged || !reflect.DeepEqual(refused.Attestation, accepted.Attestation) {
			t.Errorf("%s: %+v", name, refused)
		}
		// The presentation was recorded before the target refused it: the grant is spent.
		if again := Verify(request, options, &Target{Version: &decided}); again.ReasonCode != GrantReplayed {
			t.Errorf("%s: presented again, %+v", name, again)
		}
	}
}

func TestStepNineIgnoresTheTargetWhenTheAttestationNamesNoVersion(t *testing.T) {
	v := readVector(t, filepath.Join(vectorsDirectory(t), "dispatch-attested-accepts.json"))
	other := `"18"`
	for name, target := range map[string]*Target{"another version": {Version: &other}, "a target that no longer exists": {}} {
		verdict := Verify(v.Requests[0].received(), optionsFor(t, v), target)
		if !verdict.Accepted || verdict.Attestation == nil || stateVersion(verdict) != nil {
			t.Errorf("%s: %+v", name, verdict)
		}
	}
}

func TestCanonicalDigestRefusesWhatOtherParsersReadDifferently(t *testing.T) {
	for _, body := range []string{
		`{"a":1,"a":2}`,
		`{"x":{"a":1,"b":2,"a":3}}`,
		`{"x":[1,{"a":1,"a":2}]}`,
		`{"a":1,"a":2}`,
		`{"a":"\udc00"}`,
		`{"a":"\ud83d"}`,
		`{"a":"\ud83d\ud83d"}`,
		`{"a":"\udc00\ud83d"}`,
		`{"a":"\ud83dx"}`,
		`{"a":1} {"b":2}`,
		`not json`,
		"\xff",
		``,
		`5`,
		`"a"`,
		`[1]`,
		` [{"a":1}]`,
	} {
		if _, err := CanonicalDigest([]byte(body)); err == nil {
			t.Errorf("%q: expected a refusal", body)
		}
	}
	for _, body := range []string{
		`{"a":1,"b":{"a":2},"c":[{"a":3},{"a":4}],"d":[],"e":{}}`,
		`{"a":"🚀","b":"\\ud83d","c":"\\\\uDC00"}`,
		`{"a":"\"","a2":"\\"}`,
		` {"a":1}`,
	} {
		if _, err := CanonicalDigest([]byte(body)); err != nil {
			t.Errorf("%q: %v", body, err)
		}
	}
}

func TestCanonicalDigestIsOverTheCanonicalForm(t *testing.T) {
	spaced, err := CanonicalDigest([]byte("{\n  \"b\": 1,\n  \"a\": [1.50, 1e21, -0]\n}"))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := CanonicalDigest([]byte(`{"a":[1.5,1e+21,0],"b":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if spaced != compact {
		t.Fatalf("%s != %s", spaced, compact)
	}
}

func TestMemoryReplayStore(t *testing.T) {
	now := time.Unix(1_789_819_200, 0)
	store := NewMemoryReplayStore(func() time.Time { return now })
	if !store.Record("g", now.Add(time.Second)) {
		t.Fatal("first presentation")
	}
	if store.Record("g", now.Add(time.Second)) {
		t.Fatal("second presentation")
	}
	now = now.Add(999 * time.Millisecond)
	if store.Record("g", now.Add(5*time.Second)) {
		t.Fatal("still inside the lease")
	}
	now = now.Add(time.Millisecond)
	if !store.Record("g", now.Add(5*time.Second)) {
		t.Fatal("lease ended")
	}
}
