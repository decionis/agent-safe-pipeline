package verifier

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
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
	Expect  struct {
		Outcome    string `json:"outcome"`
		ReasonCode string `json:"reason_code"`
	} `json:"expect"`
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

func TestVectors(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(vectorsDirectory(t), "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 20 {
		t.Fatalf("found %d vectors", len(files))
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var v vector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		t.Run(v.Vector, func(t *testing.T) {
			if v.Profile != "agent-safe.verifying-provider/1" || v.Version != "0.1" {
				t.Fatalf("profile %s version %s", v.Profile, v.Version)
			}
			now, err := time.Parse(time.RFC3339Nano, v.Provider.Now)
			if err != nil {
				t.Fatal(err)
			}
			keys := make([]ExecutorKey, 0, len(v.ExecutorKeys))
			for _, key := range v.ExecutorKeys {
				keys = append(keys, executorKey(t, key))
			}
			options := Options{
				Effects:         v.Provider.Effects,
				ExecutorKeys:    keys,
				AuthorityJWKS:   v.AuthorityJWKS,
				AuthorityIssuer: v.Provider.AuthorityIssuer,
				ClockWindow:     time.Duration(v.Provider.ClockWindowSeconds) * time.Second,
				Replay:          NewMemoryReplayStore(func() time.Time { return now }),
				Now:             func() time.Time { return now },
			}
			for index, request := range v.Requests {
				var body []byte
				if request.Body != nil {
					body = []byte(*request.Body)
				}
				verdict := Verify(Request{Method: request.Method, Path: request.Path, Body: body, Headers: request.Headers}, options)
				switch request.Expect.Outcome {
				case "ACCEPT":
					if !verdict.Accepted || verdict.ReasonCode != "" {
						t.Fatalf("request %d: expected ACCEPT, got %+v", index, verdict)
					}
					if v.Provider.Effects && verdict.Attestation == nil {
						t.Fatalf("request %d: an accepted dispatch carries its attestation", index)
					}
				case "REFUSE":
					if verdict.Accepted || verdict.ReasonCode != request.Expect.ReasonCode || verdict.Attestation != nil {
						t.Fatalf("request %d: expected %s, got %+v", index, request.Expect.ReasonCode, verdict)
					}
				default:
					t.Fatalf("request %d: unknown outcome %q", index, request.Expect.Outcome)
				}
			}
		})
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
