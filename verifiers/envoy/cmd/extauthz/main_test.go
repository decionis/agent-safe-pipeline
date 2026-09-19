package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
			t.Fatalf("vector %s not found above this package", name)
		}
		directory = parent
	}
}

// A provider built the way main builds one, from the vector's keys, at the
// vector's instant.
func providerFor(t *testing.T, v vector) *provider {
	directory := t.TempDir()
	keysFile := filepath.Join(directory, "executor-keys.json")
	jwksFile := filepath.Join(directory, "jwks.json")
	if err := os.WriteFile(keysFile, v.ExecutorKeys, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jwksFile, v.AuthorityJWKS, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXECUTOR_KEYS_FILE", keysFile)
	t.Setenv("AUTHORITY_JWKS", jwksFile)
	t.Setenv("AUTHORITY_ISSUER", v.Provider.AuthorityIssuer)
	t.Setenv("PATH_PREFIX", "/verify")
	p, err := newProviderFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, v.Provider.Now)
	if err != nil {
		t.Fatal(err)
	}
	p.replay = verifier.NewMemoryReplayStore(func() time.Time { return now })
	p.now = func() time.Time { return now }
	return p
}

func serve(p *provider, request vectorRequest) *httptest.ResponseRecorder {
	var body io.Reader
	if request.Body != nil {
		body = strings.NewReader(*request.Body)
	}
	r := httptest.NewRequest(request.Method, "/verify"+request.Path+"?trace=1", body)
	for name, value := range request.Headers {
		r.Header.Set(name, value)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

func TestHandlerAnswersTheVectorsOutcomes(t *testing.T) {
	for _, name := range []string{"dispatch-replayed-within-lease", "payload-changed-after-claim", "copied-headers-unsigned"} {
		v := loadVector(t, name)
		p := providerFor(t, v)
		for index, request := range v.Requests {
			w := serve(p, request)
			switch request.Expect.Outcome {
			case "ACCEPT":
				if w.Code != http.StatusOK {
					t.Fatalf("%s request %d: %d %s", name, index, w.Code, w.Body.String())
				}
			case "REFUSE":
				if w.Code != http.StatusConflict {
					t.Fatalf("%s request %d: %d", name, index, w.Code)
				}
				var refusal map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &refusal); err != nil {
					t.Fatal(err)
				}
				if refusal["status"] != "REJECTED" || refusal["reason_code"] != request.Expect.ReasonCode {
					t.Fatalf("%s request %d: %v", name, index, refusal)
				}
				if w.Header().Get("Content-Type") != "application/json" {
					t.Fatalf("%s request %d: content-type %q", name, index, w.Header().Get("Content-Type"))
				}
			}
		}
	}
}

func TestHandlerRefusesACoveredHeaderReceivedTwiceAndABodyBeyondTheBound(t *testing.T) {
	v := loadVector(t, "dispatch-attested-accepts")
	p := providerFor(t, v)
	request := v.Requests[0]
	r := httptest.NewRequest(request.Method, request.Path, strings.NewReader(*request.Body))
	for name, value := range request.Headers {
		r.Header.Set(name, value)
	}
	r.Header.Add("x-agent-safe-grant-id", request.Headers["x-agent-safe-grant-id"])
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), verifier.SignatureInvalidOrIncomplete) {
		t.Fatalf("twice: %d %s", w.Code, w.Body.String())
	}
	p.maxBody = 8
	r = httptest.NewRequest(request.Method, request.Path, strings.NewReader(*request.Body))
	w = httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), "BODY_BEYOND_BOUND") {
		t.Fatalf("bound: %d %s", w.Code, w.Body.String())
	}
}

func TestConfigurationRefusals(t *testing.T) {
	t.Setenv("EXECUTOR_KEYS_FILE", "")
	if _, err := newProviderFromEnvironment(); err == nil {
		t.Fatal("no keys file")
	}
	v := loadVector(t, "dispatch-attested-accepts")
	directory := t.TempDir()
	keysFile := filepath.Join(directory, "keys.json")
	if err := os.WriteFile(keysFile, v.ExecutorKeys, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXECUTOR_KEYS_FILE", keysFile)
	t.Setenv("AUTHORITY_JWKS", filepath.Join(directory, "missing.json"))
	if _, err := newProviderFromEnvironment(); err == nil {
		t.Fatal("missing JWKS")
	}
	jwksFile := filepath.Join(directory, "jwks.json")
	if err := os.WriteFile(jwksFile, v.AuthorityJWKS, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTHORITY_JWKS", jwksFile)
	t.Setenv("CLOCK_WINDOW_SECONDS", "soon")
	if _, err := newProviderFromEnvironment(); err == nil {
		t.Fatal("bad window")
	}
	t.Setenv("CLOCK_WINDOW_SECONDS", "300")
	t.Setenv("EFFECTS", "maybe")
	if _, err := newProviderFromEnvironment(); err == nil {
		t.Fatal("bad effects")
	}
	t.Setenv("EFFECTS", "false")
	p, err := newProviderFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if p.effects || p.window != 300*time.Second || len(p.keys) != 2 {
		t.Fatalf("%+v", p)
	}
}
