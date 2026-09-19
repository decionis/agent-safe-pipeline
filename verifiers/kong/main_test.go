package main

import (
	"encoding/json"
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
