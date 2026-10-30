package intent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type vector struct {
	Description   string          `json:"description"`
	Binding       json.RawMessage `json:"binding"`
	CanonicalJSON string          `json:"canonical_json"`
	IntentHash    string          `json:"intent_hash"`
	Mutations     []struct {
		Path          string          `json:"path"`
		Binding       json.RawMessage `json:"binding"`
		CanonicalJSON string          `json:"canonical_json"`
		IntentHash    string          `json:"intent_hash"`
	} `json:"mutations"`
}

func rawValue(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("vector binding is not JSON: %v", err)
	}
	return value
}

// The repository's conformance vectors: every canonical form and digest the
// reference implementation pins, reproduced byte for byte.
func TestConformanceVectors(t *testing.T) {
	root := filepath.Join("..", "..", "..", "conformance")
	files := []string{filepath.Join(root, "agent-safe-intent-v1.json")}
	matches, err := filepath.Glob(filepath.Join(root, "vectors", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, matches...)
	frameworks, _ := filepath.Glob(filepath.Join(root, "frameworks", "*.json"))
	files = append(files, frameworks...)
	if len(files) < 8 {
		t.Fatalf("expected the conformance vectors beside the module, found %d files", len(files))
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var v vector
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if v.CanonicalJSON == "" || v.IntentHash == "" {
			continue // a coverage matrix, not a hash vector
		}
		t.Run(filepath.Base(file), func(t *testing.T) {
			canonical, err := Canonical(rawValue(t, v.Binding))
			if err != nil {
				t.Fatalf("canonical: %v", err)
			}
			if string(canonical) != v.CanonicalJSON {
				t.Fatalf("canonical bytes differ\n got: %s\nwant: %s", canonical, v.CanonicalJSON)
			}
			hash, err := HashValue(rawValue(t, v.Binding))
			if err != nil {
				t.Fatal(err)
			}
			if hash != v.IntentHash {
				t.Fatalf("hash %s, want %s", hash, v.IntentHash)
			}
			seen := map[string]string{hash: "base"}
			for _, mutation := range v.Mutations {
				got, err := HashValue(rawValue(t, mutation.Binding))
				if err != nil {
					t.Fatal(err)
				}
				if got != mutation.IntentHash {
					t.Fatalf("mutation %s: hash %s, want %s", mutation.Path, got, mutation.IntentHash)
				}
				if other, dup := seen[got]; dup {
					t.Fatalf("mutation %s hashes like %s", mutation.Path, other)
				}
				seen[got] = mutation.Path
			}
		})
	}
}

func TestCaptureBuildsTheContractBinding(t *testing.T) {
	at := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	captured, err := Capture(
		Proposal{ActionType: "production-deploy", Resource: "./deploy.sh", Parameters: map[string]any{"service": "api", "replicas": json.Number("3")}},
		Trusted{
			TenantID:         "00000000-0000-4000-8000-000000000002",
			Actor:            Actor{ID: "decionis/example", Type: "WORKFLOW", Runtime: "govern/2.0.0"},
			DownstreamTarget: DownstreamTarget{System: "github_actions", Operation: "production-deploy", Environment: "production", Endpoint: "https://github.com/decionis/example/actions/runs/1"},
			Context:          map[string]any{"repository": "decionis/example"},
			IdempotencyKey:   "github_actions:1:1",
			TTL:              10 * time.Minute,
			Now:              func() time.Time { return at },
			NewID:            func() (string, error) { return "11111111-1111-4111-8111-111111111111", nil },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"action":{"parameters":{"replicas":3,"service":"api"},"resource":"./deploy.sh","type":"production-deploy"},"actor":{"id":"decionis/example","runtime":"govern/2.0.0","type":"WORKFLOW"},"captured_at":"2026-09-21T12:00:00.000Z","context":{"idempotency_key":"github_actions:1:1","repository":"decionis/example"},"downstream_target":{"endpoint":"https://github.com/decionis/example/actions/runs/1","environment":"production","operation":"production-deploy","system":"github_actions"},"expires_at":"2026-09-21T12:05:00.000Z","intent_id":"11111111-1111-4111-8111-111111111111","protocol_version":"agent-safe.intent/1","tenant_id":"00000000-0000-4000-8000-000000000002"}`
	if string(captured.Canonical) != want {
		t.Fatalf("canonical\n got: %s\nwant: %s", captured.Canonical, want)
	}
	if !strings.HasPrefix(captured.Hash, "sha256:") || len(captured.Hash) != 71 {
		t.Fatalf("hash form %q", captured.Hash)
	}
	// The TTL asked for was ten minutes; the contract's ceiling is five.
	if captured.Binding.ExpiresAt != "2026-09-21T12:05:00.000Z" {
		t.Fatalf("expires_at %s", captured.Binding.ExpiresAt)
	}
}

func TestCaptureRefusesWhatTheContractRefuses(t *testing.T) {
	good := Trusted{
		TenantID:         "00000000-0000-4000-8000-000000000002",
		Actor:            Actor{ID: "a", Type: "WORKFLOW"},
		DownstreamTarget: DownstreamTarget{System: "ci", Operation: "step"},
		IdempotencyKey:   "k",
	}
	cases := []struct {
		name     string
		proposal Proposal
		trusted  Trusted
		code     string
	}{
		{"uppercase action", Proposal{ActionType: "Deploy", Resource: "x"}, good, "ACTION_TYPE_INVALID"},
		{"empty resource", Proposal{ActionType: "deploy", Resource: "  "}, good, "ACTION_RESOURCE_INVALID"},
		{"tenant not a uuid", Proposal{ActionType: "deploy", Resource: "x"}, func() Trusted { c := good; c.TenantID = "org-1"; return c }(), "TENANT_ID_INVALID"},
		{"reserved context key", Proposal{ActionType: "deploy", Resource: "x"}, func() Trusted { c := good; c.Context = map[string]any{"idempotency_key": "x"}; return c }(), "INTENT_CONTEXT_KEY_RESERVED"},
		{"unsafe key", Proposal{ActionType: "deploy", Resource: "x", Parameters: map[string]any{"__proto__": 1}}, good, "UNSAFE_INTENT_KEY"},
		{"too deep", Proposal{ActionType: "deploy", Resource: "x", Parameters: nested(25)}, good, "INTENT_TOO_DEEP"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Capture(c.proposal, c.trusted)
			if err == nil || !strings.Contains(err.Error(), c.code) {
				t.Fatalf("want %s, got %v", c.code, err)
			}
		})
	}
}

func nested(depth int) map[string]any {
	inner := map[string]any{"leaf": true}
	for i := 0; i < depth; i++ {
		inner = map[string]any{"n": inner}
	}
	return inner
}

func TestRandomUUIDIsVersion4(t *testing.T) {
	id, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	if !uuidPattern.MatchString(id) || id[14] != '4' {
		t.Fatalf("not a version 4 uuid: %s", id)
	}
}

// The two canonical forms the contract uses differ in one place, array-index
// keys: the intent hash puts them first by value, the payload digest (RFC 8785)
// sorts them by code unit with every other key. A binding hashed the second
// way, or a payload digested the first, is refused by the authority.
func TestArrayIndexKeysOrderPerDigest(t *testing.T) {
	value := map[string]any{"10": 12, "9": 1, "-1": 0, "a": true}
	digest := func(text string) string {
		sum := sha256.Sum256([]byte(text))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	canonical, err := Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"9":1,"10":12,"-1":0,"a":true}`; string(canonical) != want {
		t.Fatalf("intent form %s, want %s", canonical, want)
	}
	hash, err := HashValue(value)
	if err != nil || hash != digest(string(canonical)) {
		t.Fatalf("intent hash %s (%v), want the digest of %s", hash, err, canonical)
	}
	payload, err := PayloadDigest(value)
	if err != nil || payload != digest(`{"-1":0,"10":12,"9":1,"a":true}`) {
		t.Fatalf("payload digest %s (%v), want the RFC 8785 digest", payload, err)
	}
	if _, isIndex := arrayIndex("4294967295"); isIndex {
		t.Fatal("4294967295 is past the largest array index")
	}
	for _, key := range []string{"0", "4294967294"} {
		if _, isIndex := arrayIndex(key); !isIndex {
			t.Fatalf("%s is an array index", key)
		}
	}
	for _, key := range []string{"", "01", "-1", "+1", "1.5", " 1", "١"} {
		if _, isIndex := arrayIndex(key); isIndex {
			t.Fatalf("%q is not an array index", key)
		}
	}
}
