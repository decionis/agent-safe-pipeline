// Command extauthz is a verifying provider for Envoy's ext_authz filter in
// HTTP mode: Envoy hands it each request bound for the system of record,
// headers and body, and it answers 200 when the Verifying Provider Profile
// accepts the request and 409 with the profile's refusal body when it does
// not; Envoy returns that refusal to the executor unchanged. The hop this
// runs beside is a verifying provider only when the system of record admits
// nothing but that hop (docs/authority/verifying-provider.md, section 1).
//
// Configuration is the environment:
//
//	LISTEN                the address to listen on (127.0.0.1:9001)
//	EXECUTOR_KEYS_FILE    a JSON array of the executor keys this provider
//	                      knows, in the vectors' shape: keyid, alg, and
//	                      public_pem or shared_material_utf8 (required)
//	AUTHORITY_JWKS        the authority's execution-grant JWKS: an https URL,
//	                      refreshed, or a file path
//	                      (https://api.decionis.com/.well-known/decionis-execution-grant-jwks.json)
//	AUTHORITY_ISSUER      the iss the provider trusts (https://decionis.com)
//	CLOCK_WINDOW_SECONDS  how far `created` may lie from now, each way (300)
//	EFFECTS               whether the endpoints behind this hop effect (true)
//	MAX_BODY_BYTES        the body bound; more is refused (1048576)
//	PATH_PREFIX           Envoy's path_prefix, removed before verifying ("")
//
// One instance keeps its replay record in memory; more than one instance
// that can effect the same grant needs a shared store behind
// verifier.ReplayStore.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decionis/agent-safe-pipeline/verifiers/envoy/verifier"
)

const (
	defaultJWKS   = "https://api.decionis.com/.well-known/decionis-execution-grant-jwks.json"
	defaultIssuer = "https://decionis.com"
	refreshEvery  = 10 * time.Minute
	refreshAtMost = time.Minute
)

// The headers the signature may cover; received twice, any of them is a refusal.
var covered = []string{
	"content-digest", "idempotency-key", "x-agent-safe-intent-hash",
	"x-agent-safe-grant-id", "x-agent-safe-decision-id", "x-agent-safe-claim-attestation",
	"signature", "signature-input",
}

type keyFile struct {
	KeyID          string `json:"keyid"`
	Alg            string `json:"alg"`
	PublicPEM      string `json:"public_pem"`
	SharedMaterial string `json:"shared_material_utf8"`
}

func executorKeys(path string) ([]verifier.ExecutorKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []keyFile
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	keys := make([]verifier.ExecutorKey, 0, len(entries))
	for _, entry := range entries {
		switch entry.Alg {
		case "ed25519":
			block, _ := pem.Decode([]byte(entry.PublicPEM))
			if block == nil {
				return nil, fmt.Errorf("%s: public_pem is not PEM", entry.KeyID)
			}
			parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", entry.KeyID, err)
			}
			public, ok := parsed.(ed25519.PublicKey)
			if !ok {
				return nil, fmt.Errorf("%s: not an Ed25519 key", entry.KeyID)
			}
			keys = append(keys, verifier.ExecutorKey{KeyID: entry.KeyID, Algorithm: "ed25519", PublicKey: public})
		case "hmac-sha256":
			if entry.SharedMaterial == "" {
				return nil, fmt.Errorf("%s: shared_material_utf8 is empty", entry.KeyID)
			}
			keys = append(keys, verifier.ExecutorKey{KeyID: entry.KeyID, Algorithm: "hmac-sha256", Secret: []byte(entry.SharedMaterial)})
		default:
			return nil, fmt.Errorf("%s: unknown alg %q", entry.KeyID, entry.Alg)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("no executor keys")
	}
	return keys, nil
}

// keySet holds the authority's JWKS, from a file once or from a URL with
// refreshes: on a schedule, and on a refusal at most once a minute.
type keySet struct {
	source    string
	mutex     sync.Mutex
	current   verifier.JWKS
	refreshed time.Time
}

func newKeySet(source string) (*keySet, error) {
	set := &keySet{source: source}
	if err := set.refresh(); err != nil {
		return nil, err
	}
	if set.remote() {
		go func() {
			for range time.Tick(refreshEvery) {
				if err := set.refresh(); err != nil {
					log.Printf(`{"event":"JWKS_REFRESH_FAILED","error":%q}`, err.Error())
				}
			}
		}()
	}
	return set, nil
}

func (set *keySet) remote() bool { return strings.HasPrefix(set.source, "https://") }

func (set *keySet) refresh() error {
	var raw []byte
	var err error
	if set.remote() {
		client := &http.Client{Timeout: 10 * time.Second}
		response, err := client.Get(set.source)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("JWKS: %s", response.Status)
		}
		raw, err = io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			return err
		}
	} else if raw, err = os.ReadFile(set.source); err != nil {
		return err
	}
	var jwks verifier.JWKS
	if err := json.Unmarshal(raw, &jwks); err != nil {
		return err
	}
	if len(jwks.Keys) == 0 {
		return errors.New("JWKS: no keys")
	}
	set.mutex.Lock()
	defer set.mutex.Unlock()
	set.current = jwks
	set.refreshed = time.Now()
	return nil
}

func (set *keySet) get() verifier.JWKS {
	set.mutex.Lock()
	defer set.mutex.Unlock()
	return set.current
}

// refreshOnce refreshes a remote set when a minute has passed since the
// last refresh, and reports whether it did.
func (set *keySet) refreshOnce() bool {
	if !set.remote() {
		return false
	}
	set.mutex.Lock()
	stale := time.Since(set.refreshed) >= refreshAtMost
	set.mutex.Unlock()
	if !stale {
		return false
	}
	return set.refresh() == nil
}

type provider struct {
	keys       []verifier.ExecutorKey
	authority  *keySet
	issuer     string
	window     time.Duration
	effects    bool
	maxBody    int64
	pathPrefix string
	replay     verifier.ReplayStore
	now        func() time.Time
}

func (p *provider) options() verifier.Options {
	return verifier.Options{
		Effects:         p.effects,
		ExecutorKeys:    p.keys,
		AuthorityJWKS:   p.authority.get(),
		AuthorityIssuer: p.issuer,
		ClockWindow:     p.window,
		Replay:          p.replay,
		Now:             p.now,
	}
}

func (p *provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, p.maxBody+1))
	if err != nil || int64(len(body)) > p.maxBody {
		refuse(w, http.StatusRequestEntityTooLarge, "BODY_BEYOND_BOUND")
		return
	}
	if len(body) == 0 {
		body = nil
	}
	headers := map[string]string{}
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if len(values) > 1 {
			for _, component := range covered {
				if lower == component {
					refuse(w, http.StatusConflict, verifier.SignatureInvalidOrIncomplete)
					return
				}
			}
		}
		headers[lower] = strings.TrimSpace(values[0])
	}
	request := verifier.Request{
		Method:  r.Method,
		Path:    strings.TrimPrefix(r.URL.Path, p.pathPrefix),
		Body:    body,
		Headers: headers,
	}
	verdict := verifier.Verify(request, p.options())
	if verdict.ReasonCode == verifier.AttestationInvalid && p.authority.refreshOnce() {
		verdict = verifier.Verify(request, p.options())
	}
	grant := headers["x-agent-safe-grant-id"]
	if verdict.Accepted {
		log.Printf(`{"event":"PROVIDER_ACCEPTED","method":%q,"path":%q,"grant_id":%q}`, request.Method, request.Path, grant)
		w.WriteHeader(http.StatusOK)
		return
	}
	log.Printf(`{"event":"PROVIDER_REFUSED","reason_code":%q,"method":%q,"path":%q,"grant_id":%q}`, verdict.ReasonCode, request.Method, request.Path, grant)
	refuse(w, http.StatusConflict, verdict.ReasonCode)
}

func refuse(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "REJECTED", "reason_code": code})
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func newProviderFromEnvironment() (*provider, error) {
	keysFile := os.Getenv("EXECUTOR_KEYS_FILE")
	if keysFile == "" {
		return nil, errors.New("EXECUTOR_KEYS_FILE is required")
	}
	keys, err := executorKeys(keysFile)
	if err != nil {
		return nil, err
	}
	authority, err := newKeySet(env("AUTHORITY_JWKS", defaultJWKS))
	if err != nil {
		return nil, err
	}
	window, err := strconv.Atoi(env("CLOCK_WINDOW_SECONDS", "300"))
	if err != nil || window < 0 {
		return nil, errors.New("CLOCK_WINDOW_SECONDS must be a non-negative integer")
	}
	effects, err := strconv.ParseBool(env("EFFECTS", "true"))
	if err != nil {
		return nil, errors.New("EFFECTS must be true or false")
	}
	maxBody, err := strconv.ParseInt(env("MAX_BODY_BYTES", "1048576"), 10, 64)
	if err != nil || maxBody <= 0 {
		return nil, errors.New("MAX_BODY_BYTES must be a positive integer")
	}
	return &provider{
		keys:       keys,
		authority:  authority,
		issuer:     env("AUTHORITY_ISSUER", defaultIssuer),
		window:     time.Duration(window) * time.Second,
		effects:    effects,
		maxBody:    maxBody,
		pathPrefix: os.Getenv("PATH_PREFIX"),
		replay:     verifier.NewMemoryReplayStore(nil),
		now:        time.Now,
	}, nil
}

func main() {
	log.SetFlags(0)
	p, err := newProviderFromEnvironment()
	if err != nil {
		log.Fatalf(`{"event":"CONFIGURATION_INVALID","error":%q}`, err.Error())
	}
	listen := env("LISTEN", "127.0.0.1:9001")
	server := &http.Server{
		Addr:              listen,
		Handler:           p,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	log.Printf(`{"event":"LISTENING","address":%q,"effects":%t}`, listen, p.effects)
	log.Fatal(server.ListenAndServe())
}
