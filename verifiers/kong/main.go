// Command verifying-provider is a Kong Gateway plugin, through Kong's Go
// plugin server, that runs the Verifying Provider Profile on every request
// bound for the system of record behind a route: it answers 409 with the
// profile's refusal body when the profile refuses, and lets the request
// through unchanged when it accepts. The route this guards is a verifying
// provider only when the system of record admits nothing but Kong
// (docs/authority/verifying-provider.md, section 1).
//
// With a receipt key configured, the plugin also signs the profile's effect
// receipt (VP-3) in its response phase, from what the system of record
// reports about the effect in its answer, so a system of record that cannot
// sign for itself still answers the executor with a receipt under the hop's
// registered key.
//
// The procedure itself is the verifier package of verifiers/envoy, so the
// two Go hops verify identically and pass the same vectors.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
	"github.com/decionis/agent-safe-pipeline/verifiers/envoy/verifier"
)

// Version and Priority are what Kong's plugin server asks a plugin for.
const (
	Version  = "0.1.0"
	Priority = 1000
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

// The headers a system of record reports its effect to the hop in, for the
// hop to sign into a receipt. They are the hop's contract with its upstream
// and never leave the hop: the response phase clears them and sets the
// receipt in their place.
const (
	effectStatusHeader    = "x-agent-safe-effect-status"
	effectReferenceHeader = "x-agent-safe-effect-reference"
	effectDigestHeader    = "x-agent-safe-effect-digest"
	effectedAtHeader      = "x-agent-safe-effected-at"
	// What the access phase leaves for the response phase: the attestation
	// it accepted and the idempotency key, as JSON, under this shared key.
	acceptedContextKey = "verifying-provider.accepted"
)

// Config is the plugin's configuration, as Kong's declarative config or its
// Admin API sets it. Every field but the keys file has a default.
type Config struct {
	// ExecutorKeysFile is a JSON array of the executor keys this provider
	// issued, in the vectors' shape: keyid, alg, and public_pem or
	// shared_material_utf8.
	ExecutorKeysFile string `json:"executor_keys_file"`
	// AuthorityJWKS is the authority's execution-grant JWKS: an https URL,
	// refreshed, or a file path.
	AuthorityJWKS string `json:"authority_jwks"`
	// AuthorityIssuer is the iss the provider trusts.
	AuthorityIssuer string `json:"authority_issuer"`
	// ClockWindowSeconds is how far `created` may lie from now, each way.
	ClockWindowSeconds int `json:"clock_window_seconds"`
	// Effects says whether the route effects; a route that reads verifies at VP-1 alone.
	Effects *bool `json:"effects"`
	// MaxBodyBytes is the body bound; a larger body is refused with 413.
	MaxBodyBytes int `json:"max_body_bytes"`
	// ReceiptKeyFile is the PKCS#8 PEM of the Ed25519 key the hop signs effect
	// receipts with (VP-3); empty means the hop signs none. Its public half is
	// what the organisation registers with the authority under ReceiptKid.
	ReceiptKeyFile string `json:"receipt_key_file"`
	// ReceiptKid is the kid the key is registered under at the authority.
	ReceiptKid string `json:"receipt_kid"`
	// ReceiptIssuer is the iss registered with that key.
	ReceiptIssuer string `json:"receipt_issuer"`
	// ReceiptAudience is the authority the receipts are for; defaults to authority_issuer.
	ReceiptAudience string `json:"receipt_audience"`

	once       sync.Once
	loadError  error
	keys       []verifier.ExecutorKey
	authority  *keySet
	replay     verifier.ReplayStore
	now        func() time.Time
	receiptKey ed25519.PrivateKey
	receiptJTI func() string
}

// New is the constructor Kong's plugin server calls.
func New() interface{} {
	return &Config{}
}

// load reads the keys and the JWKS once per plugin configuration.
func (conf *Config) load() error {
	conf.once.Do(func() {
		if conf.now == nil {
			conf.now = time.Now
		}
		if conf.replay == nil {
			conf.replay = verifier.NewMemoryReplayStore(nil)
		}
		if conf.ExecutorKeysFile == "" {
			conf.loadError = errors.New("executor_keys_file is required")
			return
		}
		keys, err := executorKeys(conf.ExecutorKeysFile)
		if err != nil {
			conf.loadError = err
			return
		}
		conf.keys = keys
		source := conf.AuthorityJWKS
		if source == "" {
			source = defaultJWKS
		}
		authority, err := newKeySet(source)
		if err != nil {
			conf.loadError = err
			return
		}
		conf.authority = authority
		if conf.ReceiptKeyFile != "" {
			if conf.ReceiptKid == "" || conf.ReceiptIssuer == "" {
				conf.loadError = errors.New("receipt_kid and receipt_issuer are required with receipt_key_file")
				return
			}
			key, err := receiptKey(conf.ReceiptKeyFile)
			if err != nil {
				conf.loadError = err
				return
			}
			conf.receiptKey = key
		}
		if conf.receiptJTI == nil {
			conf.receiptJTI = randomJTI
		}
	})
	return conf.loadError
}

// accepted is what the access phase hands the response phase: the claim the
// receipt answers, and the request it was for.
type accepted struct {
	Attestation    verifier.Claims `json:"attestation"`
	IdempotencyKey string          `json:"idempotency_key"`
}

func (conf *Config) options() verifier.Options {
	effects := true
	if conf.Effects != nil {
		effects = *conf.Effects
	}
	window := conf.ClockWindowSeconds
	if window <= 0 {
		window = 300
	}
	issuer := conf.AuthorityIssuer
	if issuer == "" {
		issuer = defaultIssuer
	}
	return verifier.Options{
		Effects:         effects,
		ExecutorKeys:    conf.keys,
		AuthorityJWKS:   conf.authority.get(),
		AuthorityIssuer: issuer,
		ClockWindow:     time.Duration(window) * time.Second,
		Replay:          conf.replay,
		Now:             conf.now,
	}
}

// Access runs the profile before Kong proxies the request.
func (conf *Config) Access(kong *pdk.PDK) {
	if err := conf.load(); err != nil {
		// A misconfigured verifier refuses everything: it never waves through.
		_ = kong.Log.Err(fmt.Sprintf(`{"event":"CONFIGURATION_INVALID","error":%q}`, err.Error()))
		refuse(kong, http.StatusServiceUnavailable, "VERIFIER_NOT_CONFIGURED")
		return
	}
	maxBody := conf.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 1 << 20
	}
	body, err := kong.Request.GetRawBody()
	if err != nil {
		refuse(kong, http.StatusConflict, verifier.SignatureInvalidOrIncomplete)
		return
	}
	if len(body) > maxBody {
		refuse(kong, http.StatusRequestEntityTooLarge, "BODY_BEYOND_BOUND")
		return
	}
	if len(body) == 0 {
		body = nil
	}
	received, err := kong.Request.GetHeaders(-1)
	if err != nil {
		refuse(kong, http.StatusConflict, verifier.SignatureInvalidOrIncomplete)
		return
	}
	headers := map[string]string{}
	for name, values := range received {
		lower := strings.ToLower(name)
		if len(values) > 1 {
			for _, component := range covered {
				if lower == component {
					refuse(kong, http.StatusConflict, verifier.SignatureInvalidOrIncomplete)
					return
				}
			}
		}
		if len(values) > 0 {
			headers[lower] = strings.TrimSpace(values[0])
		}
	}
	method, _ := kong.Request.GetMethod()
	path, _ := kong.Request.GetPath()
	request := verifier.Request{Method: method, Path: path, Body: body, Headers: headers}
	verdict := verifier.Verify(request, conf.options())
	if verdict.ReasonCode == verifier.AttestationInvalid && conf.authority.refreshOnce() {
		verdict = verifier.Verify(request, conf.options())
	}
	grant := headers["x-agent-safe-grant-id"]
	if verdict.Accepted {
		_ = kong.Log.Info(fmt.Sprintf(`{"event":"PROVIDER_ACCEPTED","method":%q,"path":%q,"grant_id":%q}`, method, path, grant))
		// A receipt answers an attested dispatch and nothing else: a read
		// verified at VP-1 alone leaves nothing for the response phase.
		if conf.receiptKey != nil && verdict.Attestation != nil {
			encoded, _ := json.Marshal(accepted{Attestation: *verdict.Attestation, IdempotencyKey: headers["idempotency-key"]})
			_ = kong.Ctx.SetShared(acceptedContextKey, string(encoded))
		}
		return
	}
	_ = kong.Log.Notice(fmt.Sprintf(`{"event":"PROVIDER_REFUSED","reason_code":%q,"method":%q,"path":%q,"grant_id":%q}`, verdict.ReasonCode, method, path, grant))
	refuse(kong, http.StatusConflict, verdict.ReasonCode)
}

// Response signs the effect receipt (VP-3) once the upstream has answered a
// dispatch the access phase accepted: the effect as the upstream reported it
// in the report headers, or by its status alone, under the claim the access
// phase verified. The report headers are cleared: what leaves the hop is the
// receipt, and the receipt is the hop's own signature.
func (conf *Config) Response(kong *pdk.PDK) {
	if conf.receiptKey == nil {
		return
	}
	encoded, err := kong.Ctx.GetSharedString(acceptedContextKey)
	if err != nil || encoded == "" {
		return
	}
	var claim accepted
	if err := json.Unmarshal([]byte(encoded), &claim); err != nil {
		return
	}
	// An answer the plugin itself produced, a refusal, is not the upstream's
	// effect; only the service's answer is receipted.
	if source, err := kong.Response.GetSource(); err != nil || source != "service" {
		return
	}
	// A system of record that signs for itself has already answered with its
	// own receipt, and its signature beats the hop's: it passes through.
	if own, err := kong.Response.GetHeader(verifier.ReceiptHeader); err == nil && own != "" {
		return
	}
	status, err := kong.Response.GetStatus()
	if err != nil {
		return
	}
	report := func(name string) string {
		value, _ := kong.Response.GetHeader(name)
		_ = kong.Response.ClearHeader(name)
		return strings.TrimSpace(value)
	}
	effect := verifier.Effect{
		Status:     effectStatus(report(effectStatusHeader), status),
		Reference:  report(effectReferenceHeader),
		Digest:     report(effectDigestHeader),
		EffectedAt: effectedAt(report(effectedAtHeader), conf.now()),
	}
	audience := conf.ReceiptAudience
	if audience == "" {
		audience = conf.options().AuthorityIssuer
	}
	token, err := verifier.Receipt{
		KeyID:          conf.ReceiptKid,
		Issuer:         conf.ReceiptIssuer,
		Audience:       audience,
		Attestation:    &claim.Attestation,
		IdempotencyKey: claim.IdempotencyKey,
		Effect:         effect,
		IssuedAt:       conf.now().Unix(),
		JTI:            conf.receiptJTI(),
	}.Sign(conf.receiptKey)
	if err != nil {
		// A receipt the hop could not stand behind is not signed; the answer
		// goes back without one and the log says why.
		_ = kong.Log.Notice(fmt.Sprintf(`{"event":"RECEIPT_NOT_SIGNED","grant_id":%q,"error":%q}`, claim.Attestation.Sub, err.Error()))
		return
	}
	_ = kong.Response.SetHeader(verifier.ReceiptHeader, token)
	_ = kong.Log.Info(fmt.Sprintf(`{"event":"RECEIPT_SIGNED","grant_id":%q,"effect_status":%q}`, claim.Attestation.Sub, effect.Status))
}

// The effect status the upstream reported, or the one its status code
// implies: it effected on 2xx, refused on 4xx, and nothing is known on 5xx.
func effectStatus(reported string, status int) string {
	switch reported {
	case verifier.Effected, verifier.Refused, verifier.Indeterminate:
		return reported
	}
	switch {
	case status >= 200 && status < 300:
		return verifier.Effected
	case status >= 400 && status < 500:
		return verifier.Refused
	default:
		return verifier.Indeterminate
	}
}

func effectedAt(reported string, now time.Time) time.Time {
	if at, err := time.Parse(time.RFC3339Nano, reported); err == nil {
		return at
	}
	return now
}

func receiptKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("receipt_key_file: not a PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("receipt_key_file: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("receipt_key_file: not an Ed25519 key")
	}
	return key, nil
}

// A receipt id nobody can predict: 128 random bits, as hex.
func randomJTI() string {
	var buffer [16]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buffer[:])
}

func refuse(kong *pdk.PDK, status int, code string) {
	body, _ := json.Marshal(map[string]string{"status": "REJECTED", "reason_code": code})
	kong.Response.Exit(status, body, map[string][]string{"Content-Type": {"application/json"}})
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
				_ = set.refresh()
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

func main() {
	if err := server.StartServer(New, Version, Priority); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
