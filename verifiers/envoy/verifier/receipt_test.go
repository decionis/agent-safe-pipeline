package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type receiptVector struct {
	Vector string `json:"vector"`
	Level  string `json:"level"`
	Input  struct {
		Kid            string `json:"kid"`
		Issuer         string `json:"issuer"`
		Audience       string `json:"audience"`
		Attestation    Claims `json:"attestation"`
		IdempotencyKey string `json:"idempotency_key"`
		Effect         struct {
			Status     string `json:"status"`
			Reference  string `json:"reference"`
			Digest     string `json:"digest"`
			EffectedAt string `json:"effected_at"`
		} `json:"effect"`
		IAT int64  `json:"iat"`
		JTI string `json:"jti"`
	} `json:"input"`
	Expect struct {
		ProtectedHeader map[string]any `json:"protected_header"`
		Claims          map[string]any `json:"claims"`
		SigningInput    string         `json:"signing_input"`
		ProviderJWK     JWK            `json:"provider_jwk"`
		Token           string         `json:"token"`
	} `json:"expect"`
}

func receiptOf(t *testing.T, vector receiptVector) Receipt {
	effectedAt, err := time.Parse(time.RFC3339Nano, vector.Input.Effect.EffectedAt)
	if err != nil {
		t.Fatal(err)
	}
	attestation := vector.Input.Attestation
	return Receipt{
		KeyID:          vector.Input.Kid,
		Issuer:         vector.Input.Issuer,
		Audience:       vector.Input.Audience,
		Attestation:    &attestation,
		IdempotencyKey: vector.Input.IdempotencyKey,
		Effect: Effect{
			Status:     vector.Input.Effect.Status,
			Reference:  vector.Input.Effect.Reference,
			Digest:     vector.Input.Effect.Digest,
			EffectedAt: effectedAt,
		},
		IssuedAt: vector.Input.IAT,
		JTI:      vector.Input.JTI,
	}
}

// Numbers read from JSON are float64; the receipt's are int64. Compare through JSON.
func sameJSON(t *testing.T, got any, want any) bool {
	g, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	w, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var gv, wv any
	if err := json.Unmarshal(g, &gv); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(w, &wv); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(gv, wv)
}

func TestReceiptVectors(t *testing.T) {
	directory := filepath.Join(filepath.Dir(vectorsDirectory(t)), "receipts")
	files, err := filepath.Glob(filepath.Join(directory, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 4 {
		t.Fatalf("found %d receipt vectors", len(files))
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var vector receiptVector
		if err := json.Unmarshal(raw, &vector); err != nil {
			t.Fatal(err)
		}
		t.Run(vector.Vector, func(t *testing.T) {
			if vector.Level != "VP-3" {
				t.Fatalf("level %q", vector.Level)
			}
			receipt := receiptOf(t, vector)
			claims, err := receipt.Claims()
			if err != nil {
				t.Fatal(err)
			}
			if !sameJSON(t, claims, vector.Expect.Claims) {
				t.Fatalf("claims differ: %v", claims)
			}
			signingInput, err := receipt.SigningInput()
			if err != nil {
				t.Fatal(err)
			}
			if signingInput != vector.Expect.SigningInput {
				t.Fatalf("signing input differs:\n%s\n%s", signingInput, vector.Expect.SigningInput)
			}
			token, err := receipt.Sign(private)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(token, ".")
			if len(parts) != 3 || parts[0]+"."+parts[1] != vector.Expect.SigningInput {
				t.Fatalf("token is not the signing input signed: %s", token)
			}
			signature, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatal(err)
			}
			if !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature) {
				t.Fatal("this provider's signature does not verify under its own key")
			}
			// The vector's own token verifies under the public half it carries.
			x, err := base64.RawURLEncoding.DecodeString(vector.Expect.ProviderJWK.X)
			if err != nil {
				t.Fatal(err)
			}
			vectorParts := strings.Split(vector.Expect.Token, ".")
			vectorSignature, err := base64.RawURLEncoding.DecodeString(vectorParts[2])
			if err != nil {
				t.Fatal(err)
			}
			if !ed25519.Verify(ed25519.PublicKey(x), []byte(vectorParts[0]+"."+vectorParts[1]), vectorSignature) {
				t.Fatal("the vector's token does not verify under its public key")
			}
		})
	}
}

func TestReceiptRefusesWhatItCannotStandBehind(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attestation := &Claims{Sub: "g", DecisionID: "d", DossierID: "s", ClaimTokenDigest: "c", JTI: "a", Binding: Binding{IntentHash: "i"}}
	good := Receipt{
		KeyID: "k", Issuer: "i", Audience: "a", Attestation: attestation,
		Effect:   Effect{Status: Effected, EffectedAt: time.Unix(1_789_819_201, 0)},
		IssuedAt: 1_789_819_202, JTI: "r",
	}
	if _, err := good.Sign(private); err != nil {
		t.Fatal(err)
	}
	cases := map[string]Receipt{
		"EFFECT_STATUS_UNKNOWN":   func() Receipt { r := good; r.Effect.Status = "DONE"; return r }(),
		"EFFECT_DIGEST_MALFORMED": func() Receipt { r := good; r.Effect.Digest = "sha256:zz"; return r }(),
		"EFFECTED_AT_MALFORMED":   func() Receipt { r := good; r.Effect.EffectedAt = time.Time{}; return r }(),
		"ISSUED_AT_MALFORMED":     func() Receipt { r := good; r.IssuedAt = -1; return r }(),
		"ATTESTATION_MISSING":     func() Receipt { r := good; r.Attestation = nil; return r }(),
		"KID_EMPTY":               func() Receipt { r := good; r.KeyID = ""; return r }(),
		"ISSUER_EMPTY":            func() Receipt { r := good; r.Issuer = ""; return r }(),
		"AUDIENCE_EMPTY":          func() Receipt { r := good; r.Audience = ""; return r }(),
		"JTI_EMPTY":               func() Receipt { r := good; r.JTI = ""; return r }(),
	}
	for want, receipt := range cases {
		if _, err := receipt.Sign(private); err == nil || err.Error() != want {
			t.Errorf("%s: got %v", want, err)
		}
	}
	if _, err := good.Sign(ed25519.PrivateKey([]byte("short"))); err == nil || err.Error() != "KEY_NOT_ED25519" {
		t.Errorf("short key: got %v", err)
	}
}
