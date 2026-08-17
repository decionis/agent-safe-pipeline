# Cryptographic Agility & TLS Verification Posture

Document the cryptographic algorithms, trust decisions, rotation strategy, and TLS behavior for `@decionis/agent-safe-pipeline`.

## 1. Cryptographic Algorithm Inventory

| Algorithm | Usage | Trust Decision | Fail-Closed? |
|-----------|-------|----------------|--------------|
| SHA-256 | Intent hashing (`CanonicalIntentHasher`) | Deterministic canonicalization — same input always produces same hash | Yes — hash mismatch rejects intent |
| Ed25519 (via JOSE) | JWT signing in `FixtureDecisionAuthority` | Short-lived tokens (60s TTL) — expiry checked before signature | Yes — expired tokens rejected |
| HMAC-SHA256 (via JOSE) | JWT verification in `DecionisGate` | Symmetric key for test fixtures only | Yes — wrong key → verification fails |
| HTTPS (TLS) | All authority endpoint communication | Enforced in `AuthorityBaseUrl` — `https:` required | Yes — non-HTTPS rejected |

## 2. Algorithm Agility

### Current: SHA-256
- `CanonicalIntentHasher` uses Node.js `crypto.createHash("sha256")`
- Hash format: `sha256:${hex}` — prefix identifies algorithm
- **To rotate**: add new hash prefix (e.g., `sha3_256:${hex}`), update `AuthorizationVerifier` regex, maintain backward compatibility during transition
- The prefix-based format (`sha256:`) enables multi-algorithm support without breaking existing intents

### JOSE Algorithms
- `jose` library supports RS256, ES256, EdDSA, and others
- Current: Ed25519 (fast, small keys) for fixture signing
- **To rotate**: change `SignJWT().setProtectedHeader({ alg: "EdDSA" })` to desired algorithm — library handles verification transparently
- Key rotation: generate new keypair, update `FixtureDecisionAuthority` — old tokens expire within 60s

## 3. Credential & Key Rotation

### Intent Hashing Keys
- No keys involved — SHA-256 is a hash function, not a signature
- Rotation not applicable

### JWT Signing Keys (FixtureDecisionAuthority)
- **Rotation strategy**: new Ed25519 keypair per release or per rotation period
- Old tokens have 60s TTL — automatic expiry within one minute
- `FixtureAuthorizationVerifier` validates against current public key only
- **Evidence**: `packages/pipeline/src/decision/FixtureDecisionAuthority.ts` generates ephemeral keypair at construction time

### Authority Endpoint Keys
- External authority endpoints manage their own keys
- Pipeline only verifies signatures against provided public keys
- No local key storage — keys fetched from authority at verification time

## 4. TLS Behavior

### Minimum TLS Version
- Inherited from Node.js runtime (Node 22+ enforces TLS 1.2+)
- No library configuration can downgrade TLS version
- Node.js TLS defaults: TLS 1.2, 1.3 supported

### Certificate Verification
- `AuthorityBaseUrl` (`packages/pipeline/src/http/AuthorityBaseUrl.ts`) enforces:
  - `url.protocol === "https:"` — non-HTTPS URLs rejected
  - No option to disable certificate verification
  - `NODE_TLS_REJECT_UNAUTHORIZED` can only be set at process level (not per-request)
- **Cannot be disabled through library configuration** — `AuthorityBaseUrl` is the sole HTTP entry point for authority communication

### Loopback Exception
- `allowInsecureLoopback` parameter permits HTTP for localhost testing only
- Loopback detection: `url.hostname === "127.0.0.1" || url.hostname === "localhost"`
- **Production use**: loopback exception is off by default, must be explicitly enabled

## 5. Fail-Closed Behavior

All verification paths reject on failure:

| Check | On Failure | Behavior |
|-------|-----------|----------|
| Intent hash mismatch | `AuthorizationVerifier` | Reject — "intent hash does not match" |
| JWT expired | `jwtVerify()` | Reject — "token expired" |
| JWT signature invalid | `jwtVerify()` | Reject — "invalid signature" |
| Non-HTTPS authority | `AuthorityBaseUrl` | Reject — "authority URL must use HTTPS" |
| Hash format invalid | Regex check | Reject — "invalid hash format" |

## 6. OpenSSF Silver Evidence Links

| Criterion | Evidence |
|-----------|----------|
| Algorithm agility | Prefix-based hash format (`sha256:`) in `CanonicalIntentHasher.ts` |
| Credential rotation | 60s JWT TTL in `FixtureDecisionAuthority.ts` |
| TLS minimum | Node.js 22+ defaults (TLS 1.2+), enforced by `AuthorityBaseUrl.ts` |
| Certificate verification | `https:` protocol check in `AuthorityBaseUrl.ts`, no disable option |

---

_This document satisfies acceptance criteria for [#51](https://github.com/decionis/agent-safe-pipeline/issues/51)._
