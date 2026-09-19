# Verifying Provider Profile

`agent-safe.verifying-provider/1`, version 0.2, status **draft**. Section 7, the effect receipt, is
normative as of this version: the Decionis OpenAPI document carries it, the executor forwards it,
and five implementations build one from the same vectors.

A system of record is the only party that can _refuse_ an instruction rather than merely fail to
receive it. [Bypass resistance](../bypass-resistance.md) ranks the three chokepoints an execution
boundary has, the provider refusing, the credential the agent never holds, and the network, and
says why the first is the one worth insisting on. This profile is that first chokepoint written
down as something a provider can implement and claim: the exact procedure by which a system of
record, or the last hop in front of it that its owner controls, establishes that a request came
from the executor holding a key it issued, that the authority claimed a single-use grant for this
exact intent over these exact parameters, and that the grant has not been used before, and refuses,
effecting nothing, otherwise.

Nothing here is new to the executor. The procedure is the one `@decionis/agentsafe` documents for
its `SIGNED_REQUEST` credential and the one the offline proof's strict provider double runs. What
is new is that it is stated once, normatively, with test vectors any implementation can run, so
that native verification is a place a verifier is deployed rather than a product a vendor ships. A
customer moves from an executor-only boundary, to a verifying hop, to a verifying system of record
without changing agents, policies or evidence.

The key words MUST, MUST NOT, SHOULD, MAY are to be read as in RFC 2119.

## 1. Where a verifier runs

| Tier              | Who runs the procedure                                                                                                                                | What it binds                           | What it covers                                                         |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- | ---------------------------------------------------------------------- |
| **Vendor-native** | the system of record's own transaction layer                                                                                                          | the bytes; at VP-3, the effect          | every path into the system: its API, batch, console, people            |
| **Owner-native**  | the last hop its owner controls in front of the system of record (an API layer, a gateway, a sidecar), holding the only credential the system accepts | the bytes; the effect by reconciliation | the paths routed through it                                            |
| **Executor-only** | nobody downstream: the executor forwards on a bearer                                                                                                  | the bytes, at the executor              | agents that hold no other credential, for as long as containment holds |

A hop at the second tier is a verifying provider in this profile's sense only when the system of
record admits no other principal: the hop holds the system's sole credential, and the system is
reachable by nothing else, whether by mutual TLS to a certificate only the hop has, or by a private
link whose route exists only in the hop's namespace. Otherwise the hop is a network control, and
[bypass resistance](../bypass-resistance.md) says what those are worth. Passing this profile's
vectors demonstrates the procedure; the tier's conditions are the operator's.

## 2. Terms

- **Authority**: Decionis, or an implementation of its protocol, that evaluates an intent, issues
  a grant on `ALLOW`, and attests to the claim of that grant. Its execution-grant keys are
  published at `/.well-known/decionis-execution-grant-jwks.json` on its API origin:
  `https://api.decionis.com/.well-known/decionis-execution-grant-jwks.json` for Decionis.
- **Executor**: the process that captured the intent, claimed the grant, and dispatches the
  request: `@decionis/agentsafe`, or an adopter's process built on it. It signs each dispatch with
  a key the provider knows by `keyid`.
- **Provider**: the party running this procedure: the system of record, or the owner-controlled hop
  in front of it.
- **Intent hash**: `sha256:` over the RFC 8785 canonical form of the `agent-safe.intent/1` binding
  ([execution binding](./execution-binding.md)). What every later record names.
- **Grant**: the single-use authorization the authority issued with an `ALLOW`. **Claim**: the
  executor's atomic consumption of it immediately before dispatch
  ([claim and finalize](./claim-finalize.md)). **Lease**: the interval after the claim within
  which the dispatch must happen; the attestation expires with it.
- **Attestation**: the compact JWS the authority returns with a live claim (`claim_attestation`,
  schema `ClaimAttestationClaims`, in the Decionis OpenAPI document), which the executor forwards
  under `x-agent-safe-claim-attestation` and signs over. It is issued only once the authority has
  atomically consumed the grant: it is the authority's proof that the claim happened, and it is
  not the grant.
- **Effecting request**: one that changes state at the system of record. A read that changes
  nothing may be verified at VP-1 alone.

## 3. Conformance levels

- **VP-1, signed request.** The provider verifies the executor's HTTP message signature (RFC 9421)
  with its content digest (RFC 9530) and requires the covered components section 5 names. A
  provider at VP-1 refuses anything the executor did not send. It does not know whether the
  authority claimed anything.
- **VP-2, attested claim.** VP-1, and the provider verifies the authority's attestation against
  the authority's published keys, checks that the request in hand is the one the attestation
  describes (grant, decision, intent hash, canonical parameter digest, expiry), and refuses a
  second presentation of the grant within the lease. A provider at VP-2 refuses what the authority
  never claimed. **This is the level a system of record needs.**
- **VP-3, effect receipt.** VP-2, and the provider signs what it effected, or refused, keyed by the
  grant and the claim, and returns it with its answer, so the effect plane becomes
  provider-attested rather than executor-reconciled. Section 7.

The invariant behind the levels, stated so that it cannot be misread: verification proves what the
authority issued; the authority's claim is what consumes it; only the attestation of that claim,
bound to this request, permits the provider to effect. A grant, a decision or a dossier that a
provider verified by signature alone MUST NOT, by itself, authorize an effect. Offline
verification, `@decionis/verify` included, is deliberately stateless and cannot know whether a
valid grant was consumed; a provider that effects on `verify(grant)` alone is replayable by
construction.

An implementation claims a level by passing every vector at that level in
[`conformance/provider`](../../conformance/provider/README.md) and stating the level and the
profile version (section 8).

## 4. What the provider receives

The executor's own reference for what it sends is `packages/agentsafe/README.md`, "Downstream
credentials". For a dispatch:

| Header                           | Value                                                                                               | Covered                     |
| -------------------------------- | --------------------------------------------------------------------------------------------------- | --------------------------- |
| `content-digest`                 | `sha-256=:<base64 of SHA-256 over the raw body>:` (RFC 9530), the empty body included               | as `content-digest`         |
| `idempotency-key`                | the intent-bound idempotency key                                                                    | always                      |
| `x-agent-safe-intent-hash`       | the intent hash                                                                                     | always                      |
| `x-agent-safe-grant-id`          | the grant's id; the attestation's `sub`                                                             | on a dispatch               |
| `x-agent-safe-decision-id`       | the decision's id                                                                                   | on a dispatch               |
| `x-agent-safe-claim-attestation` | the attestation, a compact JWS                                                                      | when the authority attested |
| `signature-input`                | `agentsafe=(<components>);created=<unix seconds>;keyid="<id>";alg="ed25519"` or `alg="hmac-sha256"` | the parameters              |
| `signature`                      | `agentsafe=:<base64 signature>:`                                                                    | the signature               |

The eight components this profile knows, in the order the executor lists them: `@method`,
`@path`, `content-digest`, `idempotency-key`, `x-agent-safe-intent-hash`, `x-agent-safe-grant-id`,
`x-agent-safe-decision-id`, `x-agent-safe-claim-attestation`. The first five are the **base**.
`@path` is the request path without its query. Any other header the executor sends, such as
`x-agent-safe-dossier-id`, is not covered and MUST NOT influence whether the provider effects.

## 5. Procedure

Normative, in this order. The first failing step names the refusal, and a refusal effects nothing.

**Step 0, parse.** From `signature-input`, take the text after `agentsafe=` as the _parameters_.
From `signature`, take the base64 between the colons after `agentsafe=`. Either header absent, or
not of that form, is `SIGNATURE_INVALID_OR_INCOMPLETE`.

**Step 1, content digest.** Compute `sha-256=:<base64(SHA-256(body))>:` over exactly the bytes
received, the empty body included, and compare it with `content-digest` byte for byte. A
difference is `SIGNATURE_INVALID_OR_INCOMPLETE`.

**Step 2, covered components.** The parameters begin with a parenthesised, space-separated list of
quoted component names. Every name MUST be one of the eight, none repeated. The base MUST be
present. A provider that effects MUST require all eight; a provider verifying a read that effects
nothing MAY require the base alone. Any requirement unmet is `SIGNATURE_INVALID_OR_INCOMPLETE`. A
request may carry a grant header the signature does not cover; such a header proves nothing about
the grant, which is why the requirement is on the covered list and not on the headers present.

**Step 3, freshness.** `created` MUST lie within a window of the provider's clock. The window is
the provider's; it SHOULD be no more than 300 seconds each way. Outside it is
`SIGNATURE_INVALID_OR_INCOMPLETE`.

**Step 4, key.** `keyid` MUST name a key the provider issued to, or registered for, the executor,
and `alg` MUST be that key's algorithm: `ed25519` for an Ed25519 public key, `hmac-sha256` for a
shared secret. An unknown key, or an algorithm the key is not for, is
`SIGNATURE_INVALID_OR_INCOMPLETE`. Section 10 says what a shared secret costs.

**Step 5, signature base and verification.** Build the base as one line per covered component, in
the order the list gives them, then the parameters line:

```text
"@method": <the method, upper case>
"@path": <the request path, without its query>
"content-digest": <the content-digest value>
"idempotency-key": <the header value>
"x-agent-safe-intent-hash": <the header value>
"x-agent-safe-grant-id": <the header value>
"x-agent-safe-decision-id": <the header value>
"x-agent-safe-claim-attestation": <the header value>
"@signature-params": <the parameters, verbatim>
```

Lines are joined by a single line feed, with no trailing line feed. Each header value is the value
received, exactly; a covered header that is absent, or present more than once, is
`SIGNATURE_INVALID_OR_INCOMPLETE`. Verify the signature over the UTF-8 bytes of the base: Ed25519
against the key, or HMAC-SHA256 compared in constant time and only at its full length. A failure is
`SIGNATURE_INVALID_OR_INCOMPLETE`. A read verified at VP-1 alone ends here.

**Step 6, attestation form.** Split `x-agent-safe-claim-attestation` on `.` into exactly three
base64url parts. Decode the first as a JSON object: `alg` MUST be `EdDSA`, `typ` MUST be
`decionis-claim-attestation+jwt`, and `kid` MUST name a key in the authority's execution-grant JWKS
(section 9 says how to hold that document). Verify the Ed25519 signature, the third part, over the
ASCII bytes of the first part, a dot, and the second part, with that key. Decode the second part as
a JSON object, the claims. It MUST carry strings `iss`, `sub`, `decision_id`, `dossier_id`,
`claim_token_digest` and `jti`, a number `exp`, and an object `binding` with strings
`intent_hash`, `execution_payload_digest` and `execution_payload_canonicalization_profile`: the
claims step 7 compares and the ones a receipt (section 7) is built from; an attestation without them
is not one. `iss` MUST equal the issuer of the authority the provider trusts, `https://decionis.com`
for Decionis. Any failure is `ATTESTATION_INVALID`.

**Step 7, the attestation describes this request.** All of the following MUST hold, else the
refusal is `ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST`:

- `sub` equals `x-agent-safe-grant-id`;
- `decision_id` equals `x-agent-safe-decision-id`;
- `binding.intent_hash` equals `x-agent-safe-intent-hash`;
- `binding.execution_payload_canonicalization_profile` equals `RFC8785/JCS`, the one profile this
  version defines;
- `binding.execution_payload_digest` equals `sha256:` followed by the lower-case hex of SHA-256
  over the RFC 8785 canonical form of the body parsed as JSON. The body MUST be a JSON object,
  since parameters are one, and it MUST be I-JSON (RFC 7493): no lone surrogates, no non-finite
  numbers, no duplicate names; anything else is refused under this same code, and so is a request
  with no body, which describes no parameters. The provider MUST canonicalise, never hash the raw bytes: step 1
  bound the bytes the executor sent, this step binds the parameters the authority saw, and the two
  need not be the same bytes;
- `exp`, in seconds since the epoch, is later than now.

A provider that effects for more than one organisation SHOULD also require `org_id` to be the
organisation this endpoint effects for. `nbf` MAY be checked, with the step 3 window.

**Step 8, single presentation.** The provider keeps `sub` until `exp`. If `sub` was recorded by
an earlier acceptance, the refusal is `GRANT_REPLAYED`. Otherwise the provider records it before
effecting. The record MUST be visible to every instance that could effect this grant within the
lease: the executor never retries a side effect, so a second presentation is never the executor.
This step is not a second single-use authority. The grant was consumed once, at the authority, when
the attestation was issued; the step guards the one thing an attestation cannot, a second
presentation of that one consumption inside its lease, which is why the record needs no life beyond
`exp`.

**Accept.** Effect exactly once and answer `2xx`. A provider at VP-3 answers with its receipt
(section 7), on a `2xx` and on a `4xx` of its own alike.

**Refuse.** Effect nothing and answer `4xx`, `409` in the reference implementations, with the body
`{"status":"REJECTED","reason_code":"<code>"}`. A refusal MUST NOT be a `5xx`: the executor reads
`4xx` as `DEFINITELY_NOT_EXECUTED` and finalizes `FAILED`, and `5xx` as `UNKNOWN_AFTER_DISPATCH`
([execution outcomes](../execution-outcomes.md)). The response MUST NOT echo the body or the
attestation.

| Code                                         | Meaning                                                                                        |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `SIGNATURE_INVALID_OR_INCOMPLETE`            | Not sent by the executor for this request, or not covering what an effecting provider requires |
| `ATTESTATION_INVALID`                        | Not the authority's attestation                                                                |
| `ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST` | The authority's attestation, but of another grant, decision, intent, body, or time             |
| `GRANT_REPLAYED`                             | The authority's attestation of this request, already accepted once                             |

## 6. What each level guarantees

**VP-1.** The request was sent by the holder of the named key, for this intent hash, with this
body. A copied set of headers, an altered body, or an altered covered header proves nothing.

**VP-2.** The authority claimed this grant, for this intent, over these canonical parameters,
within a lease that has not ended, and this is the first use. A compromised executor can sign a
request; it cannot attest to one, because the attestation key is not in the executor. A leaked
attestation cannot be presented again inside the lease, and never carried the claim token, only its
digest, so it finalizes nothing. Together: no instruction effects at the provider that the
authority did not claim for exactly these parameters, which is the property the first row of the
bypass-resistance table names.

**What VP-2 does not give.** That the effect matched the parameters. The provider is trusted for
that; the executor's effect plane ([BEAP conformance](../beap-conformance.md)) reconciles its
observation afterwards.

**VP-3.** The party that effected says what it effected, under its own signature, bound to the
grant it effected it under and to the claim it answered, and the authority records that statement
with the commit. A dossier at VP-3 carries the provider's signature over the effect, not only the
executor's report of it, and when the grant named the effect it expected, a receipt whose digest
agrees confirms the effect by the provider's key.

## 7. Effect receipt (VP-3)

The attestation lets the provider refuse what the authority never claimed. The receipt closes the
other direction: after effecting, or refusing, a request it accepted at step 8, the provider signs
what it did, bound to the grant it acted under and the claim it answered, and the authority
records it with the commit. Until this existed, the exactly-once and the effect were the
executor's word, checked by reconciliation; with it, the party that effected says so.

The contract's source of truth is the Decionis OpenAPI document: the schema `EffectReceiptClaims`,
the `effect_receipt` field of `ExecutionFinalizeRequest` and `ExecutionFinalizeResponse`, and the
operations under `/v1/execution/provider-keys`. This section states what a provider does.

**Key.** The provider signs receipts with an Ed25519 key of its own. The organisation registers
the public half with the authority (`POST /v1/execution/provider-keys`: `kid`, `issuer`,
`algorithm` `EdDSA`, the OKP JWK), and the private half never leaves the provider. Revocation is a
timestamp at the authority, never a deletion, so a receipt recorded under a retired key stays
explicable. Rotation is a new `kid`.

**Receipt.** A compact JWS whose protected header is exactly `alg` `EdDSA`, `kid` the registered
key id, `typ` `decionis-effect-receipt+jwt`, and whose claims are:

| Claim                       | Meaning                                                                                                                                                       |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `iss`                       | the provider, exactly as registered with the key: a receipt under a key with another issuer does not verify                                                   |
| `aud`                       | the authority's issuer, `https://decionis.com` for Decionis                                                                                                   |
| `sub`                       | the grant id: the attestation's `sub`                                                                                                                         |
| `decision_id`, `dossier_id` | copied from the attestation                                                                                                                                   |
| `claim_token_digest`        | copied from the attestation: which claim of the grant this receipt answers, which the authority ties to the claim token being finalized                       |
| `attestation_jti`           | the attestation's `jti`                                                                                                                                       |
| `intent_hash`               | the attestation's `binding.intent_hash`                                                                                                                       |
| `idempotency_key`           | the request's, when the provider records it; MAY be omitted                                                                                                   |
| `effect.status`             | `EFFECTED`, `REFUSED`, or `INDETERMINATE`                                                                                                                     |
| `effect.reference`          | the provider's own record: a ledger entry, a transaction id; MAY be omitted                                                                                   |
| `effect.digest`             | `sha256:` over the effect in the terms the grant's `expected_effect_digest` names, when the grant carries one and the provider can compute it; MAY be omitted |
| `effect.effected_at`        | RFC 3339                                                                                                                                                      |
| `iat`, `jti`                | as in RFC 7519; `jti` unique per receipt                                                                                                                      |

The claims the receipt binds are the attestation's, which is the point: the provider copies
`sub`, `decision_id`, `dossier_id`, `claim_token_digest` and `jti` from the attestation it
verified at step 6 and cannot have obtained them any other way, since the claim token itself never
reaches it. `claim_token_digest` is what the authority compares with the claim token the executor
finalizes with, so a receipt answers one claim of one grant and no other.

**Canonical form.** The header and the claims MUST be serialised in RFC 8785 canonical form before
base64url encoding, so that every implementation signs the same bytes for the same receipt and the
vectors can hold them to it. The signature is Ed25519 over the ASCII bytes of the first part, a
dot, and the second part.

**Transport.** The response header `x-agent-safe-effect-receipt`, on every response to a request
the provider accepted at step 8: the `2xx` of an effect and the `4xx` of the provider's own refusal
alike. A signed refusal is evidence too. A response to a request refused at steps 0 to 8 carries no
receipt: nothing was claimed of the provider.

**What the executor does.** `@decionis/agentsafe` verifies nothing in the receipt. It forwards the
header's value verbatim as `effect_receipt` in `finalize-token`, whatever the attempt's outcome,
when the value has the shape of a compact JWS and is at most 20000 characters; otherwise it drops
it, since the authority refuses a malformed body and the commit outcome would be lost with it. Its
effect plane does read what the receipt _states_, the `effect` block's status and digest, and
compares that statement with its own account: the outcome the provider answered with, the effect
the grant authorised, and the effect the adapter observed. Agreement is recorded; a receipt that
names no digest is recorded as silent; a receipt whose status contradicts the outcome, or whose
digest differs from the authorised effect or from the observation, is a mismatch the executor
reports as `EFFECT_MISMATCH`, confirms nothing from, and treats as the same exception as an
observation that did not match. A statement is not a verification: the authority's verdict on the
signature is the one that counts, and the executor's comparison is what lets two witnesses'
disagreement be seen at all.

**What the authority does.** It verifies the signature under the key the organisation registered
for `kid`, requires `iss` to be the issuer registered with that key and `aud` to be itself, and
checks that the receipt describes the finalization in hand: `sub` is the grant's `jti`,
`decision_id` and `dossier_id` are the grant's, `claim_token_digest` is the digest of the claim
token being finalized, and `intent_hash`, when present, is the one the grant bound. It records the
receipt in the commit evidence as presented, verified or not, with one of six verification codes
(`EFFECT_RECEIPT_VERIFIED`, `_MALFORMED`, `_KEY_UNKNOWN`, `_SIGNATURE_INVALID`,
`_BINDING_MISMATCH`, `_KEYS_UNAVAILABLE`), and reports the verdict in the finalize response. When
the grant carried `expected_effect_digest` and the verified receipt carries `effect.digest`, the
receipt is read as Protocol 1.1 `SIGNED_RECEIPT` effect evidence with the provider key as
observer, `CONFIRMED` only when the digests agree, the status is `EFFECTED` and the outcome is
`COMMITTED`. **A receipt is never a reason to refuse a finalization**: what it changes is the
evidence, not the commit.

**What a receipt is not.** A receipt authorises nothing and consumes nothing. A receipt for a grant
the authority never claimed is recorded as a binding mismatch, and a receipt cannot be presented in
place of an attestation. The executor's effect plane keeps reconciling its own observation; the
receipt is the provider's statement beside it, compared with it, not a replacement for it.

## 8. Test vectors and claiming conformance

[`conformance/provider`](../../conformance/provider/README.md) holds one JSON file per case. Each
is self-contained: the provider's settings (whether it effects, its clock window, the time to
verify at, the issuer it trusts), the executor keys it knows, the authority JWKS, and a sequence of
requests, each with the outcome the procedure MUST reach. Every vector is generated by the
executor's own signer and an independent signer for the attestation, and is run, in this
repository, by the reference verifier in `@decionis/agentsafe` (`verifyProviderRequest`), by the
Go implementation in `verifiers/envoy`, by the Java implementation in `verifiers/spring`, by the
Rust implementation in `verifiers/rust`, and by the .NET implementation in `verifiers/dotnet`,
five implementations that must agree. The receipt vectors in
[`conformance/provider/receipts`](../../conformance/provider/README.md) pin the other half: for
each, the claims, the canonical `header.payload` every implementation MUST produce before signing,
and a token signed by a key made for that generation whose public half the vector carries. An
implementation of VP-3 passes them by producing that exact signing input and a signature its own
key verifies; each of the five does.

To claim conformance, an implementation states the profile identifier and version, the level, and
that every vector at that level passes with the outcomes the vectors name. It SHOULD state the
tier (section 1) at which it is deployed, since the vectors cannot.

## 9. Deployment notes

- **Executor keys.** The provider issues, or records, the executor's Ed25519 public key under a
  `keyid` of its choosing; the executor names it with `DOWNSTREAM_SIGNING_KEY_ID`. Rotation is a
  new `keyid`; the old one is withdrawn once no dispatch can still carry it.
- **Authority keys.** Fetch the JWKS over HTTPS from the authority's own API origin, never from
  a location the request names. Cache it; on an unknown `kid`, refresh at most once per bounded
  interval before refusing. The authority rotates with overlap, so a verifier keeps the previous
  key for the overlap.
- **Clock.** Keep the provider's clock disciplined. `exp` is authoritative and short, the length of
  the lease the authority named in `claim_lease_expires_at`; the `created` window is defence in
  depth.
- **Replay store.** Keyed by grant id, expiring at `exp`, shared by every instance that can effect.
  Since a lease is tens of seconds, the store is small.
- **Body.** Verification needs the whole body: a hop that streams bodies through cannot verify, and
  MUST buffer up to a bound it sets and refuse beyond it. In Envoy, `ext_authz` needs
  `with_request_body` with `allow_partial_message: false`; the reference in `verifiers/envoy`
  answers the check with the refusal status and body above, which Envoy returns to the executor.
  In Kong, the plugin in `verifiers/kong` reads the body itself and runs the same Go verifier.
- **Paths.** Verify with the path as received, before any rewrite the hop applies.
- **Receipt keys.** Keep the receipt key with the same care as the credential the system of record
  accepts: a receipt is the provider's signature. Register the public half with the authority
  before the first receipt is signed, since a receipt under an unregistered `kid` is recorded as
  `EFFECT_RECEIPT_KEY_UNKNOWN` and confirms nothing. An authorization hop that runs the procedure
  in front of the system of record answers before the effect, so its access phase cannot sign a
  receipt; the receipt is the effecting layer's, or the hop's response phase signs one from what
  the system of record reports about the effect in its answer, as the Kong plugin in
  `verifiers/kong` does with `receipt_key_file`. Envoy's `ext_authz` has no response phase and
  signs none.

## 10. Security considerations

- **The query is not covered.** An effecting endpoint MUST NOT let a query parameter change what
  is effected, or MUST refuse an effecting request that carries one.
- **A shared secret can be forged by the provider.** `hmac-sha256` makes VP-1 a statement the
  provider could have made itself; it is acceptable within one trust domain, and the attestation at
  VP-2 remains the authority's either way. For a system of record, prefer `ed25519`.
- **The attestation is public.** It is verifiable by anyone and a bearer for nothing: it carries no
  claim token, the executor's signature binds it to one request, and the lease bounds it in time.
  What it reveals is identifiers and digests, not parameters.
- **Replay.** A store that is per instance lets a second instance effect the same grant; the
  store's visibility, not its durability beyond the lease, is the requirement.
- **Two digests, on purpose.** The content digest binds the bytes; the attestation's digest binds
  the canonical parameters. A body with the same parameters in another key order or with other
  whitespace passes step 7 and fails step 1 unless the executor signed exactly those bytes, which
  is the intended division: the executor vouches for the bytes, the authority for the parameters.
- **Refusals are informative.** The reason code is for the executor's record; the response carries
  nothing else from the request.
- **A receipt is public too.** It is verifiable by anyone who holds the registered public key and a
  bearer for nothing: it names identifiers and digests, never parameters or the claim token. What
  it commits the provider to is what it says it did.

## 11. Status, versioning and citation

The profile identifier `agent-safe.verifying-provider/1` changes only on an incompatible change to
the procedure or the vectors. The version in this document's first line changes with the text.
Released versions of this repository, this page included, are archived under the Zenodo concept
DOI [10.5281/zenodo.22312955](https://doi.org/10.5281/zenodo.22312955); cite the version DOI of the
release that carries the text you implemented ([release metadata](../zenodo-release-metadata.md)).
The pages on the same procedure from the executor's side are [execution binding](./execution-binding.md),
[claim and finalize](./claim-finalize.md), [evidence](./evidence.md), and
[bypass resistance](../bypass-resistance.md).
