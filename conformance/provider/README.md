# agent-safe.verifying-provider/1 — conformance vectors

Vectors for the [Verifying Provider Profile](../../docs/authority/verifying-provider.md), one JSON
file per case under `vectors/`. Each is self-contained, so an implementation in any language runs
it with nothing else: the provider's settings, the executor keys it knows, the authority's JWKS,
and a sequence of requests with the outcome the procedure MUST reach for each.

```json
{
  "profile": "agent-safe.verifying-provider/1",
  "version": "0.1",
  "vector": "dispatch-replayed-within-lease",
  "level": "VP-2",
  "description": "…",
  "provider": {
    "effects": true,
    "clock_window_seconds": 300,
    "now": "2026-09-19T12:00:00.000Z",
    "authority_issuer": "https://authority.example"
  },
  "executor_keys": [
    { "keyid": "…", "alg": "ed25519", "public_pem": "-----BEGIN PUBLIC KEY-----…" },
    { "keyid": "…", "alg": "hmac-sha256", "shared_material_utf8": "…" }
  ],
  "authority_jwks": { "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": "…", "kid": "…" }] },
  "requests": [
    {
      "method": "POST",
      "path": "/v1/wires",
      "headers": {},
      "body": "…",
      "expect": { "outcome": "ACCEPT" }
    },
    { "…": "…", "expect": { "outcome": "REFUSE", "reason_code": "GRANT_REPLAYED" } }
  ]
}
```

- `provider.now` is the instant to verify at; every clock check in the vector is relative to it.
  `provider.effects` says whether the provider effects, which decides what the signature must
  cover. `provider.clock_window_seconds` and `provider.authority_issuer` are the provider's
  settings the profile leaves to it; the issuer here is synthetic, since the vectors' attestations
  are signed with a key made for them, and a provider deployed against Decionis trusts
  `https://decionis.com`.
- `executor_keys` are the keys the provider issued to the executor, by `keyid`: an Ed25519 public
  key as SPKI PEM, or the UTF-8 text of a shared HMAC secret. `authority_jwks` is the authority's
  execution-grant key set as its well-known path serves it.
- `requests` run in order against one replay store, which is how the replay vector expresses a
  second presentation. Header names are lower case. `body` is `null` for a request that carried
  none; otherwise it is the exact text, whose bytes the content digest covers.
- `expect.outcome` is `ACCEPT` or `REFUSE`; a refusal names its `reason_code`, one of the four the
  profile defines.

## Running them

Three implementations in this repository run every vector, and must agree:

- the reference in `@decionis/agentsafe`, `verifyProviderRequest`, through
  `packages/agentsafe/test/verify/VerifyingProvider.test.ts`, which discovers every file here;
- the independent Go implementation in [`verifiers/envoy`](../../verifiers/envoy/README.md),
  through `go test ./...` in that module;
- the independent Java implementation in [`verifiers/spring`](../../verifiers/spring/README.md),
  through `mvn -B test` in that module.

An implementation elsewhere claims a level by passing every vector at that level with the outcome
each names, and says so in the terms of the profile's section 8.

## Regenerating them

```bash
node scripts/GenerateProviderVectors.mjs
```

The requests are signed by the executor's own credential, `SignedRequestCredential`, so a vector
is what `@decionis/agentsafe` actually sends; the attestations are signed with `node:crypto`
alone, the way the authority signs one, so the two signers are independent. Keys are fresh on
every run, and only the public halves are written: a vector holds nothing that was ever a
credential. Regenerate when the executor's wire format or the profile changes, never to make a
failing implementation pass.

## What the cases cover

| Vector                                               | Level | Refuses with, or accepts                     |
| ---------------------------------------------------- | ----- | -------------------------------------------- |
| `dispatch-attested-accepts`                          | VP-2  | accept                                       |
| `dispatch-replayed-within-lease`                     | VP-2  | accept, then `GRANT_REPLAYED`                |
| `dispatch-hmac-attested-accepts`                     | VP-2  | accept                                       |
| `attestation-digest-is-canonical-not-raw`            | VP-2  | accept                                       |
| `read-base-components-accepts-for-read`              | VP-1  | accept, for a provider that effects nothing  |
| `read-base-components-refused-by-effecting-provider` | VP-1  | `SIGNATURE_INVALID_OR_INCOMPLETE`            |
| `copied-headers-unsigned`                            | VP-1  | `SIGNATURE_INVALID_OR_INCOMPLETE`            |
| `body-altered-after-signing`                         | VP-1  | `SIGNATURE_INVALID_OR_INCOMPLETE`            |
| `covered-header-altered-after-signing`               | VP-1  | `SIGNATURE_INVALID_OR_INCOMPLETE`            |
| `signature-omits-grant-components`                   | VP-1  | `SIGNATURE_INVALID_OR_INCOMPLETE`            |
| `unknown-keyid`                                      | VP-1  | `SIGNATURE_INVALID_OR_INCOMPLETE`            |
| `created-outside-window`                             | VP-1  | `SIGNATURE_INVALID_OR_INCOMPLETE`            |
| `dispatch-hmac-wrong-material`                       | VP-1  | `SIGNATURE_INVALID_OR_INCOMPLETE`            |
| `attestation-signed-by-unknown-key`                  | VP-2  | `ATTESTATION_INVALID`                        |
| `attestation-wrong-typ`                              | VP-2  | `ATTESTATION_INVALID`                        |
| `attestation-payload-tampered`                       | VP-2  | `ATTESTATION_INVALID`                        |
| `attestation-issuer-differs`                         | VP-2  | `ATTESTATION_INVALID`                        |
| `attestation-for-another-grant`                      | VP-2  | `ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST` |
| `attestation-for-another-decision`                   | VP-2  | `ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST` |
| `attestation-intent-hash-differs`                    | VP-2  | `ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST` |
| `payload-changed-after-claim`                        | VP-2  | `ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST` |
| `attestation-expired`                                | VP-2  | `ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST` |
| `attestation-canonicalization-profile-unknown`       | VP-2  | `ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST` |
| `body-not-i-json`                                    | VP-2  | `ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST` |

`payload-changed-after-claim` is the case the profile exists for: the amount raised after the
claim, the executor's signature valid over the changed body, the authority's attestation valid
over the original parameters, and the two digests disagreeing at the provider.
