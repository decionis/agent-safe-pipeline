# agent-safe.intent/1 — conformance vectors

Cross-implementation hash vectors for `CanonicalIntentHasher`. Each file
contains a `binding`, the expected canonical JSON bytes (`canonical_json`),
and the SHA-256 digest (`intent_hash`) over those bytes.

`IntentConformance.test.ts` discovers **every** vector in this directory and
validates both the canonicalization and the digest. A vector may also carry
`mutations`: single-field changes to its binding, each with its own
`canonical_json` and `intent_hash`, which the test holds to be distinct from
the base and from one another.

## The Compromised Principal Test

`compromised-principal.json` is the test the [execution intent](../../docs/execution-intent.md)
page describes as a hash vector: an infrastructure agent's `deployment.scale`
intent (`prod-eu`, `inference`, 96 replicas) and eight mutations a valid
principal could make after authorization. The replica count raised to 960,
the service, the cluster, the resource, the principal, the expiry, the
idempotency key and the environment: every one is inside the hash, so a grant
for the base authorises none of them. An implementation MUST reproduce all
nine hashes, and they MUST all differ.

## Intentional text distinctions (no normalization)

The canonicalizer performs **no Unicode normalization** — it sorts object
keys by UTF-16 code units and encodes strings verbatim via JavaScript's JSON
encoding. These forms are intentionally **distinct** and produce different
hashes:

| Form              | Example                              | Note                                   |
| ----------------- | ------------------------------------ | -------------------------------------- |
| NFC composed      | `"caf\u00e9"` (é, U+00E9)            | distinct from NFD                      |
| NFD decomposed    | `"cafe\u0301"` (e + combining acute) | distinct from NFC                      |
| Astral characters | `"🚀"` (U+1F680)                     | encoded verbatim as UTF-8, no escaping |

## Number encoding

JavaScript's JSON encoding is used verbatim:

| Value  | Canonical bytes | Note                           |
| ------ | --------------- | ------------------------------ |
| `-0`   | `0`             | negative zero collapses to `0` |
| `1.5`  | `1.5`           | fractional preserved           |
| `1e21` | `1e+21`         | exponent form (`toJSON`-style) |

## Key sort order

Keys sort by UTF-16 code unit, case-sensitive: `"Z"` (0x5A) < `"za"` (0x7A)
< `"z\u00e9"` (0x7A, 0xE9) < `"\u00c9clair"` (0xC9). This is the ECMAScript
`Array.prototype.sort()` default (lexicographic code-unit order), documented
here because it is not obvious and cross-language implementations must match
it exactly to reproduce the hashes.
