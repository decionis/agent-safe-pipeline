# BEAP: what the executor implements

`@decionis/agentsafe` implements the **executor-side subset** of BEAP-L3 listed in this document,
using the transport mapping the profile itself defines in Appendix B.5. BEAP v1.0, published on
2026-09-15, names it in section 24.5 as the reference **Trusted Executor**: the process a bank
deploys at the execution boundary. That is a designation of one layer, and the profile says so
itself; it is not the authority, whose half of the runtime (policy, grants, dossiers, the L1 and L2
requirements) lives elsewhere, and **no conformance level is claimed**: BEAP-L1-ACT-14 forbids
claiming one while L1 and L2 are the authority's, and the authority's own conformance is not this
repository's to assert.

The identifiers this build emits are still the frozen 0.1 draft's (`decionis.beap/v0.1`, mirrored
under `profiles/beap/v0.1`), which 1.0 carries forward unchanged apart from the version it names:
no canonicalization rule, field, verdict, outcome token or registry entry changed between them.
The one thing 1.0 adds, the claim attestation of its section 19.1, this executor already
implements (below). The move to the 1.0 identifiers changes every intent digest and is made
together with the profile's other runtimes.

The profile mirror under `profiles/beap/v0.1` is the source this build was written against. The
runtime never reads it. `EffectProjections.ts` and `ReasonCodes.ts` are typed constants tagged
`decionis.beap/v0.1`, and a test hashes every registry file against the profile's own
`registries/MANIFEST.sha256` and asserts each typed entry equals the mirror, so a drift in the
profile is a failing test rather than a silent disagreement.

## The transport mapping

A BEAP action reaches the executor as an ordinary proposal. Appendix B.5 decides every field of it,
and the executor derives the transport's own fields from the action rather than trusting them:

| Transport                             | Value                                                     |
| ------------------------------------- | --------------------------------------------------------- |
| `proposal.action`                     | `beap.<domain>.<type>`, lower case                        |
| `proposal.target`                     | `<target.type>:<target.ref>`, the type lower case         |
| `proposal.parameters`                 | The canonical `BankingAction`, unchanged                  |
| `idempotency_key`                     | `action.request_id`, which must be the same string        |
| `context.beap_profile`                | The action's own profile identifier                       |
| `context.beap_intent_digest`          | The JCS digest of the canonical action                    |
| `context.beap_expected_effect_digest` | The JCS digest of the action's expected-effect projection |
| `context.beap_batch_manifest_digest`  | The batch's manifest digest, when the action carries one  |

Every `context` field is **computed by the executor**, never accepted from the caller: the
proposal schema refuses a caller-supplied context outright, and `caller_principal` sits beside
these. The expected-effect digest is also set on the intent itself, so the grant the authority
issues commits to it and the claim is cross-checked against it.

`intent_digest` (BEAP's digest of the action) and `intent_hash` (the transport's hash of the
captured intent) are different values with different inputs. Both are carried, both are labelled,
and neither substitutes for the other.

The authority's `execution_payload_digest` is a third value with the same input as the first: the
digest it bound over the canonical action parameters. On the claim, the pipeline recomputes the
digest of the parameters it captured under the profile the authority names and refuses the claim
on any difference, which is BEAP-L3-BND-01 as written. Because the canonical action is the
parameters unchanged, that digest and `beap_intent_digest` are one value computed twice, once by
each side. A profile the pipeline cannot reproduce is refused too: a digest that cannot be checked
is not evidence.

## What the system of record can verify

A claim also returns the authority's **claim attestation**: a compact EdDSA JWS, signed with the
execution-grant key, over the grant, the decision, the dossier, the binding (intent hash, payload
digest and profile, expected-effect digest, nonce, correlation), a digest of the claim token, and
an expiry equal to the claim lease. The executor forwards it with the dispatch, and a
`SIGNED_REQUEST` credential covers it together with `x-agent-safe-grant-id` and
`x-agent-safe-decision-id`. A provider that verifies the attestation against the authority's
public JWKS can then refuse an instruction the authority never claimed, not merely one the
executor never signed: BEAP-L3-ADP-03's "verified assurance of grant validity, intent binding
... and claim status" reaches the adapter's provider, not just the adapter. The package README
carries the verification procedure and the offline proof runs it.

## What is refused before the authority is asked

The binder runs on capture, and every disagreement is a `422` that costs no dossier and no grant:

| Code                           | What disagreed                                                                                   |
| ------------------------------ | ------------------------------------------------------------------------------------------------ |
| `BANKING_ACTION_INVALID`       | The parameters are not a canonical action, or its amount is not readable at the currency's scale |
| `BANKING_ACTION_NAME_MISMATCH` | The transport's action name is not the one the action derives                                    |
| `BANKING_TARGET_MISMATCH`      | The transport's target is not the action's target                                                |
| `BANKING_REQUEST_ID_MISMATCH`  | `action.request_id` is not the idempotency key the attempt is bound to                           |
| `BANKING_DOWNSTREAM_MISMATCH`  | The action names a provider, operation, or environment this process does not serve               |
| `BANKING_ACTOR_MISMATCH`       | The action's actor is not the principal the door authenticated                                   |

## Requirement coverage

| Area                                     | State     | What holds, and what does not                                                                                                                                                                                           |
| ---------------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| §20 Adapter contract                     | Satisfied | `EffectAdapter` is prepare, execute, observe, reconcile; three of the four are pure and `reconcile` only reads                                                                                                          |
| §21 Credential isolation                 | Satisfied | A handler never holds a credential value; headers are resolved at the moment of dispatch from the secret store                                                                                                          |
| §22.7 Expected-effect projection         | Partial   | The registry's fields are mirrored exactly; the **path** each field is read from is this executor's own rule                                                                                                            |
| §22.8 Effect comparison and mismatch     | Satisfied | Field by field over the projection; a mismatch is named, recorded, alerted, and by default halts the executor                                                                                                           |
| §22 Deterministic refusal                | Satisfied | A provider reached and refusing is reported as definitely not executed, carrying its own reason code                                                                                                                    |
| §22 Observation methods                  | Satisfied | Only a method the registry marks sufficient can confirm; an acknowledgement never does                                                                                                                                  |
| §19 Claim before commit                  | Satisfied | The grant is claimed before the dispatch and the claim is journaled before the side effect                                                                                                                              |
| BEAP-L3-CLM-06 claim lease               | Satisfied | The authority's `claim_lease_expires_at` reaches the executor as `leaseExpiresAt` and bounds every dispatch                                                                                                             |
| BEAP-L3-BND-01 payload digest comparison | Satisfied | The authority's `execution_payload_digest` is compared with the pipeline's own digest of the captured parameters under `RFC8785/JCS`; a difference, or a profile it cannot reproduce, refuses the claim before dispatch |
| §17 Batch manifests                      | Not built | The manifest digest rides in the trusted context; the manifest route and the outcome ledger are not here yet                                                                                                            |
| L1 and L2                                | Not this  | The authority's half of the runtime: policy, grants, dossiers. Not in this repository and not asserted by it                                                                                                            |

### The projection path rule

The profile names the fields of an expected effect but not where in the action each is read from.
This build uses one rule, written down rather than implied:

- `amount` and `currency` come from `financial_context`
- `source_ref`, `destination_ref` and `parameters.*` from `requested_effect`
- `subject` and `target` are the entity's `type:ref`
- `batch.*` from `batch`

A field the action does not carry is a refusal, not an absent key, because an expected effect with
a hole in it would compare equal to an observation with a different hole. The rule is
implementation-defined until the profile's owner confirms it.

## Amounts

On the wire an amount is BEAP's decimal string, and the schema refuses a JSON number for one, so
`1e3`, `-0`, and a float never reach the canonicaliser. In the process the same amount is a
`bigint` of minor units with an explicit ISO 4217 exponent: an unknown currency code is
`CURRENCY_UNSUPPORTED`, and a decimal whose scale is not the currency's is `AMOUNT_SCALE_INVALID`
rather than padded. `250000.0` is not how CHF writes an amount, and accepting it would hash a
different string than the one the authority signed.

An `iban:` reference is check-digit validated. The profile recommends opaque references precisely
so a beneficiary is not readable from an intent, and an executor that only ever sees a digest
cannot validate a beneficiary at all; where an institution does put an IBAN on the wire, a typo
that would still have reached a valid-looking account is caught before the authority is asked.

## Where the evidence goes

The adapter's observation becomes two records. One is the executor's own effect record, digested
over its canonical form and reported in the response's `effect` block; it carries statuses,
digests, identifiers and codes, and never a provider body, a parameter, or a credential. The other
is the Protocol 1.1 `AuthorityEffectEvidence` the verifier attaches to the finalization, bound to
the grant by the expected-effect digest and the commit correlation id.

A mismatch is reported to the authority as `UNCONFIRMED` **with the digest that was observed**,
not hidden. `CONFIRMED` in the executor's own record requires an observation method the registry
marks sufficient and a projection that matched. Whether the **authority** records that
confirmation is separate: it accepts confirmed evidence only from an observer identity its own
trusted-observer allowlist names, which is the deployer's to set, and when it refuses one the
verifier finalizes again without the observation rather than trading the commit record for it. See
[execution outcomes](execution-outcomes.md).
