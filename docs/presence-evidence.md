# Protocol: Presence Evidence semantics

This section defines what a Presence receipt is, what it proves, what it never does, and how the
execution authority consumes it. It is written so that a reader who has not seen the rest of the
architecture can evaluate the claim "a verified human was in the loop" on its own terms.

## Terms

| Term     | Meaning                                                                                                                                                  |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Intent   | The immutable, short-lived proposal an agent made: action, target, parameters, and trusted runtime context, identified by its canonical SHA-256 hash.    |
| Ceremony | The identity and assurance verification a person completes on their own device: FIDO2/WebAuthn, optionally with active liveness, at a required level.    |
| Receipt  | The signed Presence Record sealed after a ceremony, identified by a receipt dossier id and chained to the request that produced it.                      |
| Evidence | The reference an executor returns to the authority: `{ provider: "presence", requestId, receiptDossierId }`. It contains no secret and no authority.     |
| Grant    | The single-use execution token the authority issues for one exact intent after evaluation. Only a grant authorizes execution.                            |
| Delivery | Transport of an opaque invitation to the person: push, a customer channel, or a printed link. Delivery carries no authority; possession is not approval. |

## What a receipt proves

When the authority accepts evidence, all of the following were established against Presence, not
against the requester:

1. The verification request reached a terminal `ALLOWED` state with result `ALLOW`, and the receipt
   named in the evidence is the receipt that request produced.
2. The receipt's signature and chain verify under Presence's published keys.
3. The request's action context names the same action type and target resource as the intent.
4. The request is bound to the intent hash: a structured intent-hash field when Presence emits one,
   otherwise the mandatory `Intent hash` display field the person saw before authenticating.
5. The approving identity and its role are present, and the approval has not expired.
6. Any inherited conditions are digested into the evidence, and the ceremony's authenticator details
   (method, AAGUID, platform, user-verified flag) are carried as evidence when Presence reports them.

A receipt therefore proves: this identity, holding this role, completed this ceremony, for exactly
this intent, within this window.

## What a receipt never does

- **It never executes.** A receipt is not a grant. The authority evaluates the original intent
  again under current policy with the receipt as an input, and only that evaluation can issue a
  grant. Policy may still block after a valid approval.
- **It never transfers.** The receipt is bound to one intent hash. Presented for another intent,
  even one differing only in beneficiary or amount, verification fails and the authority blocks.
- **It never revives.** An intent lives at most five minutes. Approval arriving after expiry is
  discarded; a fresh intent needs a fresh evaluation and a fresh ceremony.
- **It never comes from the agent.** Evidence is attached by the trusted executor, or resolved by
  the authority itself in managed mode. Anything the agent writes into its proposal is parameters,
  which the sealed handler registry validates and the authority treats as untrusted input.
- **It is re-presented at claim.** A grant issued on evidence is claimed with the same evidence, and
  the authority re-verifies it at that moment. A claim without it is refused.

## Two integration modes, one semantics

| Mode    | Who talks to Presence           | What the executor sends to the authority                       | What the executor receives                         |
| ------- | ------------------------------- | -------------------------------------------------------------- | -------------------------------------------------- |
| DIRECT  | The trusted executor            | The receipt reference as `evidence` on re-evaluation and claim | An `ALLOW` decision with a grant, or a block       |
| MANAGED | The authority, server to server | Approver and ceremony constraints outside the canonical intent | A grant-free pending state, then a terminal status |

In both modes Presence signs its own evidence independently, the authority verifies it directly with
Presence, and the executor reaches execution only through the same claim-before-handler grant path.
Managed mode removes Presence credentials and invitation handling from the executor; it does not
weaken verification.

## Failure semantics

| Reason code                                                            | Meaning                                                                 |
| ---------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `PRESENCE_RECEIPT_REQUIRED`, `PRESENCE_PROOF_MISSING`                  | Evidence absent or incomplete                                           |
| `PRESENCE_OUTCOME_NOT_ALLOW`, `PRESENCE_DENIED`                        | The person denied, or the request expired, escalated, or was cancelled  |
| `PRESENCE_DOSSIER_INVALID`                                             | The receipt's signature or chain failed to verify                       |
| `PRESENCE_ACTION_MISMATCH`, `PRESENCE_INTENT_HASH_MISMATCH`            | The receipt is bound to a different action, target, or intent           |
| `PRESENCE_APPROVER_IDENTITY_MISSING`, `PRESENCE_APPROVER_ROLE_MISSING` | The receipt does not establish who approved or in what role             |
| `PRESENCE_APPROVAL_EXPIRED`, `PRESENCE_INTENT_EXPIRED`                 | The approval or the intent is outside its window; recapture is required |
| `PRESENCE_APPROVAL_STALE`                                              | A claim arrived without the evidence the decision was made with         |

Every failure is a block with a stable reason code. No failure produces a grant, and no failure
retries a side effect.

## Invariants, stated once

1. Evidence is necessary when policy requires it and never sufficient on its own.
2. Evidence binds to exactly one intent hash and one identity in one role.
3. Evidence is time-bound by the intent and cannot outlive or revive it.
4. Evidence is verified by the authority against Presence, never trusted from the requester.
5. Only a grant executes, and a grant is claimed exactly once.

The wire shapes are pinned by the [contract harness](../tests/integration/contract/README.md); the
mechanics are exercised offline by the [golden adversarial demo](../examples/golden-adversarial-demo)
and against the live services by the [direct](../examples/presence-live-approval) and
[managed](../examples/presence-managed-approval) approval examples.
