# Human approval

A **ceremony** is the human identity and assurance verification performed by Presence, such as
FIDO2/WebAuthn with optional active liveness. **Evidence** is Presence's signed result proving which
identity completed which ceremony for which exact bound intent. **Delivery** is transport for an
opaque invitation locator only; push, desktop notification, or a customer-operated channel may
carry it. Possessing or opening that invitation is not approval.

> Delivery does not confer authority.

Presence is an evidence provider, not the execution authority. Client-side booleans, screenshots,
copied proof strings, invitation possession, or model claims such as “the user approved” are never
sufficient. Decionis independently verifies Presence's signature and receipt binding, then evaluates
the original intent again under current policy before it may issue a normal execution grant.

> Human approval is necessary when policy requires it, but Presence evidence is not transferable
> execution authority.

Transport failures, unknown verdicts, malformed or unbounded receipt identifiers, and independent
reauthorization failures produce stable fail-closed outcomes. Raw Presence or authority errors are
not returned through the coordinator.

If the intent changes or expires during approval, capture a new intent and start again. Neither a
valid receipt nor a previously delivered invitation revives or transfers to a replacement intent.

> Presence authorization cannot revive an expired execution intent.

## Direct and managed integration

Both modes end at the same authority boundary and use the same normal grant, atomic claim, handler,
and finalization path:

- **DIRECT** — the trusted executor uses `PresenceApprovalCoordinator` to create and poll the
  Presence request, then returns the receipt reference to Decionis for verification and
  re-evaluation. The re-evaluated decision carries that evidence, and `DecionisGrantVerifier`
  presents it again when claiming the grant.
- **MANAGED** — the trusted executor requests `{ mode: "MANAGED" }` from `DecionisGate`. Decionis
  creates the Presence request server-to-server and returns a grant-free pending escalation. The
  executor polls Decionis with `waitForAuthorization`; it never needs Presence credentials or
  receives Presence evidence. When Decionis has verified the receipt and re-authorized the exact
  intent, status returns a normal ALLOW decision and grant. The normal claim contains no
  client-supplied managed Presence evidence.

The existing direct coordinator remains appropriate when an application owns delivery and Presence
coordination. Managed mode is orchestration convenience, not weaker authorization.

## Presence attestations

A presence provider other than Presence can prove a person was there, such as a cardholder tapping
the physical card on their own phone in the issuer's app. Its proof is a compact Ed25519 JWS over
the intent (`typ: decionis-presence-attestation+jwt`), and it reaches Decionis as
`evidence.humanApproval: { provider: "attestation", attestation }` on a fresh `enforce-and-bind`
of the same intent. `DecionisGate` checks only the shape (a compact JWS of at most 20,000
characters, nothing else in the object) and fails closed with `HUMAN_APPROVAL_EVIDENCE_INVALID`
before asking anything otherwise. Decionis verifies the signature under the key the organisation
registered for that provider, the audience, the expiry and the intent binding, and writes the
approval facts into the evaluation context; an `ESCALATE` becomes `ALLOW` only where policy has a
rule that matches them. The attestation is evaluated once: unlike a Presence receipt it is not
presented again at the claim. This package never verifies, logs, or records it. The trusted
executor accepts one on `/v1/escalations` as `{ mode: "ATTESTATION", intent, attestation }`, from
the proposer or from an `OPERATOR` holding `escalations.resume` (the issuer app's backend, where
the tap lands).

An identity wallet that signs for a person enters the same way and in no other shape. Proof's
[x401](https://x401.proof.com/spec/) (specification 0.2.0, a draft, read on 21 October 2026) asks
an agent for an OpenID4VP presentation of a verified identity; it defines no object that signs a
transaction's terms. A deployment that wants such an approval to admit an action runs the x401
exchange itself, as the verifier, and issues an attestation from what it verified: its claims
`intent_id` and `intent_hash` name the intent the person approved, and it is signed with the key
the organisation registered for that provider. Decionis refuses it for any other intent, so a
changed amount or recipient is a different intent and the approval does not follow it. The
attestation proves that the organisation's verifier accepted the presentation; the person's own
signature stays with that verifier, and whether an x401 request can carry the intent hash as
OpenID4VP `transaction_data`, so that the person's key signs over it, the specification does not
yet say. An OpenID4VP presentation, an SD-JWT or mdoc credential, or a WebAuthn assertion is not
an `attestation`: `DecionisGate` refuses what is not a compact JWS with
`HUMAN_APPROVAL_EVIDENCE_INVALID`, and Decionis refuses a JWS of any other `typ`.

A producer's signed standing signal is the other evidence a proposal can carry, and it is not an
approval: `signals: [{ "token": "<compact JWS>" }]` on `POST /v1/actions`, at most eight, reaches
Decionis as `evidence.signals` on the first evaluation (and with a managed escalation, which
forbids approval evidence only). `DecisionGate` checks only the shape and fails closed with
`SIGNED_SIGNAL_EVIDENCE_INVALID` otherwise; Decionis verifies each token under the key the
organisation registered for its producer with purpose `signed_signal`, writes the facts under
`agent_safe.signed_signals.<name>` for policy to name, and refuses one it cannot verify with a
`SIGNED_SIGNAL_*` code the proposal then fails closed with. The token is kept on no decision, in
no journal line and in no hold row; the card guide's
[standing permission](./banking/card-authorization.md#a-standing-permission-tap-to-authenticate)
is the worked example.

Where a hold goes is the policy's to say. A rule's `verification_requirements` may name a method
`CARD_TAP` and a `provider` (an admitted presence provider's id, `koard` for one); Decionis reads
the decision's `escalation_requirement` for a runtime at 0.3.7 or later, and `DecionisGate`
carries it as `DecisionGate.escalationRequirement`: the selector (a kind and a role, never a
person) and the verification (`provider`, `methods`, `level`). A provider other than `decionis`
means no Presence ceremony is asked for; the executor hands the caller an `ATTESTATION` handoff
with the routing in `requirement` and waits for that provider's attestation. Decionis also tells
the organisation's webhook subscribers: `authority.escalation_required` carries the same
`selector` and `verification`, and `authority.escalation_resolved` carries what became of the
hold once a proof was presented, the fresh decision's outcome or `REFUSED` with the code, with the
proof's facts and never the proof.

## Ceremony requirements and delivery

`PresenceApprovalCoordinator` accepts `requirements`, the docs/22 verification requirements Presence
enforces before it seals a receipt, and `ttlSeconds`, the approval-request lifetime (30 to 600
seconds). A FIDO2 approval is `{ level: "STANDARD", methods: ["WEBAUTHN"] }`; adding active liveness
is `{ level: "HIGH_CONFIDENCE", methods: ["WEBAUTHN", "ACTIVE_LIVENESS"] }`. Omitted, Presence applies
its default standard-confidence device proof.

The approver identity passed to the direct coordinator is the subject Presence routes the request to.
Presence pushes to enrolled mobile devices bound to that identity; it does not send email, and
neither does the Decionis execution-authority path. When no enrolled device exists, deliver the
`approval_url` from the `HUMAN_REQUIRED` result to the person over your own channel. Putting the
approver's email in the trusted intent context, for example under `approver_email`, keeps the
routing identity hash-bound and recorded in the Decision Dossier. The
[live approval example](../examples/presence-live-approval) runs both ceremonies against the real
services. The [managed approval example](../examples/presence-managed-approval) demonstrates the same
ceremonies while calling Decionis only.

For managed mode, `approver.principal_id` and `approver.role_id` are constraints supplied by trusted
executor configuration. `APPROVER` is a human approval role, not agent, executor, administrator, or
service-account authority. The requesting agent cannot self-assign it; Decionis and verified
Presence evidence resolve the effective identity and role. Policy-specific roles such as
`TREASURY_APPROVER` remain distinct constraints.

## Bounded direct polling

`PresenceApprovalCoordinator.resolveAndReauthorize` polls a `HUMAN_REQUIRED` request until Presence
returns a terminal outcome. Polling uses capped exponential backoff with bounded jitter and stops at
the earliest of:

- 20 outcome lookups;
- a 60-second polling deadline;
- the captured intent's `expiresAt`; or
- cancellation through the optional `AbortSignal`.

The defaults use a 250 ms initial delay and a 2-second maximum delay. Operators can tighten these
limits with the coordinator's `maxAttempts`, `deadlineMs`, `initialDelayMs`, and `maxDelayMs`
options. Invalid settings are rejected when the coordinator is created. The clock, sleep function,
and jitter source are injectable so timeout and cancellation behavior can be tested without relying
on wall-clock timing.

Only a terminal `PROCEED` response with the original request ID and a bounded receipt dossier ID is
submitted to Decionis. Pending responses never authorize execution. The coordinator returns a
fail-closed `BLOCK` when it observes:

- `PRESENCE_TIMEOUT` after the deadline or attempt budget;
- `PRESENCE_INTENT_EXPIRED` when the captured intent expires;
- `PRESENCE_ABORTED` when the caller cancels;
- `PRESENCE_CLOCK_INVALID` or `PRESENCE_POLLING_RANDOM_INVALID` for invalid injected scheduling
  controls;
- `PRESENCE_RESPONSE_INVALID` for an unknown verdict or changed request binding;
- `PRESENCE_PROOF_MISSING` for incomplete terminal approval evidence; or
- `PRESENCE_UNAVAILABLE` for an outcome lookup or backoff failure.

Presence `DENIED` and `ESCALATED` outcomes also remain non-authorizing. After valid approval,
Decionis still makes a fresh decision against the original captured intent and verified receipt. If
the caller cancels or the intent expires while reauthorization is in flight, the authority response
is discarded and execution remains blocked.

## Bounded managed polling

`DecionisGate.waitForAuthorization` polls only
`GET /v1/authority/escalations/{escalation_id}`. Its capped exponential schedule starts at 500 ms,
then 1 s, 2 s, 4 s, and 5 s thereafter, with bounded jitter. It supports `AbortSignal`, bounds each
response and request timeout, and stops at the earlier of the escalation or captured-intent expiry.
Concurrent default waits for the same exact intent and escalation share one polling loop.

Pending states return `ESCALATE_PENDING` and never contain a grant. `GRANT_READY` returns the normal
ALLOW decision. `REJECTED`, `BLOCKED`, `EXPIRED`, `CANCELLED`, and `FAILED` are typed terminal states
with stable reason codes; malformed responses, state regression, changed intent IDs or hashes, and
changed expiry fail closed. `INTENT_EXPIRED` is accompanied by `RECAPTURE_REQUIRED`.
