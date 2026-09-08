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
