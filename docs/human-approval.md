# Human approval

Presence receives an immutable presentation of action, target, and intent hash. The reference coordinator accepts only a terminal receipt dossier with a request ID. Decionis independently fetches and verifies that receipt, including signature/chain status and the exact displayed intent binding.

Presence is an evidence provider, not the execution authority. Client-side booleans, screenshots, copied proof strings, or model claims such as “the user approved” are never sufficient.

Transport failures, unknown verdicts, malformed or unbounded receipt identifiers, and independent
reauthorization failures produce stable fail-closed outcomes. Raw Presence or authority errors are
not returned through the coordinator.

The re-evaluated decision carries the evidence it was made with, and `DecionisGrantVerifier` presents
the same evidence when it claims the grant, because Decionis re-verifies a Presence-bound decision at
claim time and rejects a claim that arrives without it.

If the intent changes or expires during approval, capture a new intent and start again.

## Ceremony requirements and delivery

`PresenceApprovalCoordinator` accepts `requirements`, the docs/22 verification requirements Presence
enforces before it seals a receipt, and `ttlSeconds`, the approval-request lifetime (30 to 600
seconds). A FIDO2 approval is `{ level: "STANDARD", methods: ["WEBAUTHN"] }`; adding active liveness
is `{ level: "HIGH_CONFIDENCE", methods: ["WEBAUTHN", "ACTIVE_LIVENESS"] }`. Omitted, Presence applies
its default standard-confidence device proof.

The approver identity passed to the coordinator is the subject Presence routes the request to.
Presence pushes to enrolled mobile devices bound to that identity; it does not send email, and
neither does the Decionis execution-authority path. When no enrolled device exists, deliver the
`approval_url` from the `HUMAN_REQUIRED` result to the person over your own channel. Putting the
approver's email in the trusted intent context, for example under `approver_email`, keeps the
routing identity hash-bound and recorded in the Decision Dossier. The
[live approval example](../examples/presence-live-approval) runs both ceremonies against the real
services.

## Bounded polling

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
