# Human approval

Presence receives an immutable presentation of action, target, and intent hash. The reference coordinator accepts only a terminal receipt dossier with a request ID. Decionis independently fetches and verifies that receipt, including signature/chain status and the exact displayed intent binding.

Presence is an evidence provider, not the execution authority. Client-side booleans, screenshots, copied proof strings, or model claims such as “the user approved” are never sufficient.

Transport failures, unknown verdicts, malformed or unbounded receipt identifiers, and independent
reauthorization failures produce stable fail-closed outcomes. Raw Presence or authority errors are
not returned through the coordinator.

If the intent changes or expires during approval, capture a new intent and start again.

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
