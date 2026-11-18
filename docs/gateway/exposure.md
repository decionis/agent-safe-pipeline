# Cumulative limits

A Decionis policy can cap how much money leaves per vendor, per agent or per organisation over a
rolling window: `Vendor payment | per vendor | 1 day | USD 100,000`. A single decision cannot
enforce that, because each payment is within its own limit; only something on the execution path,
which sees every payment before it is sent, can refuse the one that would cross the total. The
gateway does it for a route that says it releases money: after the authority's `ALLOW`, and before
the payment is sent, it reserves the amount against the Decionis exposure ledger.

A route that declares nothing is governed exactly as before, and a gateway with no such route
never calls the ledger.

## Declaring a route that releases money

```yaml
interception:
  routes:
    - path: /vendors/:vendor/payments
      action: payment.release
      methods: [POST]
      exposure:
        actionType: PAYMENT_RELEASE # the default
        amount: /body/amount_minor
        amountUnit: minor # or major: a decimal in the currency's major unit
        currency: /body/currency # or a fixed code: USD
        subjects:
          vendor: /path/vendor # or /body/payee_id
          agent: /headers/x-agent-id # optional; the gateway's actor.id when absent
        settledAmount: /body/captured_minor # optional: what a 2xx answer says moved
        failurePolicy: failClosed # the default
```

Each value is an RFC 6901 pointer into the request as the gateway reads it: `/path/<name>` for a
route's `:name` segment, `/query/<name>`, `/headers/<lower-case name>`, and `/body/...` into a JSON
body. They read the request the authority evaluated and the gateway forwards, byte for byte.

| Setting         | Meaning                                                                                                                                                                                    |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `actionType`    | The ledger's action type: `PAYMENT_RELEASE` by default, or another of `CommerceExposure`'s (`VENDOR_BANK_CHANGE`, `REFUND_REQUEST`, ...). A limit covers the route when it names this type |
| `amount`        | Where the amount is. `minor` (the default) is an integer of minor units; `major` is a decimal with no more fractional digits than the currency has (two for USD, none for JPY)             |
| `currency`      | Where the ISO 4217 code is, or the code itself. No limit is converted between currencies                                                                                                   |
| `subjects`      | Where the `vendor`, `customer`, `sku` or `agent` identifier is. The organisation is always the gateway's tenant                                                                            |
| `settledAmount` | Where a `2xx` answer states the amount that actually moved. Without it, or when it is unreadable or more than reserved, the reserved amount is settled                                     |
| `failurePolicy` | `failClosed` refuses a payment the ledger could not be asked about; `failOpen` forwards it, ungoverned, and says so                                                                        |

An amount, currency or declared subject the request does not state is refused before the authority
is asked, with `400` and `EXPOSURE_AMOUNT_UNREADABLE`, `EXPOSURE_CURRENCY_UNREADABLE` or
`EXPOSURE_SUBJECT_UNREADABLE`: a payment that cannot be counted is never counted on a guess.
Nothing is rounded: `12.345` USD is unreadable, not `1235`.

The agent, when the route names no pointer for it, is the gateway's own `actor.id`, which the
caller cannot choose. A pointer into a header the agent sets is the agent's own statement of who
it is; name one only where the header is set by something the agent does not control.

A direct `Gateway.govern()` caller that changes a money route's action is refused with
`400 ROUTE_ACTION_MISMATCH`, as for a route that pins a policy.

## What happens to a payment

The authority decides first. A `BLOCK` or an `ESCALATE` is answered as always, and the ledger is
not asked.

On `ALLOW`, the executor claims the grant and checks the bytes. Immediately before sending, the
gateway reads the organisation's limits and reserves the amount against every limit that covers
the route: its action types include the route's, its `actor_types` (when it has any) include the
gateway's `actor.type`, and the route states its subject. The reservations are made in limit key
order.

Within every limit, the payment is sent once. Otherwise nothing is sent, the reservations already
made are released, and the caller is answered:

| State                  | Status | Execution       | `reason_codes`                                                                                |
| ---------------------- | ------ | --------------- | --------------------------------------------------------------------------------------------- |
| `EXPOSURE_EXCEEDED`    | 409    | `NOT_FORWARDED` | the ledger's code, then `EXPOSURE_ON_EXCEED_HOLD` or `EXPOSURE_ON_EXCEED_ESCALATE`            |
| `EXPOSURE_UNAVAILABLE` | 503    | `NOT_FORWARDED` | `EXPOSURE_UNAVAILABLE` and why (`EXPOSURE_UNREACHABLE`, `EXPOSURE_POLICY_INVALID`, and so on) |

The ledger's codes are `EXPOSURE_LIMIT_EXCEEDED`, `EXPOSURE_CURRENCY_NOT_CAPPED` (no FX: a currency
the limit does not cap is refused) and `SOD_SEQUENCE_CONFLICT`. `EXPOSURE_UNAVAILABLE` sets
`Retry-After: 5`. Both answers carry `verdict: ALLOW`, the intent, decision and dossier, and the
attempt's finalization: the authority allowed the payment, its grant was claimed, and the attempt
is finalized with Decionis as not executed, with the code. An exceeded answer names the limit
(`exposure: { limit_key, on_exceed }`), never an amount or how much remains. Neither is a `BLOCK`,
and nothing presents it as one.

Once the upstream has answered, the reservations end with the payment:

| The payment                                                         | Its reservations                      |
| ------------------------------------------------------------------- | ------------------------------------- |
| committed (`2xx`, `3xx`)                                            | settled, for `settledAmount` if given |
| refused by the upstream (`4xx`), or never sent                      | released                              |
| unknown (`5xx`, `408`, a timeout, a connection lost after the send) | kept, and recorded `EXPOSURE_KEPT`    |

A payment whose outcome is unknown may have moved money, so its reservation keeps counting until
the window passes it, as an unsettled reservation does in the ledger: the ledger errs toward the
cap, and the evidence names the reservation so it can be settled or released by hand once the
outcome is known.

### A retry of an unknown payment

A retry with the same `Idempotency-Key` and the same request is the same payment, so it is counted
once. The gateway remembers the reservation key of the unknown attempt with the attempt itself, and
the retry reserves under that key. The ledger answers with the reservations the first attempt kept
(`replayed`), never a second draw, and the retry's own outcome ends them:

| The retry               | What the first attempt kept                  |
| ----------------------- | -------------------------------------------- |
| committed               | settled                                      |
| refused by the upstream | released                                     |
| unknown again           | kept, under the same key, for the next retry |

Its `EXPOSURE_RESERVED` line carries `retry_of: true` and the limits whose reservation was
`replayed`. Two cases still draw afresh, under the retry's own key:

- **Released by hand.** The kept reservation was released because someone found the payment did
  not happen.
- **Older than a day.** The attempt is remembered for a day (`ATTEMPT_TTL_MS`); after that, a retry
  is not linked to it.

A reservation settled by hand stays settled. A retry the upstream then refuses records
`EXPOSURE_RELEASE_FAILED` for it, so the contradiction is in the evidence.

A settle or release that fails is retried, up to three attempts with a short backoff, and a failure
that remains is a chained `EXPOSURE_SETTLE_FAILED` or `EXPOSURE_RELEASE_FAILED` line naming the
limit and the reservation, and `agentsafe_exposure_total{outcome="SETTLE_FAILED"}`. It never
changes the answer: the payment already happened, or already did not.

### An `ESCALATE` limit

A limit's `on_exceed` is `HOLD` or `ESCALATE`. The gateway's [holds](./http-interception.md#holds-and-resume)
wait for the authority to mint a grant after a person approves; a limit is reached after the grant
was claimed, so there is nothing for an approval to release. Both are therefore refused, and the
answer says which the policy asked for. The person's path is the policy's: raise the limit, or
approve the payment where the policy routes it, and the agent sends a new request, which is decided
afresh.

### Idempotency

Every reservation for one intent carries the same `reservation_key`, `agentsafe:` and the intent
hash's hex digest, and a `request_digest` over what it reserves. A reservation whose answer was
lost is asked again under the same key, and the ledger answers with the reservation it already
holds rather than drawing twice. A resumed hold is the same intent, so it reserves under the same
key.

### Limits the route cannot state

A limit that covers the route's action type but whose subject the route does not name (a
per-customer cap on a route that names only a vendor) is not counted against. The payment goes on,
and the report and the `EXPOSURE_RESERVED` line name it under `unstated`, with
`EXPOSURE_SUBJECT_UNSTATED`. A sequence limit (segregation of duties) is reserved as a step
(`payment_release`, `vendor_bank_change`) with the agent as its actor.

## What the ledger receives

Subject identifiers never leave the gateway. Each is sent as `id_digest`, the SHA-256 of
`decionis-exposure-v1`, the organisation id, the subject kind and the identifier trimmed and
lower-cased, one per line: the same digest Decionis Commerce sends for the same vendor, so one
vendor is one subject whichever channel paid it. A sequence limit's actor is digested the same way
under the kind `actor`. The amount and currency are sent as the ledger needs them; neither is
written to the gateway's output or evidence, which carry limit keys, reservation ids and codes
only.

The source of each reservation is `{ platform: "agentsafe", channel: "gateway", record_id: <intent
id> }`, and `occurred_at` is when the intent was captured.

## The Decionis endpoints

The gateway calls them through the authority's guarded egress, with the authority's key
(`DECIONIS_API_KEY`); the organisation is the key's.

| Operation                                                                    | When                                       |
| ---------------------------------------------------------------------------- | ------------------------------------------ |
| `GET /v1/commerce/exposure`                                                  | each money release: the active limits      |
| `POST /v1/commerce/exposure/{limitKey}/reservations`                         | each covering limit, before the send       |
| `POST /v1/commerce/exposure/{limitKey}/reservations/{reservationId}/settle`  | after a committed payment                  |
| `POST /v1/commerce/exposure/{limitKey}/reservations/{reservationId}/release` | after a payment not executed, or a refusal |

Reading limits accepts `policy:read`, `policy:write`, `decision:read`, `decision:write` or `org:*`;
reserving, settling and releasing need `decision:write`, `decision:*` or `org:*`. A hosted
gateway's confined key (`decision:shadow`, `decision:enforce`) reaches none of these routes, so a
money route behind one fails closed with `EXPOSURE_UNAVAILABLE` until its key holds a draw scope.
An organisation without an active policy has no limits, and every payment is `NOT_APPLICABLE`. A
policy whose limits cannot be read (`EXPOSURE_POLICY_INVALID`) is never read as "no limits".

The demo authority serves no ledger: a money route in front of it fails closed, or forwards
ungoverned under `failOpen`. A deployment that keeps its own ledger passes an `ExposureLedger` as
`GatewayDependencies.exposureLedger`.

## Shadow

In shadow every payment is forwarded unchanged, as everything is. After the authority's would-be
`ALLOW` settles, the gateway asks the ledger what it would have said, without counting the payment.

- **Read-only, against Decionis.** It reads each covering subject's usage
  (`GET /v1/commerce/exposure?subject_kind=…&subject_digest=…`, `subject_usage`) and compares
  usage plus this amount with each limit's cap, as the ledger does: over the cap when the total
  exceeds it, and a currency without a cap is not limited. Nothing is reserved. This is the only
  ledger call a hosted gateway's `decision:shadow` key may make.
- **A sequence limit** counts steps, not amounts, so it cannot be previewed. The observation names
  it in `unpreviewed`.
- **A ledger without that read** (`ExposureLedger.subjectUsage` absent) is asked by reserving
  under a key of its own (`agentsafe-shadow:` and the intent hash) and releasing at once. For the
  length of two ledger calls, that reservation counts toward its limit for every other channel.

The observation's report line carries `exposure` (`WITHIN_LIMIT`, `NOT_APPLICABLE`, `EXCEEDED`,
`UNAVAILABLE`, or `UNREADABLE` when the request did not state its facts). The gateway's stream gets
an `EXPOSURE_OBSERVED` line (with `read_only: true` when previewed). The shadow report and
`/_agentsafe/status` count by status under `exposure`.

## Evidence

Each step is a line on the gateway's own stream (`agent-safe.gateway-events/1`), chained like every
other: `EXPOSURE_RESERVED` (the limits reserved against, and any `unstated`), `EXPOSURE_EXCEEDED`,
`EXPOSURE_UNAVAILABLE` or `EXPOSURE_UNGOVERNED`, then `EXPOSURE_SETTLED`, `EXPOSURE_RELEASED` or
`EXPOSURE_KEPT`, and `EXPOSURE_SETTLE_FAILED` or `EXPOSURE_RELEASE_FAILED` where one did not take.
The interception report carries `exposure: { status, reason_codes, limits, unstated, settlement }`,
a forwarded answer `agentsafe-exposure: WITHIN_LIMIT | NOT_APPLICABLE | UNGOVERNED`, and
`agentsafe_exposure_total{outcome}` counts each.

## Not yet

- Payments that bypass the gateway are not recorded; a payment source that reconciles them into the
  ledger is a separate integration.
- A reservation kept for an unknown outcome that is never retried is not settled or released
  until someone does so by hand, or the window passes it.
- Facts-only privacy governs by API profiles alone, and a profile operation cannot declare
  `exposure` yet.
