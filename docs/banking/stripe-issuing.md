# Stripe Issuing: real-time card authorization by policy

A company that issues cards on Stripe Issuing can have its own spending policy decide each card
authorization: routine purchases clear, exceptions go to an approver, and every decision leaves a
Decision Dossier. The bridge described here connects Stripe to the executor's issuer hook, which
[card-authorization.md](./card-authorization.md) describes in full. This page only adds what is
specific to Stripe.

This covers cards **you issue on Stripe Issuing**. It does not reach cards on other programs: a
card platform that exposes no real-time authorization hook to its customers cannot be gated
this way.

## What runs where

```text
Stripe ──issuing_authorization.request──▶ bridge ──POST /v1/card-authorizations──▶ executor ──▶ Decionis
       ◀──────── { approved } ───────────        ◀──── APPROVE | PENDING | NO_MATCH ──
Stripe ──issuing_authorization.created──▶ bridge ──POST …/{id}/result──────────────▶ executor
```

- **`agentsafe cards stripe-bridge`** is a small listener. It verifies Stripe's signature, keeps
  only what the hook needs, asks the executor's hook and answers in Stripe's shape. It decides
  nothing.
- **The executor** runs with `EXECUTOR_CARD_NO_GRANT=evaluate`, so an authorization with no
  pre-approved hold becomes a `card.purchase` intent decided at commit (the fraud-queue
  contract). The verdict, the single-use grant and the evidence are the executor's and the
  authority's, as for any issuer.
- The bridge calls the executor as an `OPERATOR` holding only `cards.authorize`. It cannot propose
  a purchase or resume an escalation.

## What leaves Stripe's event

The bridge reads these fields and nothing else:

| Hook field         | From the Stripe authorization                                                                      |
| ------------------ | -------------------------------------------------------------------------------------------------- |
| `authorization_id` | `id` (`iauth_…`)                                                                                   |
| `card_token_ref`   | `card.id` (`ic_…`). It is an opaque reference; a value shaped like a card number is refused.       |
| `amount_minor`     | `pending_request.amount` while Stripe waits; the last `request_history` amount once Stripe decided |
| `currency`         | the same entry's currency, upper-cased                                                             |
| `merchant_id`      | `merchant_data.network_id`                                                                         |
| `mcc`              | `merchant_data.category_code`, when it is four digits                                              |

The cardholder's name, email, phone and address, the card's last four digits, verification data
and the rest of the payload are never copied out of the parse. No log line carries them.

## Answers

| The executor's hook says | Stripe is answered                                                                                  |
| ------------------------ | --------------------------------------------------------------------------------------------------- |
| `APPROVE`                | `{"approved": true}`, with `decionis_intent_id` and `decionis_decision_id` in `metadata`            |
| `NO_MATCH` (a BLOCK)     | `{"approved": false}`, with the hook's code in `metadata.decionis_code`                             |
| `PENDING` (an ESCALATE)  | `{"approved": false}`, with `decionis_code: ESCALATION_PENDING` and the intent the approver answers |

Every answer carries the `Stripe-Version` you configure, because Stripe requires it.

**Escalation.** Stripe cannot hold an authorization open while a person answers, so an escalated
purchase is declined at once and Decionis routes the approval (Presence, or the cardholder's tap).
Once the approver answers, the hold their answer leaves is keyed by card and merchant. The
cardholder's retry is a new Stripe authorization for the same card at the same merchant, and it
matches that hold and is approved. Tell cardholders to retry after approval.

**Zero-amount authorizations** (account verifications) move no money and are not a purchase the
hook can decide. The undecided rule below answers them.

## The deadline and when nothing is decided

Stripe waits 2 seconds, then applies the account's timeout setting or Autopilot. The bridge keeps
its own budget inside that, `STRIPE_BRIDGE_DEADLINE_MS` (1,500 ms by default, at most 1,800).
Its answer is undecided when the budget runs out, the executor cannot be reached, the executor
refuses, or the event cannot be turned into a question. `STRIPE_BRIDGE_ON_UNDECIDED` then says
what to do:

- `stand_in` (the default): answer with an error, so Stripe applies the account's own timeout
  setting or Autopilot. This is the issuer's stand-in decision, which the finance plan makes the
  default failure mode for card authorization.
- `decline`: answer `{"approved": false}` with `decionis_decision: UNDECIDED` and the code.

**Verify in test mode before enforcing:** confirm which of the account's timeout setting or
Autopilot Stripe applies to an error answer, as against a timeout. Stripe's documentation records
an invalid answer as `webhook_error` and a missing one as `webhook_timeout`.

A request with a missing, forged or stale signature, a live event at a test-mode bridge, or
another event type is refused before the executor is asked. The undecided rule does not apply to
these, since nothing about them can be trusted.

**Latency.** No end-to-end latency figure is stated here. What the executor adds in process is
measured in its own suite. The executor's call to the authority is a network round trip, budgeted
per placement in [card-authorization.md](./card-authorization.md#latency). The bridge logs
`elapsed_ms` on every answer. Read the bridge's answer times in shadow on your own link before
enforcing. If they do not fit, use the edge evaluator's local claim.

## Shadow first

`STRIPE_BRIDGE_MODE` is `shadow` unless you set `enforce`.

- **In shadow the real-time route is not served**, so shadow never sits in a card's path. Do not
  configure the real-time endpoint in Stripe yet. Point only an ordinary webhook endpoint at the
  bridge, subscribed to `issuing_authorization.created`.
- On each `created` event the bridge has the executor evaluate what Stripe already decided. Run the
  executor in `SHADOW` too. The bridge logs `STRIPE_SHADOW_OBSERVED` with Stripe's decision beside
  the policy's, and the executor records the evaluation.
- If the executor enforces while the bridge shadows, the claim is settled with what Stripe did and
  `STRIPE_SHADOW_EXECUTOR_ENFORCING` is logged. Fix the executor's mode.

To enforce, set the executor to `ENFORCEMENT`, set `STRIPE_BRIDGE_MODE=enforce` and configure the
real-time endpoint in Stripe's Issuing settings. Keep the `created` subscription: it settles each
claim with what Stripe actually did, including a decision Stripe made itself on a timeout
(`STRIPE_STAND_IN_DECIDED`), so the Dossier says what happened, not what was asked.

## Running it

| Variable                                   | Meaning                                                                                                                       |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| `STRIPE_BRIDGE_MODE`                       | `shadow` (default) or `enforce`                                                                                               |
| `STRIPE_BRIDGE_LIVEMODE`                   | `true` or `false`, required. The other mode's events are refused.                                                             |
| `STRIPE_BRIDGE_STRIPE_VERSION`             | required, for example `2025-03-31.basil`                                                                                      |
| `STRIPE_BRIDGE_WEBHOOK_SECRETS_FILE`       | required. One `whsec_…` per line: the real-time endpoint's, the events endpoint's, and a rolled one while it changes.         |
| `STRIPE_BRIDGE_EXECUTOR_URL`               | required. HTTPS, or HTTP on loopback only.                                                                                    |
| `STRIPE_BRIDGE_EXECUTOR_TOKEN_FILE`        | required. The operator principal's bearer token (scope `cards.authorize`), read on every call so a rotation needs no restart. |
| `STRIPE_BRIDGE_DEADLINE_MS`                | 100–1,800, default 1,500                                                                                                      |
| `STRIPE_BRIDGE_ON_UNDECIDED`               | `stand_in` (default) or `decline`                                                                                             |
| `STRIPE_BRIDGE_HOST`, `STRIPE_BRIDGE_PORT` | default `127.0.0.1:8790`                                                                                                      |

Stripe only posts to HTTPS, so TLS ends at your ingress in front of the bridge. Point the
real-time endpoint at `POST /v1/stripe/issuing/authorization-requests` and the ordinary webhook at
`POST /v1/stripe/issuing/events`. `GET /health` answers `ok`. The bridge writes one JSON line per
event on stderr and stops on `SIGTERM`.

Try it without Stripe's dashboard: `stripe listen --forward-to localhost:8790/v1/stripe/issuing/events`,
then `stripe trigger issuing_authorization.request`.

## Not yet

- **Who the card belongs to.** Every authorization is decided as the executor's configured commit
  actor (`EXECUTOR_CARD_COMMIT_*`). Naming the employee or agent per card (for example from the
  card's metadata), so per-person limits and segregation of duties apply, is the next slice.
- **Partial approval.** `pending_request.is_amount_controllable` and the `amount` answer field are
  not used.
- **Incremental authorizations and reversals.** These come through `issuing_authorization.updated`,
  which is acknowledged and ignored for now.
- **Stripe Connect.** A platform deciding for its connected accounts' cards is not covered.
