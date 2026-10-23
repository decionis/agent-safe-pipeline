# Card authorization: the issuer's hook and the cardholder's tap

How a bank puts AgentSafe between an agent's card purchase and the issuer's authorization, and how
the cardholder's tap through a presence provider such as Koard resumes a held purchase. The
executor's own reference is the [package README](../../packages/agentsafe/README.md); this page
walks the flow in the order the parties meet it and names what each one owns.

## The split

| Party     | Owns                                                                                     |
| --------- | ---------------------------------------------------------------------------------------- |
| The agent | Proposes `card.purchase` to the bank's AgentSafe. It never proves its own approval.      |
| Decionis  | Evaluates the bank's policy, verifies admitted proof, issues one bound grant per intent. |
| AgentSafe | Holds the grant inside the bank, matches and claims it once, records the effect.         |
| Koard     | Proves the cardholder tapped their own card, and signs that over the intent.             |
| Issuer    | Takes the final card decision, enforces card controls, reports the result.               |

The decision is taken before the card is submitted, because an authorization has seconds and a
person has minutes. The authorization itself is matched to the grant in milliseconds.

## 1. The purchase is proposed

A `PROPOSER` posts to `POST /v1/actions`:

```json
{
  "proposal": {
    "action": "card.purchase",
    "target": "card:tok_7f3a",
    "parameters": {
      "cardTokenRef": "tok_7f3a",
      "amountMinor": 4250,
      "currency": "EUR",
      "merchantId": "M-17"
    }
  },
  "idempotency_key": "purchase-2026-10-12-0001"
}
```

The card is named by the issuer's token reference, never by its number: a value shaped like a card
number is refused as `422 CARD_PAN_REFUSED` before anything is asked or recorded. The intent the
authority evaluates carries `context.card_velocity`, how many purchases this process held for the
same card and how many authorizations claimed one in the last ten minutes, so a policy rule can
hold a burst for the cardholder without the policy language counting anything over time.

Three answers come back from the enforced evaluation:

| Verdict    | What AgentSafe does                                                                                  |
| ---------- | ---------------------------------------------------------------------------------------------------- |
| `ALLOW`    | Holds the grant for the issuer's hook: `outcome: "HELD_FOR_AUTHORIZATION"`, with the grant's expiry. |
| `ESCALATE` | Hands back the intent and where the hold goes: `outcome: "ESCALATE_PENDING"`, `escalation` as below. |
| `BLOCK`    | Nothing is held; the agent never submits the card.                                                   |

## 2. The hold goes to the cardholder

When the bank's policy names the cardholder, through a presence provider, the rule's
`verification_requirements` say so:

```json
{
  "level": "STANDARD",
  "methods": ["CARD_TAP"],
  "hardware_pki_required": false,
  "disallow_virtual_cameras": false,
  "provider": "koard"
}
```

Decionis puts the routing on the decision, and AgentSafe hands it to the caller:

```json
{
  "verdict": "ESCALATE",
  "outcome": "ESCALATE_PENDING",
  "escalation": {
    "mode": "ATTESTATION",
    "intent": { "...": "the exact intent, to present back" },
    "requirement": {
      "requirement_id": null,
      "expires_at": "2026-10-12T12:05:00.000Z",
      "selector": { "kind": "ROLE", "role_id": "CARDHOLDER" },
      "verification": { "provider": "koard", "methods": ["CARD_TAP"], "level": "STANDARD" }
    }
  }
}
```

A `verification.provider` other than `decionis` means no Presence ceremony is asked for, whatever
`EXECUTOR_ESCALATION` says: only that provider's attestation resumes the hold. When policy names a
bank role instead (the fraud desk, the head of cards), `provider` is `decionis` or absent, and the
escalation runs through Decionis Presence as [human approval](../human-approval.md) describes.

At the same moment Decionis tells the bank's webhook subscriber. `authority.escalation_required`
carries the intent's id, hash and expiry, the action and its parameters, and the same `selector`
and `verification`, so the subscriber (the bank, or Koard as the bank's delegate) can prompt the
right cardholder in the issuer's app.

## 3. The tap resumes the hold

Koard signs a presence attestation: a compact Ed25519 JWS, `typ`
`decionis-presence-attestation+jwt`, bound to the intent's id and hash, `aud` the bank's
organisation, `presence.method` `card_tap`, `presence.result` `VERIFIED`, at most 300 seconds old.
Decionis verifies it under a key it finds in two places: a key the bank registered itself at
`POST /v1/execution/provider-keys` (purpose `presence_attestation`), or the JWKS of a provider the
bank admitted from the Decionis directory (`PUT /v1/execution/presence-providers/koard/admission`).

Whoever holds the tap presents it to `POST /v1/escalations`:

```json
{
  "mode": "ATTESTATION",
  "intent": { "...": "the intent from the handoff" },
  "attestation": "<compact JWS>"
}
```

The agent that proposed may present it. So may the issuer app's backend, where the tap actually
lands: an `OPERATOR` principal holding the scope `escalations.resume`, which opens this one route
and nothing else, and only for an attestation. The operator adds no authority: the intent is
re-hashed on the way in, the authority binds the attestation to that hash and evaluates the policy
again, and only a rule such as "approval by `koard`, method `card_tap`" turns the second evaluation
into an `ALLOW` with a grant. AgentSafe keeps nothing of the token. The answer is the same shape as
a first proposal: `ALLOW` becomes `HELD_FOR_AUTHORIZATION`, a refused attestation is a fail-closed
`BLOCK`.

Decionis then tells the subscriber what became of the hold: `authority.escalation_resolved` carries
the fresh decision's outcome, or `REFUSED` with the refusal code, with the proof's facts (provider,
method, approver role, attestation id, key id) and never the proof.

## 4. The authorization is matched

The issuer's real-time hook, an `OPERATOR` holding `cards.authorize`, posts the authorization:

```json
{
  "authorization_id": "auth_01J...",
  "card_token_ref": "tok_7f3a",
  "amount_minor": 4000,
  "currency": "EUR",
  "merchant_id": "M-17",
  "mcc": "5812"
}
```

The hold is found by the card and the merchant the authorization names, and the match is pure and
local: same currency, same category when the purchase named one, an amount at or below the grant,
a grant unexpired and unspent. A match claims the grant through the authority exactly once and
answers `{ "decision": "APPROVE", ... }`; anything else answers `{ "decision": "NO_MATCH", "code":
... }`, and what that means for the authorization is the issuer's own policy. The codes, the retry
semantics and the bounds are in the README's card section.

## 5. The result becomes the effect

The hook posts what it did to `POST /v1/card-authorizations/{authorization_id}/result`. An
approval finalizes the grant as `COMMITTED` with the effect compared against the grant; an amount
above the ceiling is `EFFECT_MISMATCH`, which halts the executor by default. A decline finalizes
`FAILED`; a result after the claim's lease finalizes `INDETERMINATE`. The dossier then carries the
intent, the policy version, the approval facts and what the issuer actually approved.

## 6. Replicas and restarts

Holds are keyed by the card and the merchant, so an agent's burst across merchants holds in
parallel and one card has at most one pending purchase per merchant. By default they live in the
process, which is right for exactly one replica: a restart loses only grants nobody claimed, and
they expire with no effect.

A bank that runs several replicas behind its hook, or that must keep holds across a restart, gives
the executor a shared store:

| Variable                                    | What it is                                                                   |
| ------------------------------------------- | ---------------------------------------------------------------------------- |
| `EXECUTOR_CARD_HOLDS_STORE=postgres`        | holds, claims and the per-card activity become rows every replica shares     |
| `EXECUTOR_CARD_HOLDS_NAMESPACE`             | whose rows these are; two deployments on one database never see each other's |
| `EXECUTOR_CARD_HOLDS_DATABASE_URL`, `_FILE` | the connection string, a secret like any other                               |
| `EXECUTOR_CARD_HOLDS_KEY`, `_FILE`          | 32 bytes, hex or base64: what a row keeps of a grant is sealed under it      |
| `EXECUTOR_CARD_HOLDS_TABLE`                 | the tables' prefix, `agentsafe_card` by default                              |

`agentsafe cards holds-schema` prints the DDL; the operator creates the three tables once, before
the first replica starts, and the executor's database role needs `SELECT`, `INSERT`, `UPDATE` and
`DELETE` on them and nothing else. The executor probes the tables at start and refuses to start
when it cannot reach them, since no authorization could then match.

The race rule is the same as in memory, decided by the database in one statement instead of by one
process's memory: a hold takes its key when the row is absent, spent or expired, and an
authorization spends the row that is still unspent and unexpired, so of two replicas racing for the
same hold one claims. A hold another replica made is admitted on first use through the executor's
own checks, exactly as the replica that made it admitted it, and recorded as adopted. A claim
another replica made is settled with the claim material that replica sealed into the row, so the
hook and its result may reach any replica, in any order, and a replica started after the claim
finalizes it with the authority. The rows outside the seal are references, times and flags; the
grant's token and the claim's tokens are never in the database in clear, and a sealed value moved
to another row does not open. The hold key is read from the secret store when a row is sealed; it
is the deployment's, not Decionis's, and where it lives per hosting tier is the deployment guide's
subject.

### Card limits and the hosted allowance

Decionis is adding allowances it holds itself (`/v1/authority/allowances`). Each one is a named
counter for the organisation that the approving rule draws on (`then.allowance`). The draw is
reserved with the grant, converted at the claim, kept by a commit and released by a decline, and
every replica and every executor shares it. A draw that does not fit is refused as `BLOCK`
`ALLOWANCE_EXHAUSTED` before any grant exists. A card's spending or velocity limit could later move
onto one, so that `context.card_velocity` would no longer be one process's count of the last ten
minutes.

Nothing moves in this release, for two reasons:

- A hold does something an allowance does not: it matches an authorization to the grant that
  admitted it, by card and merchant.
- The rule fixes an allowance's key, so a limit per card would need a key derived from the card,
  which `then.allowance` does not offer yet.

`HardLimits` stays the host's backstop either way.

## Latency

What this process adds to the hook is measured in the package's `test/performance` suite on every
verification, and is far inside any authorization's budget. The suite asserts a budget wide
enough to hold on a loaded runner and under the mutation gate's instrumentation; a quiet machine
measures an order of magnitude below it:

| Step, in process                                                | 99th percentile, measured | Asserted budget |
| --------------------------------------------------------------- | ------------------------- | --------------- |
| match an authorization to a held grant                          | under 50 microseconds     | 1 millisecond   |
| find, open and spend a hold in the in-memory store, 10,000 held | under 1 millisecond       | 5 milliseconds  |

The rest of the hook's time is the claim: one HTTPS round trip from the executor to the authority
(`POST /v1/execution/claim-token`), and, with the shared store, one or two round trips to the
bank's database. Those are the network's figures, measured in a deployment rather than here; the
`@decionis/iso8583` simulator reports them per authorization on a given link. The figure Decionis
stands behind for the hook is therefore stated as a budget per placement, and confirmed on the
bank's own link before enforcement:

| Placement of the claim                                            | Hook answer, 99th percentile |
| ----------------------------------------------------------------- | ---------------------------- |
| hosted authority in the same cloud region as the executor         | 150 ms                       |
| hosted authority in another region                                | 300 ms                       |
| local claim at the edge (below), hosted authority told afterwards | 10 ms                        |

A hook whose processor budget is tighter than its placement allows uses the local claim.

## A local claim with the edge evaluator

Where the budget demands it, the claim stays in the bank. With
`EXECUTOR_DECISION_AUTHORITY=edge` ([the edge evaluator](../edge-evaluator.md)) the purchase is
decided locally by the signed policy bundle and the `ALLOW` becomes a local authorization; the
hold keeps it, the issuer's authorization claims it in the process through the local verifier, and
single use is held in the replay store every replica shares. The whole path, decision to
finalization, makes no network call: the decision and its finalization are recorded in the
executor's evidence chain (`EDGE_DECISION`, `EDGE_EXECUTION_FINALIZED`) under the bundle's id and
key, and the hosted authority learns of them afterwards through the signed usage reports.

What that is as evidence: a local claim is single-use by the shared replay store, bound to the
intent's hash by the bundle's own evaluation digest, and signed into the evidence chain; it is not
a hosted Decision Dossier for the claim, and a cardholder's tap is never evaluated locally, since
an `ESCALATE` always goes to the hosted authority. It is acceptable evidence on the card path when
three things hold: the replay store is the shared Postgres one, the evidence chain is
retained and signed, and the bundle and usage-report keys live in the bank's key vault, one per
tenant. With the shared hold store, a hold claimed locally on one replica is settled on another,
which records the finalization in its own chain.

## Incremental and split authorizations

An issuer may be asked for the same authorization twice, for more. `EXECUTOR_CARD_AUTHORIZATIONS`
says what the hook does with it, per deployment:

- `single` (the default): one authorization spends the hold, and the same authorization id
  re-presented for a different amount is `NO_MATCH` with `AUTHORIZATION_ID_REUSED`.
- `incremental`: the same authorization id re-presented for a higher amount, within the grant's
  ceiling and before its result is recorded, is answered from the same claim, with no second claim
  (`CARD_AUTHORIZATION_INCREMENTED` in the security stream); the result then records the final
  amount against the ceiling. Less than before, more than the ceiling, another merchant, or a
  re-presentation after the result are refused as a reuse.

Split authorizations, several authorization ids against one purchase, are not offered: a grant is
claimed and finalized once, so a second capture against it would have no finalization of its own
and the dossier would not say what happened to it. An issuer that splits lets the first capture
settle the grant and treats the rest as `NO_MATCH`, or the agent proposes one purchase per capture.

## The three places a tap can wait

An authorization lives on a clock measured in seconds, so where a held item waits while a person
answers is a design decision per bank. Koard's paper names three places and three taps; this is
what each is on AgentSafe.

| Where the item waits                       | Koard's name                                   | What AgentSafe does                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------------------ | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Before the authorization exists            | **Tap to Verify**, for a held purchase         | Sections 1 to 5 above: the agent proposes, policy holds the grant or asks for the cardholder, the tap resumes the hold, the authorization matches it in milliseconds. The cleanest path, and the one built first.                                                                                                                                                                                                                                                                         |
| In the bank's fraud queue                  | **Tap to Verify**, for a flagged authorization | `EXECUTOR_CARD_NO_GRANT=evaluate`: an authorization with no hold is evaluated at the commit boundary, below. An `ALLOW` is held and claimed in the same call; an `ESCALATE` is answered `PENDING` with the handoff, the platform pends the authorization, the tap arrives through `POST /v1/escalations`, and the re-presented authorization matches the hold the tap left. Needs a platform that can pend.                                                                               |
| After the authorization                    | **Tap to Confirm**, called by the platform     | Nothing can pend, so the authorization goes through and the cardholder confirms or rejects it afterwards in the issuer's app; a rejection is a reversal the bank's own rail carries. AgentSafe's part is evidence only: the same commit-boundary evaluation in `SHADOW` records what policy would have said (`NO_MATCH` with `SHADOW_OBSERVED`), and the `@decionis/iso8583` interceptor's shadow mode records it on the wire. The easiest to build and the weakest: the money has moved. |
| A standing permission, no amount behind it | **Tap to Authenticate**                        | Not a purchase: the cardholder grants an agent permission to buy on their behalf, a new device, account recovery. It is a signal the producer signs and the agent presents with each purchase, verified by the authority and named by policy with `required_signals`: [the standing permission](#a-standing-permission-tap-to-authenticate), below.                                                                                                                                       |

Soft decline and re-present is left off on purpose, as Koard's paper leaves it off: the step-up it
invites assumes a person at a browser.

### The fraud-queue contract

With `EXECUTOR_CARD_NO_GRANT=evaluate`, the hook's answer gains a third shape. An authorization
with no hold for its card and merchant is captured as a `card.purchase` intent of the commit
actor the deployment names (`EXECUTOR_CARD_COMMIT_TENANT_ID`, `EXECUTOR_CARD_COMMIT_ACTOR_ID`,
`EXECUTOR_CARD_COMMIT_ACTOR_TYPE`, `SYSTEM` by default), with the hook's principal, the
authorization's id and the card's velocity in its context, and evaluated now:

| Policy says | The hook answers                                                                                                                                                                                                                                                              |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ALLOW`     | `{ "decision": "APPROVE", ... }` as a match does: the grant is held and claimed in the same call, and the result settles it.                                                                                                                                                  |
| `ESCALATE`  | `{ "decision": "PENDING", "authorization_id", "intent_id", "intent_hash", "decision_id", "dossier_id", "expires_at", "escalation": { "mode": "ATTESTATION", "intent", "requirement" } }`. Decionis tells the subscriber (`authority.escalation_required`) at the same moment. |
| `BLOCK`     | `{ "decision": "NO_MATCH", "code": "POLICY_BLOCK" }`; a halt, a ceiling or an authority that did not answer name their own code.                                                                                                                                              |

A `PENDING` authorization waits in the platform's pending state until `expires_at`, the intent's
own expiry (`EXECUTOR_INTENT_TTL_SECONDS`). The issuer app's backend, an `OPERATOR` holding
`escalations.resume`, presents the tap to `POST /v1/escalations` with the handoff's intent, exactly
as in section 3; no agent proposed this intent, so there is no proposer to present it. Decionis
tells the subscriber what became of it (`authority.escalation_resolved`). The platform then re-presents the
same authorization: it finds the hold the tap left and is approved, claimed once, and settled by
its result like any other. Re-presented before the tap, it is answered `PENDING` again, from the
same intent, and nothing is evaluated twice; re-presented with a different amount under the same
id, it is `AUTHORIZATION_ID_REUSED`; past `expires_at` it is evaluated afresh. A result posted
for a `PENDING` authorization is `404 CARD_AUTHORIZATION_UNKNOWN`, since nothing was claimed.
The pending answers are kept per replica; a re-presentation that reaches another replica before
the tap is evaluated there too, and the tap resolves one of the two intents while the other
expires with no effect.

## A standing permission: Tap to Authenticate

A cardholder taps once to let an agent buy on their behalf for a while: up to an amount, in a
currency, with a card. Nothing is held, since there is no purchase yet. What Koard produces is a
signed signal: a compact Ed25519 JWS, `typ` `decionis-signed-signal+jwt`, issued by the producer
(`iss`, `koard`) to the bank (`aud`, its organisation id) about an opaque subject (`sub`, never a
card number), with `iat`, `exp` at most thirty days later, `jti`, and a `signal` claim:

| Claim                   | What it says                                                                          |
| ----------------------- | ------------------------------------------------------------------------------------- |
| `signal.name`           | the fact's name, `card_delegation` here (`^[a-z][a-z0-9_]{0,63}$`)                    |
| `signal.method`         | how the producer verified the person who granted it, `card_tap`                       |
| `signal.result`         | `VERIFIED`; a `FAILED` signal is refused                                              |
| `signal.agent`          | optional: the agent principal the permission is for                                   |
| `signal.scope.actions`  | optional: the actions it covers, `["card.purchase"]`                                  |
| `signal.limits`         | optional: `{ "currency": "USD", "amount_minor": 5000 }`, the most one purchase may be |
| `signal.card_token_ref` | optional: the card, as an opaque token reference                                      |

The agent presents it with the proposal, beside the intent and never inside it:

```json
{
  "proposal": {
    "action": "card.purchase",
    "target": "card:tok_synthetic_card_a",
    "parameters": {
      "cardTokenRef": "tok_synthetic_card_a",
      "amountMinor": 4000,
      "currency": "USD",
      "merchantId": "merchant_synthetic_1"
    }
  },
  "idempotency_key": "purchase-one",
  "signals": [{ "token": "<compact JWS>" }]
}
```

The executor carries the token to the authority as evidence (`evidence.signals`) and keeps
nothing of it: it is in no journal line, no hold row and no response. The authority verifies it
against the key the bank registered for the producer (`POST /v1/execution/provider-keys` with
`purpose` `signed_signal`), or against the JWKS of a provider the bank admitted from the
directory, and writes the facts under `agent_safe.signed_signals.<name>`: the producer, the
method, the subject, the signal id, the key id, the issued and expiry times, a digest of the
token (`evidence_digest`), what the signal asserts, and `covers`, one entry per axis, `true`,
`false`, or `null` when the signal says nothing about it: `action` (the intent's action is in
`scope.actions`), `agent` (the proposer is the named agent), `amount` and `currency` (the purchase
is within `limits`), `card` (the card is the one named). `covers_intent` is true when nothing the
signal asserts is false. The facts are recorded in the signed binding and rebuilt at the claim,
where the key's trust and the expiry are checked again; the token itself is recorded nowhere.

The policy for it names the fact and reads one of them: `required_signals` carries
`agent_safe.signed_signals.card_delegation`, so a purchase without the signal escalates; a rule
compares `agent_safe.signed_signals.card_delegation.covers_intent` with `true` and allows; the
escalation rule's `verification_requirements` name `CARD_TAP` through `koard`, so anything the
permission does not cover goes to the cardholder's tap as a held purchase does. The bundle itself
is on the Decionis docs page for card authorization.

A forged, expired or mis-addressed token is refused before any evaluation, as a forged tap is
(`SIGNED_SIGNAL_SIGNATURE_INVALID`, `SIGNED_SIGNAL_EXPIRED`, `SIGNED_SIGNAL_AUDIENCE_MISMATCH`,
`SIGNED_SIGNAL_KEY_UNKNOWN`), and the proposal fails closed with that code. The edge evaluator
holds no producer keys, so a proposal that carries a signal is decided by the hosted authority
even where the claim is local.

## Hosting and key custody

Where the authority and Presence run per hosting tier, and whose custody every signing key is in,
are written once in the deployment guide,
[Hosting tiers and where the keys live](../gateway/deployment.md#hosting-tiers-and-where-the-keys-live).
For the card path the short form is: the grant the hook claims is minted and signed by the
authority (Decionis-run and hosted, Decionis-run for one bank, or bank-run under licence), its
key is a Key Vault secret of that deployment or the bank's own secret manager; the cardholder's
tap is signed by the provider and verified against the provider's public key; and everything the
gateway holds (the card hold key, the tokenizer key, the evidence and TLS keys) is in the bank's
secret store and never leaves it.

## Weeks 10 to 12: enforcement on one range, with a stop

Koard's path to a bank ends with enforcement on a narrow issuing range and a kill switch. Both are
built:

- **BIN scoping.** The `@decionis/iso8583` interceptor governs only the issuing ranges named in
  its `binRanges`; an authorization outside them passes through to the host untouched and is
  recorded as ungoverned. Widen the list range by range as the shadow weeks show what each would
  have done.
- **The stop.** `POST /v1/control/halt` with a reason, by an `OPERATOR` holding `halt`, or the
  halt file (`EXECUTOR_HALT_FILE`) on the host: the gateway takes no new work, the hook answers
  `NO_MATCH` with `EXECUTOR_HALTED`, and the interceptor's fail policy says what each frame then
  does on the wire (`onUnavailable`: forward or decline). The [incident response
  guide](../incident-response.md) has the rest of the stop and the evidence it leaves.

## Outcome evidence for the Decionis meter

The Decionis outcome meter measures what the card path held, released and let through, against an
agreement the bank signs, and closes each month in a signed statement. AgentSafe states the facts
of each card purchase as `decionis.outcomes.evidence/1`; Decionis's `OutcomeCalculator` classifies
them, and nothing in AgentSafe does. Evidence is off unless the deployment turns it on, and turning
it on changes no authorization: each fact is recorded after its answer has been given, and the
evidence goes to Decionis on a timer, never on the request path.

### Turning it on

| Variable                                  | What it is                                                                                                |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `EXECUTOR_CARD_OUTCOMES`                  | `off` (the default), `record` (keep the facts) or `publish` (keep them and send the evidence to Decionis) |
| `EXECUTOR_CARD_OUTCOMES_DIR`              | `record` and `publish`: where the facts and the publisher's state live; absolute, private to the process  |
| `EXECUTOR_CARD_OUTCOMES_ORG_ID`           | `publish`: the Decionis organization the evidence is about                                                |
| `EXECUTOR_CARD_OUTCOMES_INTERVAL_SECONDS` | `publish`: how often a run starts, one minute to a day; an hour by default                                |
| `DECIONIS_PRODUCER_TOKEN`, `_FILE`        | `publish`: the producer token Decionis registered for this deployment; a secret, a file in production     |

Decionis takes outcome evidence from a registered producer only. The token has to be the one its
`DECIONIS_DELIVERY_PRODUCERS_JSON` entry names with `outcomes: "agentsafe"`, and Decionis has to
run with `DECIONIS_OUTCOMES_ENABLED=1`. The bank's own `DECIONIS_API_KEY` is never a producer, so
the bank's key cannot feed the meter that measures the bank. The evidence goes to
`POST {DECIONIS_API_URL}/v1/outcomes/evidence` through the same guarded egress, CA bundle and pins
as every other call to the authority.

Each purchase is stated under the platform module id **`card-authorization`**, with the action type
`CARD_PURCHASE`. An agreement counts card evidence only when its scope names that platform and that
action type, and names no connection ids: card evidence carries none. (The executor that answers
the issuer's hook runs as the `card-issuer` platform; `card-authorization` names what is measured.)

With several replicas, every replica's `EXECUTOR_CARD_OUTCOMES_DIR` points at one volume they all
mount. Each replica writes its own files (`card-outcomes-<day>.<replica>.jsonl`), exactly one
replica runs `publish`, and the rest run `record`. The publisher reads every replica's facts, so a
purchase held on one replica and claimed on another is stated as one purchase. A volume per
replica would state only what that replica saw, as differing evidence for the same purchase.

### What it states

One subject per purchase: the digest of the tenant and the purchase's intent id. Every stated
purchase carried a decision, so its coverage is `GOVERNED`. Its amount is what the purchase named
at decision time, in its own currency and minor units, never converted. The decision's `mode` says
whether it was enforced or only evaluated in shadow.

| What happened                                                                       | Decision                              | Review                                  | Execution                                                     |
| ----------------------------------------------------------------------------------- | ------------------------------------- | --------------------------------------- | ------------------------------------------------------------- |
| Allowed; the issuer's authorization claimed the grant and the issuer approved       | `PROCEED`                             | none                                    | `COMMITTED`, with the grant id and the effect record's digest |
| Allowed, claimed, and declined by the issuer                                        | `PROCEED`                             | none                                    | `FAILED`                                                      |
| Allowed, claimed, and the result came after the claim's lease or has not come       | `PROCEED`                             | none                                    | `UNKNOWN`                                                     |
| Allowed, and the grant expired unspent, or no grant could be kept for the issuer    | `PROCEED`                             | none                                    | `NOT_EXECUTED`                                                |
| Escalated, and released by the cardholder's tap or a Presence approval              | `HOLD`                                | `RELEASED`, `LEGITIMATE`, by `CUSTOMER` | as the claim and the issuer's result say                      |
| Escalated, and refused through Presence (`PRESENCE_DENIED`, `PRESENCE_REJECTED`)    | `HOLD`                                | `REJECTED`, `UNCONFIRMED`               | `NOT_EXECUTED` once the intent has expired                    |
| Escalated, and nobody answered (a forged or expired attestation is no one's answer) | `HOLD`                                | none                                    | `NOT_EXECUTED` once the intent has expired                    |
| Blocked by policy                                                                   | `BLOCK`                               | none                                    | `NOT_EXECUTED` once the intent has expired                    |
| Evaluated in shadow, at the proposal or at the issuer's hook                        | what policy would have said, `SHADOW` | none                                    | none                                                          |

How the meter reads that, under the agreement's own terms: an allowed and committed purchase is
governed value; a hold the cardholder released is a false hold; a refused or blocked hold that
nobody confirmed as a problem is exposure, held but unconfirmed; a hold nobody answered is pending;
a shadow result is an estimate, never summed with realized ones. When a purchase's facts change
after it was stated (the issuer's result arrives, a grant lapses), it is stated again under the
next revision, and Decionis appends that as a correction.

What card evidence never states:

- **A prevented loss.** The meter counts a hold as prevented only when a person confirmed that the
  purchase was a real problem and nothing was paid. AgentSafe records no such confirmation: a tap
  approves a purchase, and a Presence refusal refuses one without establishing that it was a
  problem. So card evidence never says `CONFIRMED_PROBLEM`, and nothing it states is counted as
  prevented.
- **The issuer's money.** Clearing, settlement and reversals are the issuer's, outside this
  boundary; `financial` is always null.
- **What had no decision.** An authorization with no hold answered `NO_GRANT`, which the issuer's
  own policy then decides; a decision the authority never took because it did not answer; and a
  refusal the host made before asking (a halt, a ceiling, a card already held).
- **Card data.** The facts kept for this carry the intent id, the tenant, the decision, dossier and
  grant ids, codes, times, and the purchase's amount and currency. They never carry a card
  reference, a merchant, an authorization id, an approval code or a tap, and the subject is a
  digest. The security stream still carries none of the amounts: only counts and codes
  (`CARD_OUTCOMES_DROPPED`, `CARD_OUTCOMES_PUBLISHED`, `CARD_OUTCOMES_REFUSED`).

### How it is sent

A run reads the last three days of facts, states each purchase, and records a subject at a new
revision only when its evidence changed, then sends what Decionis has not accepted, at most a
thousand subjects per request. Nothing unchanged is sent again, so a restart resends nothing
Decionis already holds. Decionis takes a batch whole or refuses it:

- a revision conflict (Decionis holds that revision with other content) moves the subject to its
  next revision and the batch goes again;
- a refusal the same batch cannot pass (`403` for a token Decionis does not allow to submit, `401`,
  `400`, `404`, `413`, `422`) stops the run until the next interval, with the evidence still owed,
  and is reported as `CARD_OUTCOMES_REFUSED`;
- an outage or `503` (`outcomes_disabled`) is retried after thirty seconds, then four times longer
  each time, never longer than the interval.

A fact that cannot be kept (a full queue, a directory that refuses the write) is dropped and counted
as `CARD_OUTCOMES_DROPPED`; the purchase's evidence then stays at what the kept facts establish.

The wire contract is Decionis's, vendored byte for byte at
`packages/agentsafe/contracts/OutcomeEvidence.v1.json` with its SHA-256 pinned in the source; a
test fails when the copy drifts, and holds every submission the producer builds to that schema.
When Decionis regenerates the contract (`pnpm --filter @decionis/shared outcomes:generate`), copy
the file and update the pinned digest together.

## What this version does not do

- Split authorizations, as above.
- The intent comes from the agent platform. Nothing here derives an intent from an ISO 8583
  message; an authorization with no grant is `NO_GRANT`. The
  [`@decionis/iso8583` interceptor](https://github.com/decionis/Decionis/tree/master/packages/interceptors/iso8583)
  does that on the wire, in its match mode, through this hook.
- Rotating the hold key re-seals nothing: a hold sealed under the previous key is read as absent,
  and expires with no effect. Rotate between bursts, or let the holds drain first.
- A person's confirmation that a held purchase was a real problem. Without one, the outcome
  meter counts no card purchase as prevented, as above.

The evidence boundary is unchanged: the security stream carries intent ids and codes, never a card
reference, an amount, a merchant or a token.
