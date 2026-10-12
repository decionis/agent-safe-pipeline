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

The match is pure and local: same card, same currency, same merchant (and category when the
purchase named one), an amount at or below the grant, a grant unexpired and unspent. A match claims
the grant through the authority exactly once and answers `{ "decision": "APPROVE", ... }`; anything
else answers `{ "decision": "NO_MATCH", "code": ... }`, and what that means for the authorization is
the issuer's own policy. The codes, the retry semantics and the per-process bounds are in the
README's card section.

## 5. The result becomes the effect

The hook posts what it did to `POST /v1/card-authorizations/{authorization_id}/result`. An
approval finalizes the grant as `COMMITTED` with the effect compared against the grant; an amount
above the ceiling is `EFFECT_MISMATCH`, which halts the executor by default. A decline finalizes
`FAILED`; a result after the claim's lease finalizes `INDETERMINATE`. The dossier then carries the
intent, the policy version, the approval facts and what the issuer actually approved.

## What this version does not do

- Holds are per process and in memory. A restart loses only grants nobody claimed. Replica routing
  and a shared store are later work.
- One pending purchase per card at a time. A second purchase on the same card waits for the first
  to be authorised or to expire.
- The intent comes from the agent platform. Nothing here derives an intent from an ISO 8583
  message; an authorization with no grant is `NO_MATCH`.
- The latency of the claim call inside the authorization's budget has not been published.

The evidence boundary is unchanged: the security stream carries intent ids and codes, never a card
reference, an amount, a merchant or a token.
