# Presence

An `ESCALATE` means a person must decide. The gateway holds the request and never turns the hold
into permission; Decionis does, after the ceremony, with a fresh decision.

## Held

The gateway answers `202` with `execution: HELD`, the decision and dossier identifiers, and a
`resume` path, and keeps the captured intent and the raw request in memory until the intent
expires (`intentTtlSeconds`). Nothing reaches the upstream. Without Presence configured that is
the whole answer: `resume` says `409 ESCALATION_NOT_RESUMABLE`, and the operator reads the dossier.

## Managed

With `presence.managed: true` and an `approverId`, the gateway asks Decionis to orchestrate the
ceremony at evaluation time (`EscalationResolver` in `MANAGED` mode, the same class the executor
uses). Decionis creates the Presence request bound to the exact intent hash, the person completes
the ceremony on their own enrolled device, Decionis verifies the receipt and re-evaluates policy.
The gateway holds no Presence credential and polls Decionis only.

`POST /_agentsafe/v1/escalations/{intent_id}/resume` is one bounded lookup: while the person is
deciding it is `202` again with the escalation's state; a refusal is `403` (or `503` when the
lookup failed closed); a fresh `ALLOW` with a grant runs the held request through the same claim,
forward and finalize as any other, once. `GET` on the same path shows the hold.

## What a receipt establishes

A Presence receipt establishes that a named person approved that exact intent hash under the
assurance the receipt records. It does not establish permission to execute: only the decision
Decionis makes with the receipt as evidence can issue a grant, and a receipt for another intent, a
replayed receipt, or an approval after the intent expired yields nothing. The protocol pages are
[human approval](../human-approval.md) and [Presence evidence](../presence-evidence.md); the
executor's `DIRECT` shape, where the process holds a Presence credential and coordinates the
ceremony itself, is the executor's and is not offered by the gateway.
