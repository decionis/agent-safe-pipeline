# Local escalation

Runs both Presence integration modes locally with no credentials. Two loopback doubles from
`@decionis/agent-safe-pipeline/testing` stand in for Decionis and Presence; the production clients
are used unchanged. The person's ceremony is simulated through the local Presence control route.

```bash
pnpm --filter @decionis/agent-safe-example-local-escalation demo
```

## What runs

| Step                     | Mode    | What happens                                                                                                                                             |
| ------------------------ | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `direct_handoff`         | DIRECT  | `PresenceApprovalCoordinator` drives the real `@decionis/presence-node` gate against the local Presence; the request is bound to the intent hash         |
| `ceremony`               | both    | `POST /local/verification-requests/:id/complete` with `APPROVE` or `DENY`, what the person would do on their device                                      |
| `direct_execution`       | DIRECT  | Re-authorization with the receipt, claim through `DecionisGrantVerifier`, one simulated refund, and a `COMMITTED` commit recorded by the local authority |
| `direct_swapped_receipt` | DIRECT  | The receipt presented for a different intent is refused                                                                                                  |
| `direct_denied`          | DIRECT  | A denied ceremony ends in a fail-closed `BLOCK`                                                                                                          |
| `managed_pending`        | MANAGED | The local authority creates the Presence request itself, bound structurally to the intent hash with the requested ceremony                               |
| `managed_execution`      | MANAGED | `waitForAuthorization` polls the authority only and returns a normal grant once the receipt is verified                                                  |
| `managed_denied`         | MANAGED | A denied managed ceremony is a typed terminal state with no grant                                                                                        |

The process exits 0 only when both modes end with a claimed grant, exactly two executions in total,
and a `COMMITTED` outcome recorded by the local authority.

## Reading the output

Every stage is one JSON line. `bindingSource` shows how the Presence request was bound: `structural`
when `action_context.intent_hash` was sent, `display_field` when only the `Intent hash` display field
was. The managed request is always structural because the local authority builds it the way
Decionis does; the direct request becomes structural once the Presence SDK forwards the coordinator's
`intentHash`.

For the doubles' semantics and limits, see [`docs/local-testing.md`](../../docs/local-testing.md).
