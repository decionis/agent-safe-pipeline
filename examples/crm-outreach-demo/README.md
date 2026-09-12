# CRM outreach demo: who can approve an AI agent's customer-acquisition action?

One legitimate CRM update, one approved outbound message, and six adversarial attempts against the
same execution boundary, run offline in a few seconds with no credentials. Every expectation is
asserted, so the run is a self-checking proof: it exits 0 only when every attack failed to execute
and each legitimate path executed exactly once per grant.

```bash
pnpm --filter @decionis/agent-safe-example-crm-outreach demo
```

## The scenario

A sales-development agent works a prospect list. The host attaches, as the trusted context of every
captured intent, what the CRM of record says about the contact at capture time — territory, consent
status, lifecycle stage, contact tier, account owner. The agent never writes any of it.

Two handlers are registered behind the executor: one updates a contact record, one sends a message.
They are the only code that can write to the CRM or send a message; each holds its provider
credential; the agent never sees either.

Synthetic policy decides over those committed facts and nothing else. A contact update inside the
owner's territory is allowed on its own. An outbound message needs the named account owner's
verified approval, an approved template, and a contact who opted in. An executive-tier contact is
never messaged by an agent at all.

The demo uses the development fixture authority and an in-process Presence double. Replace them
with `DecionisGate`, `DecionisGrantVerifier`, and the Presence client for the live services; the
executor code does not change.

## Who can approve

| Action                  | Who decides                                                                          | What happens on `ESCALATE`                                                                                                                                                                   |
| ----------------------- | ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crm.contact.update`    | Policy, from the territory in the trusted context; nobody signs inside the territory | Not reached in this demo                                                                                                                                                                     |
| `outreach.message.send` | Policy escalates every send to the named account owner                               | The owner completes a Presence ceremony bound to this exact message; the receipt goes back to the authority, which evaluates the same intent again; only that evaluation can issue the grant |

The receipt authorizes nothing on its own. It is evidence that a named person approved this exact
intent hash; see [`docs/presence-evidence.md`](../../docs/presence-evidence.md).

## What it proves

| Step          | Attempt                                                                           | Outcome                                                                                                                                                                                                          | Owning document                                                      |
| ------------- | --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Golden path 1 | A contact record updated inside the owner's territory                             | `ALLOW`; `COMPLETED`; exactly one write; ledger `COMMITTED`                                                                                                                                                      | [`docs/allow-escalate-block.md`](../../docs/allow-escalate-block.md) |
| Golden path 2 | An outbound message the account owner approved                                    | `ESCALATE`, then `ALLOW` after the ceremony; exactly one send; ledger `COMMITTED`                                                                                                                                | [`docs/human-approval.md`](../../docs/human-approval.md)             |
| Attack 1      | Recipient changed after the owner approved                                        | `BLOCKED`, `INTENT_BINDING_MISMATCH`: the grant is bound to one intent hash                                                                                                                                      | [`docs/presence-evidence.md`](../../docs/presence-evidence.md)       |
| Attack 2      | Template swapped for one the owner never saw                                      | Authority `BLOCK`, even with the owner's receipt from the approved send presented                                                                                                                                | [`docs/trust-boundary.md`](../../docs/trust-boundary.md)             |
| Attack 3      | Message to a contact who opted out                                                | Authority `BLOCK`, from the consent status the host attached                                                                                                                                                     | [`docs/trust-boundary.md`](../../docs/trust-boundary.md)             |
| Attack 4      | Message to an executive contact, with the owner's receipt from another send       | Authority `BLOCK`: the receipt is bound to another intent, and the tier refuses regardless                                                                                                                       | [`docs/presence-evidence.md`](../../docs/presence-evidence.md)       |
| Attack 5      | The owner's approval used again after it expired, and the consumed grant replayed | `BLOCKED`, `AUTHORIZATION_INVALID` twice                                                                                                                                                                         | [`docs/execution-outcomes.md`](../../docs/execution-outcomes.md)     |
| Attack 6      | Provider response lost after dispatch, then a retry                               | `UNKNOWN_AFTER_DISPATCH` with `executed: null`, finalized `INDETERMINATE`; the retry with the same grant is `BLOCKED`; reconciliation reads the provider's record and returns `COMPLETED`; nothing is sent twice | [`docs/execution-outcomes.md`](../../docs/execution-outcomes.md)     |

## Reading the output

Each block names the attempt, prints what the authority did, and ends with `PASS` or `FAIL`. The
final line reads `PROVEN` with the counts, or `NOT PROVEN` with a non-zero exit code. `PASS` for an
attack means the attempt did not execute — not that the agent noticed anything. CI runs this demo on
every pull request through `pnpm examples:prove`.

## What it does not prove

It does not show that outreach converts, that a lifecycle stage is the right one, or that the CRM
data is accurate; policy decides whether the write may happen, not whether it is good business. It
does not name or call a real CRM or messaging vendor; the handlers are simulated. It is the sales
reading of "customer acquisition". Creating, approving, or activating a bank customer is a different
action with different evidence, and this demo does not show it.
