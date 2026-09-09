# Golden adversarial demo

One legitimate path and eight adversarial attempts against the same execution boundary, run offline
in a few seconds with no credentials. Every expectation is asserted, so the run is a self-checking
proof: it exits 0 only when every attack failed to execute and the legitimate path executed exactly
once per verified grant.

```bash
pnpm --filter @decionis/agent-safe-example-golden-adversarial demo
```

## The scenario

A treasury agent at a bank proposes a USD 250,000 wire. Synthetic policy allows the agent to act
alone below USD 10,000, requires verified human presence up to USD 500,000, and blocks above. The
Chief Risk Officer is remote and completes a FIDO2 plus active-liveness ceremony on their own device.
The only code that can move money is the registered handler behind the executor; the agent never
holds a banking credential and cannot name one.

The demo uses the development fixture authority and an in-process Presence double that keeps the
semantics that matter: a request is bound to the exact intent hash shown to the person, a receipt
exists only after the ceremony, and the authority verifies receipt, request, and hash before evidence
counts. Replace them with `DecionisGate`, `DecionisGrantVerifier`, and the Presence client for the
live services; the executor code does not change.

## What it proves

| Step        | Attempt                                                                   | Outcome                                                  |
| ----------- | ------------------------------------------------------------------------- | -------------------------------------------------------- |
| Golden path | Escalate, verified ceremony, re-authorization, exact grant                | `COMPLETED`, exactly one wire                            |
| Attack 1    | Proposal carries `authorized: true` and `approved_by: CRO`                | Rejected at capture; no intent exists                    |
| Attack 2    | A receipt identifier smuggled inside the agent's parameters               | Still `ESCALATE`; the sealed registry refuses the field  |
| Attack 3    | The agent fabricates an `ALLOW` decision with its own token               | `AUTHORIZATION_INVALID`                                  |
| Attack 4    | The agent asserts the CRO approved, with no ceremony                      | Authority `BLOCK`                                        |
| Attack 5    | Wire A's receipt presented for wire B                                     | Authority `BLOCK`; `INTENT_BINDING_MISMATCH`             |
| Attack 6    | Amount raised to USD 2,500,000 after approval                             | `INTENT_BINDING_MISMATCH`; the captured intent is frozen |
| Attack 7    | The consumed grant replayed, then 25 concurrent claims of a fresh grant   | Replay `AUTHORIZATION_INVALID`; exactly one winner       |
| Attack 8    | A shadow observation cast as a decision; a grant used after intent expiry | `DECISION_NOT_AUTHORITATIVE`; `AUTHORIZATION_INVALID`    |

The run ends with the redacted audit trail for the golden path and a check that the execution token
never appears in it.

## Reading the output

Each block names the attempt, prints what Presence and the authority did, and ends with `PASS` or
`FAIL`. The final line reads `PROVEN` with the counts, or `NOT PROVEN` with a non-zero exit code.
Attack 7 executes once by design: the point is that 25 simultaneous claims of one grant yield one
execution, and that count is excluded from the unauthorized total.

Finalization shows `RECORDED` because the development fixture keeps an inspectable commit ledger:
the run prints the ledger entry for the golden grant and asserts its outcome is `COMMITTED`. The
production verifier records the same outcome with Decionis so it joins the Decision Dossier chain.

For the same sequence drawn for a bank audience, see
[`docs/remote-cro-authorization.md`](../../docs/remote-cro-authorization.md). For what the receipt
does and does not prove, see [`docs/presence-evidence.md`](../../docs/presence-evidence.md).
