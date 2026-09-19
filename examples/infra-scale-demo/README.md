# Infrastructure scale demo: the Compromised Principal Test

One legitimate scale-out and seven adversarial attempts by a **valid principal** against the same
execution boundary, run offline in a few seconds with no credentials. Every expectation is
asserted, so the run is a self-checking proof: it exits 0 only when every attack failed to execute
and each legitimate path executed exactly once per verified grant.

```bash
pnpm --filter @decionis/agent-safe-example-infra-scale demo
```

## The test

Most adversarial corpora test forged credentials: a token the attacker should not hold, a
signature that does not verify. The realistic failure is the other one. The agent's identity is
real, its credential is valid, and the API it calls is one it is permitted to call; what it asks
for is not what anyone authorised.

```text
valid principal → valid credential → permitted API → unauthorized consequential intent → BLOCK | ESCALATE
```

An agent that may call `deployment.scale` is not an agent that may scale anything to anything.
The boundary binds the exact action, principal, cluster, service, replicas, policy revision and
expiry, into one hash; Decionis decides over that hash; a grant is good for that hash once; and a
change to any bound field after authorization fails the binding. Identity says who is asking.
Execution authority says whether this is permitted to happen. The faster and more autonomous the
agent, the less the first can stand in for the second.

## The scenario

An infrastructure agent proposes:

```text
deployment.scale
cluster:   prod-eu
service:   inference
replicas:  96
```

Synthetic policy holds the agent's remit, not its identity: `prod-eu` only, the `inference` and
`retrieval` services, up to 128 replicas on its own, up to 512 with the SRE on call approving that
exact intent through a Presence ceremony, never zero, and nothing above. The only code that can
change a replica count is the registered handler behind the executor, which resolves the cluster
credential at dispatch; the agent never holds one and cannot name it.

## What it proves

| Step        | Attempt                                                               | Outcome                                                     |
| ----------- | --------------------------------------------------------------------- | ----------------------------------------------------------- |
| Golden path | 48 → 96 replicas, within the autonomous ceiling                       | `ALLOW`, `COMPLETED`, exactly one scale                     |
| Attack 1    | The same valid agent proposes 960 replicas                            | Authority `BLOCK`; nothing scales                           |
| Attack 2    | `payments` scaled to zero: outside the remit, and an outage           | Authority `BLOCK`                                           |
| Attack 3    | `inference` in `prod-us`: another team's cluster                      | Authority `BLOCK`                                           |
| Attack 4    | Replicas changed after authorization, 96 → 960, with the 96 decision  | `INTENT_BINDING_MISMATCH`; the captured intent is frozen    |
| Attack 5    | 256 replicas need the SRE; the approval for 256 is presented for 512  | `ESCALATE`, one approved execution, then `BLOCK`            |
| Attack 6    | The consumed grant replayed, then 25 concurrent claims of a fresh one | `AUTHORIZATION_INVALID`; exactly one winner                 |
| Attack 7    | The agent calls the cluster API itself, with the credential it has    | `401`: the agent zone holds no credential the cluster takes |

Attacks 5 and 6 each execute once by design, on a grant the run itself verified; those executions
are counted as authorised and excluded from the unauthorized total. The run ends with the redacted
audit trail for the golden path and a check that neither the execution token nor the cluster
credential appears in it.

## In the cluster

This is the case the [deployment kit](../../deploy/README.md) exists for. The trusted executor
runs in its own namespace with the one credential the cluster's API accepts for `deployments/scale`,
projected as a file and resolved at dispatch; the agent zone runs the proposing workflow with no
service-account token and no route anywhere but the executor's listener. A compromised agent in
that zone can propose whatever it likes, and the proposal meets the same boundary this demo runs:
the authority decides over the exact action, the executor effects the authorised one once, and the
cluster refuses everyone else.

## Reading the output

Each block names the attempt, prints what the authority and, where a ceremony was needed, Presence
did, and ends with `PASS` or `FAIL`. The final line reads `PROVEN` with the counts, or
`NOT PROVEN` with a non-zero exit code.

The demo uses the development fixture authority and an in-process Presence double that keeps the
semantics that matter: a request is bound to the exact intent hash shown to the person, a receipt
exists only after the ceremony, and the authority verifies receipt, request, and hash before
evidence counts. Replace them with `DecionisGate`, `DecionisGrantVerifier`, and the Presence client
for the live services; the executor code does not change.

## Hosted epilogue

`DECIONIS_HOSTED=1` (or `DECIONIS_API_KEY` with `DECIONIS_TENANT_ID`) adds one step after the
proof: Decionis evaluates the golden scale-out beside the fixture, in shadow, so nothing above
changes, and the run ends with the signed Decision Dossier it left, its verification page when the
authority attaches one, and how to verify it offline. With no key, the run mints a free provisional
workspace and stores its key for the next run. The adversarial attempts stay local by design; they
are about this boundary, not the authority. Unset, the run prints one hint line and nothing else
changes.

For the same test stated as a threat, see the Compromised Principal Test in
[`THREAT-MODEL.md`](../../THREAT-MODEL.md); for what the intent hash covers and the conformance
vector that pins it, see [execution intent](../../docs/execution-intent.md).
