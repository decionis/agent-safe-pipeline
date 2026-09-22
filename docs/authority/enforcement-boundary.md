# The enforcement boundary

A Decision Dossier says who proposed an action, what exactly the action was, which policy decided
it, and what happened. In an estate running one gateway that is the whole story. In an estate
running three hundred — Docker here, two Kubernetes clusters there, a Linux host beside a legacy
system, the hosted runtime for the rest — one question is still open:

**which of them admitted the effect?**

The enforcement boundary is the answer, and it is inside the intent hash.

## What a boundary is

A boundary is the _configured logical door_, not the process standing in it. Restart the
container, reschedule the pod, scale the deployment to thirty replicas: same boundary, same id.
Point it at a different upstream, or run it for a different environment, and it is a different
boundary with a different id.

That distinction is the whole design. An identity that moved when a pod did would be an instance
id wearing a boundary's name, and an operator grouping evidence by it would be grouping by
nothing.

```text
boundary_id          prod-payments-eu (configured)
runtime              kubernetes
agentsafe_version    0.3.4
protocol_version     agent-safe.intent/1
environment          production
conformance          agent-safe-intent-v1
cluster              eu-1
namespace            payments
```

`agentsafe identity` prints this, with `--json` for a machine. It runs before there is a
configuration, so an operator can see what a process would resolve to.

## Where the id comes from

| Source            | How                                                                      |
| ----------------- | ------------------------------------------------------------------------ |
| An operator       | `AGENTSAFE_BOUNDARY_ID`, else `boundary.id` in `agentsafe.yaml`          |
| The configuration | `bd_` and a digest over deployment type, environment and upstream origin |

The derived form reads configuration, never the machine: no hostname, no address, no user, no
container id. It is therefore stable across restarts and carries nothing about the host into
evidence. It is also a compatibility contract pinned by a test, because changing the derivation
would silently re-partition the evidence of every deployment that never named a boundary.

A derived id wears the `bd_` prefix so it is never mistaken for one somebody chose.

## What is bound, and what is only reported

Split by lifetime, deliberately:

| Field                                                 | Bound into the intent | Why                                                             |
| ----------------------------------------------------- | --------------------- | --------------------------------------------------------------- |
| `boundary_id`, versions, deployment type, environment | yes                   | the boundary's identity; what evidence must name                |
| `placement`: cluster, namespace, region, workload     | yes                   | survives a restart; what a policy means by "production in eu"   |
| container, pod, node                                  | no                    | this instance, not this boundary; host-sensitive, and ephemeral |

The instance appears in `agentsafe identity` for an operator reading one process's own output,
and nowhere on the wire. An effect's evidence should say which boundary admitted it, not which
container was alive that second.

Every field is read from variables the operator's own manifest declares. Nothing is scraped from
`/proc`, no Docker API is called, and no value is inferred. A variable holding something that is
not a well-formed token is no value rather than a guess.

## How it is bound

Inside the canonical hash, as a reserved key in the intent's `context`:

```json
"context": {
  "idempotency_key": "pay-1",
  "enforcement_boundary": {
    "boundary_id": "prod-payments-eu",
    "agentsafe_version": "0.3.4",
    "protocol_version": "agent-safe.intent/1",
    "deployment_type": "kubernetes",
    "environment": "production",
    "conformance_version": "agent-safe-intent-v1",
    "placement": { "cluster_id": "eu-1", "namespace": "payments" }
  }
}
```

This is the mechanism the trusted idempotency key already uses, for the same reason: the Decionis
`ExecutionIntentBinding` contract declares `unevaluatedProperties: false` at the top level and
`additionalProperties: true` on `context`, and every property of `context` is inside the hash.
See [ADR 0006](../architecture/decisions/0006-enforcement-boundary-identity.md).

Two consequences follow:

- **The boundary is not a claim about the request; it is part of what the authority was issued
  against.** A grant is bound to those bytes.
- **An intent that carries no boundary hashes exactly as it did before.** Every published
  conformance vector still holds, and `agent-safe.intent/1` did not change.

A caller cannot write the key. `IntentCapture` refuses a trusted context that already carries a
reserved one (`INTENT_CONTEXT_KEY_RESERVED`), and an agent's proposal has never been able to
reach `context` at all.

## Boundary substitution

An authority issued through one boundary is not presentable at another.

`SafeExecutor` takes an optional `boundaryId`; the gateway sets it to its own. When it is set, an
intent captured through a different boundary — or through none — is refused with
`BOUNDARY_MISMATCH`:

```text
authority issued at   prod-payments-eu
presented at          staging-payments-us
                      →  BOUNDARY_MISMATCH, nothing dispatched
```

The refusal happens **before** the claim, so the grant the owning boundary holds is left intact
for it to spend. A boundary that refuses an intent must not burn somebody else's single use.

Underneath that explicit check, the hash already does the work: an intent naming another boundary
is different bytes, so its grant does not match. Boundary substitution fails by the same mechanism
that defeats parameter mutation and target substitution, rather than by a new one.

Leaving `boundaryId` unset is the behaviour that existed before this page, exactly.

## What it does not do

The boundary says which door an action came through. It does not say the door was configured
well, that the workload behind it is the one it claims to be, or that the operator who set
`AGENTSAFE_BOUNDARY_ID` was entitled to that name. A boundary id is an identifier inside a
workspace, not a credential; the key the gateway presents is what authenticates it to Decionis.

## See also

- [ADR 0006](../architecture/decisions/0006-enforcement-boundary-identity.md) — the decision, and the two options not taken
- [ExecutionBinding](./execution-binding.md) — everything else an intercepted request binds
- [Telemetry](../reference/telemetry.md) — `BOUNDARY_IDENTIFIED`, and what never leaves the process
- [CLI reference](../reference/cli.md) — `agentsafe identity`
