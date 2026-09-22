# ADR 0006: an enforcement boundary with an identity, inside the intent hash

Status: accepted, 2026-09-22.

## Problem

AgentSafe is deployed as many gateways at once. A single customer may run it in Docker, in
Kubernetes across two clusters, on a Linux host beside a legacy system, and through the hosted
runtime, all against one Decionis workspace. Every one of them produces decisions, grants and
dossiers into the same evidence.

Nothing in any of that says which of them admitted an effect.

`boundary_id` had zero occurrences in the repository. The nearest thing was
[`gateway/InstallSurface.ts`](../../../packages/agentsafe/src/gateway/InstallSurface.ts), one
closed token naming the distribution a process was installed from, and deliberately nothing more:
"nothing is derived from the network, the user or the machine." That is the right constraint and
it does not answer the question. `surface=docker` is true of every AgentSafe container in the
estate.

So an auditor reading a Decision Dossier could establish the principal, the exact action, the
policy and the grant, and could not establish the door. An operator investigating an incident
could not scope it to one boundary. A policy could not say "this action, only through the
production boundary in eu," because there was no way to name one.

## Options considered

1. **An instance identifier, from the runtime.** Read the container id from `/proc/self/cgroup`,
   or the pod name from the downward API, and report that. It is available without asking the
   operator for anything, and it is precise. It is also the wrong object: it changes on every
   restart, every reschedule and every replica, so grouping evidence by it groups by nothing, and
   it is host-sensitive — writing it into signed evidence puts the machine into the record for no
   authority benefit. Reading `/proc` also widens the Node permission model's `--allow-fs-read`
   grant in the distroless image.

2. **A new top-level property on the binding.** Add `boundary` beside `actor` and
   `downstream_target` in the `ExecutionIntentBinding`. It is the most legible shape, and it is
   not available: the Decionis OpenAPI declares `ExecutionIntentBinding` with
   `unevaluatedProperties: false`, so an unknown top-level property is a refused request. Taking
   it would mean a contract change in Decionis, a new `agent-safe.intent/2`, and a re-issue of
   every published conformance vector — for an optional, additive signal.

3. **A reserved key inside the hashed `context`.** The same contract declares `context` as
   `additionalProperties: true`, and every property of `context` is inside the canonical hash.
   The package already does exactly this for the trusted idempotency key
   (`RESERVED_CONTEXT_IDEMPOTENCY_KEY`), for the same reason and with the same comment.

## Decision

Option 3, with the identity split by lifetime.

**The identity.** `EnforcementBoundary` in
[`boundary/BoundaryIdentity.ts`](../../../packages/agentsafe/src/boundary/BoundaryIdentity.ts)
is the configured logical boundary: `boundary_id`, the AgentSafe version, the protocol version,
the conformance profile, the deployment type (reusing `InstallSurface`), and the environment.
An operator names it in `AGENTSAFE_BOUNDARY_ID` or `boundary.id`. When nobody names one it is
derived — `bd_` and the first sixteen hex of a SHA-256 over the deployment type, the environment
and the upstream origin, joined by newlines. Nothing about the host, the network, the user or the
container is in that material, so it survives a restart, a reschedule and a scale-out, and two
gateways configured alike are one boundary. The derivation is pinned by a test, because changing
it would silently re-partition the evidence of every deployment that never named a boundary.

**The split by lifetime.** Placement that survives a restart — cluster, namespace, region,
workload — is bound into the intent, because it is what a policy means by "production in eu."
Placement that does not — container, pod, node — is reported by `agentsafe identity` and bound
nowhere. An effect's evidence should say which boundary admitted it, not which container happened
to be alive that second.

**What reads the runtime.** Only variables an operator's own manifest declares. No `/proc`, no
Docker API, no hostname, no inference. A value that is not a well-formed token is no value rather
than a guess, exactly as an unrecognised `AGENTSAFE_SURFACE` is no surface.

**The refusal.** `SafeExecutor` takes an optional `boundaryId`. When set, an intent captured
through another boundary — or through none — is refused with `BOUNDARY_MISMATCH`, before the
claim, so the authority the other boundary owns is left intact for it. The gateway sets it to its
own. Left unset, nothing changes.

**The command.** `agentsafe identity` prints what this process is, so an operator can see the id
is stable before relying on it, and can read it before there is a configuration at all.

## Reason

The boundary belongs in the hash, not beside it. A signal carried outside the canonical bytes is
a claim about the request; a signal inside them is part of what the authority was issued against.
Because the boundary is hashed, an intent whose boundary is edited after capture fails
`SafeExecutor`'s conformance recheck before the handler runs, and an authority issued at one
boundary is bound to bytes that name that boundary. Boundary substitution therefore fails by the
same mechanism that already defeats parameter mutation, rather than by a new one.

## Protocol impact

None to the wire contract. `agent-safe.intent/1` is unchanged: the binding's shape, its
canonicalization and its schema are as published. The new property is an entry in `context`,
which the contract has always declared open and always hashed.

An intent that carries no boundary hashes byte-for-byte as it did before, so every vector under
[`conformance/`](../../../conformance) and every published intent hash still holds. This is the
additive rule in [`spec/intent/v1` §9](../../../spec/intent/v1/README.md), used as intended.

Decionis policy can read `context.enforcement_boundary.*` today, in the namespace CommerceGate
policy already uses for signals. Whether it does is a decision for the control plane, not for
this repository.

## Compatibility impact

Nothing is required of an existing deployment. A gateway with no `AGENTSAFE_BOUNDARY_ID` and no
`boundary.id` derives one and carries it; its intent hashes change, which is invisible to it,
because a hash is only ever compared to the one the same capture produced. `SafeExecutor`
constructed with three arguments behaves exactly as before. AgentSafe outside a container is
unaffected: the deployment type is whatever `InstallSurface` already said, or `unknown`.

## Security impact

- The boundary signal is written by the runtime, never by a caller. `IntentCapture` refuses a
  trusted context that already carries a reserved key (`INTENT_CONTEXT_KEY_RESERVED`), and an
  agent's proposal has never been able to reach `context` at all.
- Boundary substitution is refused twice over: by `BOUNDARY_MISMATCH` before the claim, and by the
  canonical hash, since an intent naming another boundary is different bytes.
- The refusal is deliberately before `verifyAndConsume`. A boundary that refuses an intent must not
  burn the single-use grant the boundary that owns it will present.
- Nothing host-sensitive reaches the wire. The container, pod and node are reported locally only,
  and a test asserts they appear nowhere in the signal.
- `BoundaryIdentity.ts` is on the repository's mutation gate at 100%, because a mutant that let an
  id move with a container would attribute an effect to a boundary that never admitted it.

## Migration impact

Name the boundary where the estate has more than one: `AGENTSAFE_BOUNDARY_ID` in the manifest, or
`boundary.id` in `agentsafe.yaml`. Declare placement with the downward API where Kubernetes can
supply it. Neither is required, and neither changes any decision.

Run `agentsafe identity` to see what a process resolves to, including before it has a
configuration.
