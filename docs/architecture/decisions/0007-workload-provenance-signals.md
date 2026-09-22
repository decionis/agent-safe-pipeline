# ADR 0007: workload provenance as a carried signal, with its trust source attached

Status: accepted, 2026-09-22.

## Problem

A policy should be able to say "only this approved release may move money in
production." Doing that needs the answer to a question AgentSafe could not previously carry: what
software is proposing this action?

The repository had nothing. `oci` and `publisher` had zero occurrences in source; the only
`trust_level` was `actor.trust_level` on the intent binding, which nothing reads or branches on.
No code anywhere read container runtime information.

The temptation is to close the gap by looking: open the Docker socket, read `/proc/self/cgroup`,
treat image labels as provenance. Each of those makes AgentSafe a weaker version of a thing that
already exists and is better at it, and the last one is simply wrong — a label is metadata the
image author wrote, not a signature anybody checked.

The harder problem is that the honest signal available today is weak, and a weak signal presented
without its provenance is indistinguishable from a strong one. A policy matching
`workload.digest == "sha256:..."` against a value read out of an environment variable is matching
a claim, and it has no way to know that.

## Options considered

1. **Verify provenance in AgentSafe.** Read the image, check its signature, resolve an attestation
   chain. This is Docker's, Sigstore's and the platform's job; AgentSafe would be a worse
   implementation of it, on the request path, and the non-goals name it explicitly.

2. **Carry fields with no trust representation.** `workload.digest` and `workload.image`, taken
   from wherever they are available, on the argument that an operator knows what their own
   manifest set. This is the failure mode above: the field is identical whether it came from an
   admission controller that pinned it or from a compromised entrypoint that wrote it, and the
   policy cannot tell.

3. **Carry the fields with a mandatory `provenance` beside them**, naming the source and how far
   it goes, with a ceiling this package cannot exceed.

## Decision

Option 3.

**The shape.** `WorkloadSignal` carries `runtime`, `artifact_type`, `image`, `digest`, `publisher`
— every one optional — and a required `provenance: { source, trust_level }`. There is no way to
express a workload without saying who reported it.

**The ladder.** `unverified` → `supplied` → `observed` → `verified`, weakest first.
`MAX_REPORTED_TRUST` is `supplied`, and `assertReportable` **throws** on anything above it rather
than clamping: a provider reaching for `verified` has decided it checked something, and if it did
not, that is a defect to fix rather than a value to weaken in silence on its way to a policy.

**Nothing emits `verified` today, deliberately.** An environment variable an orchestrator set is
`supplied`, however true it happens to be, because the process cannot distinguish it from one a
compromised entrypoint wrote. `verified` is reserved for a provider that consumes a signal the
platform itself attests, and that provider is a file beside the existing ones.

**The abstraction.** `ProvenanceProvider` is one synchronous, side-effect-free method:
`describe(facts) → WorkloadSignal | null`. A provider that had to reach something to answer would
be a provenance authority, which is what this exists not to be. `DockerProvenanceProvider`,
`KubernetesProvenanceProvider`, `StaticProvenanceProvider` and `NoneProvenanceProvider` ship;
`resolveWorkload` takes the first with something to say and merges nothing, because a workload
assembled from two sources would carry one `provenance` describing neither.

**Absence is an answer.** No provider with anything to say means no `workload` key in the intent at
all — not a placeholder saying there is none. A policy that requires provenance then refuses on the
signal's absence, under Decionis's own required-signal semantics, rather than matching a
placeholder.

**What is read.** Only variables an operator's own manifest declares:
`AGENTSAFE_WORKLOAD_IMAGE`, `_DIGEST`, `_PUBLISHER`. There is no interface that hands a container
its own resolved image digest — not the Docker API without a socket the gateway must not have, and
not the Kubernetes downward API, which exposes pod fields and not the image. So the orchestrator
puts it there, and the chart does, from the digest an operator already pins in `image.digest`. A
malformed value is dropped rather than carried.

**The binding and the refusal.** The workload rides in the hashed `context` under a reserved key,
the seam [ADR 0006](./0006-enforcement-boundary-identity.md) established. `SafeExecutor` takes an
optional `workloadDigest`; when set, an intent proposed by a different artifact — or by none — is
refused with `WORKLOAD_MISMATCH` before the claim.

## Reason

The trust source is not documentation; it is the field that makes the other fields safe to use. A
policy can then be written against what is actually known — "digest in the approved set **and**
`trust_level` at least `supplied`, for this environment" — and an auditor reading the dossier
afterwards can see exactly how strong the claim was when the decision was made.

It also keeps the integration honest in the only way that matters commercially: Docker remains the
authority for what is running, and the day Docker offers an attested channel, it becomes a
provider that can say `verified` without a word of this changing.

## Protocol impact

None. As with the boundary, this is a reserved key in `context`, which the Decionis contract
declares `additionalProperties: true` and which is entirely inside the canonical hash.
`agent-safe.intent/1` is unchanged and every published vector still holds.

No Docker-specific primitive reaches the protocol. `runtime: "docker"` is a value in a generic
`workload` shape, the way `kubernetes` and `systemd` are.

## Compatibility impact

Nothing is required. A deployment that declares no workload carries no `workload` key and behaves
exactly as before. `SafeExecutor` without `workloadDigest` checks nothing. The chart's new values
default to what the release already knew about itself, and `boundary.reportWorkload: false` turns
even that off.

## Security impact

- The trust level cannot be raised by configuration. `assertReportable` throws above the ceiling,
  and `ProvenanceProvider.ts` is on the mutation gate at 100% precisely because a mutant there
  would have this package asserting it verified something it never looked at.
- A declared value is matched whole against an anchored pattern, so a field that is not shaped like
  the thing it claims to be is dropped rather than passed to a policy.
- A caller cannot write the reserved key: `IntentCapture` refuses it, and an agent's proposal
  cannot reach `context`.
- Workload substitution is refused by `WORKLOAD_MISMATCH` before the claim, and underneath that by
  the canonical hash.
- AgentSafe gains no new reach: no socket, no `/proc`, no network call. The providers read the
  environment and nothing else.

## Migration impact

To let policy reason about the workload, pin the digest and declare it: `image.digest` in the
chart, or `AGENTSAFE_WORKLOAD_IMAGE` and `_DIGEST` on `docker run`. Expect `trust_level: supplied`
and write policy that says so. `agentsafe identity` shows what a process reports.
