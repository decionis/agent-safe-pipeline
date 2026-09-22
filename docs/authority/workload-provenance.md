# Workload provenance

A policy should be able to say: _only this approved release, running in production, may move this
much money._ That needs an answer to a question about software rather than about identity — what
is proposing this action?

AgentSafe carries that answer. It does not establish it.

> Docker establishes what is running. AgentSafe captures what it intends to do. Decionis
> establishes what that workload is authorized to cause.

## AgentSafe is not the provenance authority

Image digests, provenance attestations, SBOMs, publisher verification, vulnerability status and
container identity belong to Docker, OCI tooling and the platform. This package does not scan an
image, generate an SBOM, verify a publisher or check a signature, and it must never appear to have
done so. It opens no Docker socket, reads no `/proc`, calls no undocumented API, and never treats
an image label as provenance — a label is metadata the image author wrote, not a signature anybody
checked.

What it does is carry what those systems say, with the source attached, so a decision can depend
on it and evidence can record it.

## The trust source is the load-bearing field

A digest read from an environment variable and a digest checked against a signature look
identical. A policy matching on one without knowing which it has is matching a claim.

So a workload cannot be expressed without saying who reported it:

```json
"workload": {
  "runtime": "docker",
  "artifact_type": "oci",
  "image": "ghcr.io/example/payments-agent:1.4.2",
  "digest": "sha256:...",
  "provenance": { "source": "docker", "trust_level": "supplied" }
}
```

The ladder, weakest first:

| Level        | Means                                                                  |
| ------------ | ---------------------------------------------------------------------- |
| `unverified` | nothing trustworthy was available; recorded, never hidden              |
| `supplied`   | something told us, and nothing checked it                              |
| `observed`   | the runtime reported it through an interface the workload cannot write |
| `verified`   | a signature or attestation was checked                                 |

**AgentSafe emits nothing above `supplied` today, and that is the point.** An environment variable
an orchestrator set is `supplied` however true it happens to be, because the process cannot
distinguish it from one a compromised entrypoint wrote. `verified` is reserved for a provider that
consumes a signal the platform itself attests.

The ceiling is enforced, not advisory: `assertReportable` **throws** above it rather than quietly
downgrading. A provider reaching for `verified` has decided it checked something, and if it did
not, that is a defect to fix rather than a value to weaken in silence on its way to a policy.

## Absence is an answer

A workload nobody described produces **no `workload` key at all** — not a placeholder saying there
is none.

That distinction matters. A policy that requires trusted provenance refuses on the signal's
absence, under Decionis's own required-signal semantics. A placeholder would be something to
match.

## The providers

One contract, one method, synchronous and side-effect free. A provider that had to reach something
to answer would be a provenance authority.

```ts
interface ProvenanceProvider {
  readonly id: string;
  describe(facts: ProvenanceFacts): WorkloadSignal | null;
}
```

| Provider                       | Reads                                               |
| ------------------------------ | --------------------------------------------------- |
| `DockerProvenanceProvider`     | the declared variables, reporting `runtime: docker` |
| `KubernetesProvenanceProvider` | the same, reporting `runtime: kubernetes`           |
| `StaticProvenanceProvider`     | a workload an operator states in code               |
| `NoneProvenanceProvider`       | nothing, on purpose                                 |

`resolveWorkload` takes the first provider with something to say and **merges nothing**: a
workload assembled from two sources would carry one `provenance` describing neither, and the trust
level would belong to the wrong fields.

## What is declared, and by whom

| Variable                       | Meaning                   |
| ------------------------------ | ------------------------- |
| `AGENTSAFE_WORKLOAD_IMAGE`     | the image reference       |
| `AGENTSAFE_WORKLOAD_DIGEST`    | `sha256:…`, matched whole |
| `AGENTSAFE_WORKLOAD_PUBLISHER` | who published it          |

There is no interface that hands a container its own resolved image digest — not the Docker API
without a socket the gateway must not have, and not the Kubernetes downward API, which exposes pod
fields and not the image. So the orchestrator puts it there. The Helm chart does it from the
digest an operator already pins in `image.digest`, and `boundary.reportWorkload: false` turns it
off.

A value that is not shaped like the thing it claims to be is dropped rather than carried: a digest
that is not a digest would be a field a policy could match on by accident.

## Binding, and workload substitution

The workload rides inside the canonical hash, as a reserved key in the intent's `context` — the
same seam [the enforcement boundary](./enforcement-boundary.md) uses, and for the same contract
reason. So the authority is issued against bytes that name the workload.

`SafeExecutor` takes an optional `workloadDigest`, which the gateway sets from what it resolved.
An intent proposed by a different artifact, or by none, is refused with `WORKLOAD_MISMATCH` before
the claim:

```text
authority granted to   sha256:aaa…   (the approved release)
presented by           sha256:bbb…
                       →  WORKLOAD_MISMATCH, nothing dispatched
```

Authority granted to one signed artifact is not authority for the next one to reuse.

## What a policy can say

Decionis reads these as `context.workload.*`. Whether it does is the control plane's decision, not
this package's. Conceptually:

```text
ALLOW only if
    workload.digest in approved_release_digests
    AND workload.provenance.trust_level >= supplied
    AND runtime.environment == "production"
    AND action.amount <= payment_limit
```

This is an example, not a policy AgentSafe ships or hard-codes. The point is the second line: a
policy written against provenance should say how strong a claim it will accept, and it can, because
the claim's strength travels with it.

## Extension points

The abstraction exists so that better signals slot in without the protocol changing. If Docker
offers an attested channel this process can check — a verified publisher, a provenance
attestation, a Scout status — it becomes a provider that can honestly return `verified`, and
nothing on this page changes but the ceiling.

Until then, AgentSafe says `supplied`, and says so out loud.

## See also

- [ADR 0007](../architecture/decisions/0007-workload-provenance-signals.md) — the decision and the two options not taken
- [The enforcement boundary](./enforcement-boundary.md) — the other signal on the same seam
- [Docker](../install/docker.md) — running the gateway in a container
- [Threat model](../../THREAT-MODEL.md) — workload substitution, and forged provenance
