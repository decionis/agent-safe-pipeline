# Deployment kit

What an adopter runs to put the execution boundary in front of one workflow, and how it gets from
a shadow deployment to an enforced one. One image, one manifest, one runbook.

| Piece                                                                             | What it is                                                                                   |
| --------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| [`examples/trusted-executor`](../examples/trusted-executor)                       | The executor as a process: the wire contract, the configuration, the handler seam, the proof |
| [`examples/trusted-executor/Dockerfile`](../examples/trusted-executor/Dockerfile) | The image, built from the repository root                                                    |
| [`kubernetes/TrustedExecutor.yaml`](./kubernetes/TrustedExecutor.yaml)            | ConfigMap, Deployment, Service and NetworkPolicy; Secrets referenced, never written          |
| [`Runbook.md`](./Runbook.md)                                                      | Shadow, controlled enforcement, enforcement: what to compare and what changes between them   |

## What is deployed

One container. It is the component between the agent and the downstream: the workflow that hosts
the agent posts a proposal to it, it asks the authority for a verdict, and in enforcement it claims
a single-use grant and executes once through the handler registered at startup, then records what
came back. The proposer never receives a grant or a credential. In shadow it evaluates and records
and never executes.

The image holds no configuration. Every address, name, token and key is supplied at run time, and
the process refuses to start with one missing, naming the variable and never its value.

## Getting the image

Build it from the repository root:

```bash
docker build -f examples/trusted-executor/Dockerfile -t trusted-executor .
```

Or take the one the release workflow publishes. From the first release after this kit merged, every
release pushes `ghcr.io/decionis/agent-safe-trusted-executor:<version>` (and `latest` for a stable
release) to the organisation's GitHub container registry, attests the image digest with the same
keyless workflow identity that signs the release tag, verifies that attestation before the release is
created, and records the reference and digest in the release assets. A dry run builds the image and
never pushes. Verify before you run it:

```bash
gh attestation verify oci://ghcr.io/decionis/agent-safe-trusted-executor:<version> \
  --repo decionis/agent-safe-pipeline
```

Then mirror it into your own registry and put that reference in the manifest. `IMAGE_PLACEHOLDER` is
deliberately not the public name: a cluster pulls what it has verified and mirrored.

## Who supplies what

| Piece                                                         | Who                                                                    |
| ------------------------------------------------------------- | ---------------------------------------------------------------------- |
| The executor, its image, the manifest, the proof              | This repository                                                        |
| The authority behind `DecionisGate`                           | The Decionis service, or your implementation of the two interfaces     |
| Policy                                                        | You, in the authority                                                  |
| The handlers, the parameter schemas, the downstream addresses | You, in `src/Handlers.ts` and the ConfigMap                            |
| The escalation shape: who approves, through which ceremony    | You, in the ConfigMap (`DIRECT` or `MANAGED`; `NONE` returns the hold) |
| The caller token, the API key, the downstream credential      | You, as Secrets the manifest references                                |
| Executor isolation, agent egress denial, credential scoping   | Your cluster, starting from the NetworkPolicy in the manifest          |

The seam between the library and the authority is written down in [OPEN-CORE.md](../OPEN-CORE.md).
This kit deploys the library's side of it.

## Three modes, taken in order

1. **Shadow.** The executor runs beside the path the workflow runs today. Every proposal is evaluated
   and recorded; nothing changes in what executes. You compare what the authority would have decided
   with what happened.
2. **Controlled enforcement.** One action, one workflow, one team. The workflow is changed to require
   the executor's answer before it acts, for that action only, and to act only through the executor.
3. **Enforcement.** The action is not reachable except through the executor.

[`Runbook.md`](./Runbook.md) says what to compare in shadow, how to write stopping criteria in your
own words, and what changes between the steps.

## What the kit does not do

- Carry a value that belongs to a deployment. Every host in these files is `.example`, every
  credential is a placeholder the manifest references, every identity is synthetic.
- Assert anything about a provider. The shipped handler forwards to one configured endpoint and is
  the file you replace.
- Say how well anything performs. There is no figure here to quote.
- Stand in for the controls the host owns. The NetworkPolicy is a starting point; the accepted
  risks in [THREAT-MODEL.md](../THREAT-MODEL.md) name the rest.
