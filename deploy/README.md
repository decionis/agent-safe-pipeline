# Deployment kit

What an adopter runs to put the execution boundary in front of one workflow, and how it gets from
a shadow deployment to an enforced one. One image, one manifest, one runbook.

| Piece                                                                  | What it is                                                                                       |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| [`packages/agentsafe`](../packages/agentsafe)                          | The executor as a process, `@decionis/agentsafe`: the wire contract, the configuration, the seam |
| [`examples/trusted-executor`](../examples/trusted-executor)            | The proof over real HTTP against the loopback doubles, and the template an adopter starts from   |
| [`packages/agentsafe/Dockerfile`](../packages/agentsafe/Dockerfile)    | The image, built from the repository root                                                        |
| [`kubernetes/TrustedExecutor.yaml`](./kubernetes/TrustedExecutor.yaml) | ConfigMap, Deployment, Service and NetworkPolicy; Secrets referenced, never written              |
| [`Runbook.md`](./Runbook.md)                                           | Shadow, controlled enforcement, enforcement: what to compare and what changes between them       |

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
docker build -f packages/agentsafe/Dockerfile -t agentsafe .
```

Or take the one the release workflow publishes. From the first release after this kit merged, every
release pushes `ghcr.io/decionis/agentsafe:<version>` (and `latest` for a stable release) to the
organisation's GitHub container registry, attests the image digest with the same keyless workflow
identity that signs the release tag, verifies that attestation before the release is created, and
records the reference and digest in the release assets. A dry run builds the image and never pushes.
Verify before you run it:

```bash
gh attestation verify oci://ghcr.io/decionis/agentsafe:<version> \
  --repo decionis/agent-safe-pipeline
```

Then mirror it into your own registry and put that reference in the manifest. `IMAGE_PLACEHOLDER` is
deliberately not the public name: a cluster pulls what it has verified and mirrored.

The published image runs the reference forwarding handler. An adopter with their own handlers
builds their own image on the package: a process of a few lines that calls `serve(handlers)`, as
[`examples/trusted-executor/src/Serve.ts`](../examples/trusted-executor/src/Serve.ts) does.

## Who supplies what

| Piece                                                         | Who                                                                                                                                       |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| The executor, its image, the manifest, the proof              | This repository                                                                                                                           |
| The authority behind `DecionisGate`                           | The Decionis service, or your implementation of the two interfaces                                                                        |
| Policy                                                        | You, in the authority                                                                                                                     |
| The handlers, the parameter schemas, the downstream addresses | You, in your handler registration (the example's `src/Handlers.ts`) and the ConfigMap                                                     |
| The escalation shape: who approves, through which ceremony    | You, in the ConfigMap (`DIRECT` or `MANAGED`; `NONE` returns the hold)                                                                    |
| The caller token, the API key, the downstream credential      | You, as Secrets the manifest references                                                                                                   |
| The listener's certificate and key; the client CA, if any     | You, as a TLS Secret the manifest references, and a ConfigMap for the CA your callers' certificates chain to                              |
| Who may call: the principals file                             | You, as the ConfigMap the manifest mounts; digests and identities only, one principal per workload, roles and scopes named                |
| The JWKS workload tokens are verified against                 | You, as a ConfigMap populated from the cluster's `/openid/v1/jwks`, or the address the executor refreshes it from                         |
| CA bundles or SPKI pins for the authority and the downstream  | You, in the ConfigMap, when the platform's trust store is not the anchor you want; the executor reaches nothing else                      |
| Executor isolation, agent egress denial, credential scoping   | Your cluster, starting from the NetworkPolicy in the manifest; the executor verifies the posture it can see and refuses to run without it |

The seam between the library and the authority is written down in [OPEN-CORE.md](../OPEN-CORE.md).
This kit deploys the library's side of it.

## Where secrets come from

The executor reads every secret from a file under `EXECUTOR_SECRETS_DIR`, verifies that the file
is private to it (owned by its user, or owned by root and readable by the pod's `fsGroup` and
nobody else, which is what the manifest's `defaultMode` and `fsGroup` produce), and follows the
file when it changes without a restart. Where the value comes from is a choice the manifest does
not make for you:

- A Kubernetes Secret, created out of band and referenced by name, as the manifest shows.
- The Secrets Store CSI driver with a cloud KMS or Vault provider, mounting each secret as a file
  at the same paths; rotation on the provider's side becomes a changed file here.
- External Secrets, syncing a provider into the Secret the manifest references.

None of these is integrated in the executor and no vendor client ships with it. An HSM-resident
key that must never leave its device needs a signing sidecar, which this kit does not provide. The
listener's private key is a secret like the others: mounted under `EXECUTOR_SECRETS_DIR`, checked
for its mode and owner, and followed when it rotates, at which point the listener replaces its TLS
context without a restart.

## What the posture check makes visible

The image runs as the distroless `nonroot` user under Node's permission model, and the process
refuses to start unless the host holds the posture the manifest declares: a non-root user, a
read-only root filesystem, no service-account token, no proxy or trust-anchor or inspector
injection, secret files it alone can read, and no ability to read or write outside the application,
the mounts and the journal directory, or to spawn a process. Remove one of those from the manifest and the pod does not start; the
refusal names the check. The [package README](../packages/agentsafe/README.md) lists every check.

What the process adds to that on its own: it admits only the principals the file names, each by
its own credential and for its own role; it seals the global `fetch` at start and opens
connections only to the origins the ConfigMap names, over TLS verified against the anchors and
pins the ConfigMap declares; it listens over TLS 1.3 with the certificate the TLS Secret holds;
and it chains every evidence line, persisting the chain heads under the journal volume so a
restart continues the sequence. The NetworkPolicy still decides what the pod can reach at all;
the process's policy is the second layer, not a replacement for the first.

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
  the one you replace.
- Say how well anything performs. There is no figure here to quote.
- Stand in for the controls the host owns. The NetworkPolicy is a starting point; the accepted
  risks in [THREAT-MODEL.md](../THREAT-MODEL.md) name the rest.
