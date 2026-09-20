# Deployment kit

What an adopter runs to put the execution boundary in front of one workflow, and how it gets from
a shadow deployment to an enforced one. One image, one manifest, one runbook.

| Piece                                                               | What it is                                                                                       |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| [`packages/agentsafe`](../packages/agentsafe)                       | The executor as a process, `@decionis/agentsafe`: the wire contract, the configuration, the seam |
| [`examples/trusted-executor`](../examples/trusted-executor)         | The proof over real HTTP against the loopback doubles, and the template an adopter starts from   |
| [`packages/agentsafe/Dockerfile`](../packages/agentsafe/Dockerfile) | The image, built from the repository root                                                        |
| [`kubernetes/`](./kubernetes)                                       | Two namespaces, a default deny in both, the executor, its egress, the agent zone, operator RBAC  |
| [`Runbook.md`](./Runbook.md)                                        | Shadow, controlled enforcement, enforcement: what to compare and what changes between them       |

## What the kit is for

The clearest case for the kit is an agent that changes infrastructure. An infrastructure agent
with a valid identity and a valid credential to the cluster's API can scale, roll and delete, and
the API checks only that the identity may call it, not that this call is the one anyone
authorised. The kit puts the executor between the two: the proposing workflow runs in the agent
zone with no service-account token and no route anywhere but the executor's listener; the executor
runs in its own namespace with the one credential the API accepts for the operations it handles,
projected as a file and resolved at dispatch; and each proposal meets the authority as an exact
intent, principal, cluster, service, parameters and expiry in one hash, to be effected once on a
claimed grant or refused. [`examples/infra-scale-demo`](../examples/infra-scale-demo) runs that
case offline as the Compromised Principal Test, seven attempts by a valid principal and none
executed; the kit is where the same boundary runs in a cluster.

## Two zones

The kit puts the proposing workflows and the executor in separate namespaces, and the separation
is the point: the policies that keep an agent away from the provider are namespace-scoped, so a
single namespace would turn "the agent cannot reach the provider" into a claim about labels rather
than a claim about the network.

| File                                                            | What it establishes                                                                                  |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| [`Namespaces.yaml`](./kubernetes/Namespaces.yaml)               | `agent-safe-agents` and `agent-safe-executor`, both enforcing Pod Security's `restricted` profile    |
| [`DefaultDeny.yaml`](./kubernetes/DefaultDeny.yaml)             | No ingress and no egress for any pod in either namespace, applied before any pod exists              |
| [`TrustedExecutor.yaml`](./kubernetes/TrustedExecutor.yaml)     | The configuration, the principals, the JWKS, the StatefulSet, its claim, its Service and its budget  |
| [`ExecutorEgress.yaml`](./kubernetes/ExecutorEgress.yaml)       | The one way in (a labelled caller on 8443) and the three ways out (DNS, the authority, the provider) |
| [`AgentZone.yaml`](./kubernetes/AgentZone.yaml)                 | A caller's only path is the executor's listener, and it names no CIDR at all                         |
| [`OperatorRbac.yaml`](./kubernetes/OperatorRbac.yaml)           | What on-call may do to the deployment: read it, and create or delete the halt flag                   |
| [`cilium/FqdnEgress.yaml`](./kubernetes/cilium/FqdnEgress.yaml) | The same egress by DNS name instead of by range, where Cilium is the CNI                             |

Apply them in the order [`kustomization.yaml`](./kubernetes/kustomization.yaml) lists, which is
what `kubectl apply -k deploy/kubernetes` does:

```bash
kubectl apply -k deploy/kubernetes
```

The order is a control rather than a convenience. The namespaces carry their Pod Security labels
before anything can be admitted into them, and both zones are default-deny before any pod exists
to have a network. Applied the other way round there is a window in which a pod runs with no
policy at all.

The Cilium file is deliberately not in that list. It replaces the two `ipBlock` rules with DNS
names, and applying both would widen the policy rather than narrow it: two policies allowing
different things is a union. On a Cilium cluster, apply it and delete those two rules.

## What the agent zone cannot do

With the default deny beneath it and no `ipBlock` above it, a pod in `agent-safe-agents` has no
route off the cluster: not to the provider, not to the authority, not to the internet. Its only
path is the executor's listener on 8443, and it is admitted there only if it carries the
`agent-safe-caller: "true"` label and presents a projected service-account token whose audience is
the executor's. No shared secret exists between the two zones; the cluster signs the token and the
executor verifies it against the JWKS the platform team populates.

This is what narrows the threat model's first residual risk. It does not remove it: the
NetworkPolicies here are declarations, and a cluster whose CNI does not enforce them ignores every
one of them silently. That is the one control in this kit a process cannot verify about itself.

## Conformance

The manifests are held to their own shape by
[`test/automation/DeployManifests.test.mjs`](../test/automation/DeployManifests.test.mjs), which
runs in `pnpm verify`. It parses every YAML file under `deploy/` and asserts, among other things:
every hardening key on the pod and the container; a default deny per namespace; explicit
`policyTypes` on every other policy; no `0.0.0.0/0` or `::/0` anywhere; a port on every rule; no
`ipBlock` in the agent zone; no egress from the executor back into the agents' namespace; one port
agreed across the configuration, the container, the Service and the probes; a resolvable service
account for every pod that names one; every `*_FILE` value inside a mounted directory; no
development-only flag; no `kind: Secret`; and `.example` hosts only.

`packages/agentsafe/test/deploy/ManifestConfigKeys.test.ts` goes the other way, from the manifest
to the code: every variable the ConfigMap names has to be one the loader knows, every secret has
to be given as a file, and the whole ConfigMap has to be a configuration the loader actually
accepts — both as shipped, in shadow, and after the runbook's last step turns it into an enforcing
deployment with a managed ceremony. Writing that test found two ways the earlier single-file
manifest could not have started at all, which is the case for having it.

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
records the reference and digest in the release assets. After the release, the same manifest is
copied by digest to `docker.io/decionis/agentsafe:<version>` and attested under that name too; the
digest is the same on both registries. A dry run builds the image and never pushes. Verify before
you run it:

```bash
gh attestation verify oci://ghcr.io/decionis/agentsafe:<version> \
  --repo decionis/agent-safe-pipeline
```

Then mirror it into your own registry and put that reference in the manifest. `IMAGE_PLACEHOLDER` is
deliberately not the public name: a cluster pulls what it has verified and mirrored.

The published image runs the reference forwarding handler. An adopter with their own handlers
builds their own image on the package: a process of a few lines that calls `serve(handlers)`, as
[`examples/trusted-executor/src/Serve.ts`](../examples/trusted-executor/src/Serve.ts) does.

The image's entrypoint is the `agentsafe` command and its default argument is the gateway
(`proxy`); this kit's StatefulSet names `serve` explicitly, and so must any deployment of the
executor from the image. The gateway, the HTTP-interception ingress over the same lifecycle, has
its own chart in [`charts/agentsafe`](../charts/agentsafe) and its own
[install page](../docs/install/kubernetes.md); it is the smaller deployment, one Deployment in
front of one Service, and it does not replace this kit where a bank boundary with principals,
downstream credentials and a verified host posture is what is wanted.

## Who supplies what

| Piece                                                                  | Who                                                                                                                                                                    |
| ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The executor, its image, the manifest, the proof                       | This repository                                                                                                                                                        |
| The authority behind `DecionisGate`                                    | The Decionis service, or your implementation of the two interfaces                                                                                                     |
| Policy                                                                 | You, in the authority                                                                                                                                                  |
| The handlers, the parameter schemas, the downstream addresses          | You, in your handler registration (the example's `src/Handlers.ts`) and the ConfigMap                                                                                  |
| The escalation shape: who approves, through which ceremony             | You, in the ConfigMap (`DIRECT` or `MANAGED`; `NONE` returns the hold)                                                                                                 |
| The caller token, the API key, the downstream credential               | You, as Secrets the manifest references                                                                                                                                |
| The listener's certificate and key; the client CA, if any              | You, as a TLS Secret the manifest references, and a ConfigMap for the CA your callers' certificates chain to                                                           |
| Who may call: the principals file                                      | You, as the ConfigMap the manifest mounts; digests and identities only, one principal per workload, roles and scopes named                                             |
| The JWKS workload tokens are verified against                          | You, as a ConfigMap populated from the cluster's `/openid/v1/jwks`, or the address the executor refreshes it from                                                      |
| A volume per replica for the journal                                   | Your cluster, as the claim the StatefulSet requests; the attempt journal lives there and an attempt has to outlive the container that made it                          |
| The halt flag, when you want one                                       | You, as a ConfigMap created and deleted by the on-call operator; its presence halts every replica                                                                      |
| CA bundles or SPKI pins for the authority and the downstream           | You, in the ConfigMap, when the platform's trust store is not the anchor you want; the executor reaches nothing else                                                   |
| Executor isolation, agent egress denial, credential scoping            | Your cluster, starting from the policies in `kubernetes/`; the executor verifies the posture it can see and refuses to run without it                                  |
| The two CIDR ranges, or the Cilium policy that replaces them           | You: `AUTHORITY_CIDR_PLACEHOLDER` and `DOWNSTREAM_CIDR_PLACEHOLDER` are facts about your network, and a range wide enough to keep working is wide enough to reach more |
| The group on-call belongs to                                           | You, in `OPERATOR_GROUP_PLACEHOLDER`; binding a real group is a statement about who may stop payments and belongs in your own change review                            |
| A NetworkPolicy-enforcing CNI, and a sandboxed runtime if you want one | Your cluster; `runtimeClassName` is commented in the StatefulSet for gVisor or Kata                                                                                    |

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

What the process adds to that on its own: it writes every attempt to its journal before the
provider is touched and reconciles what it finds there at start, read-only; it stops taking work
on an operator's word, on a halt file, or on a spike it was told to watch for; it refuses above
the ceilings the ConfigMap names, before the authority is asked; it admits only the principals the
file names, each by its own credential and for its own role; it seals the global `fetch` at start
and opens connections only to the origins the ConfigMap names, over TLS verified against the anchors and
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
