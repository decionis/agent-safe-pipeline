# Bypass resistance: what stops an agent going around the executor

The architecture is worth nothing if an agent can reach the system of record directly. This
document says where that is actually stopped, in what order of strength, and which layer this
repository can and cannot hold.

The short version: **the network is the weakest of the three available chokepoints and the only
one no process can verify.** Reaching for it first is what makes the boundary look like a
configuration promise.

## Three chokepoints

| Where a bypass is stopped                                                   | What bypassing then costs                                                      | State in this repository                                                                                                     |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| **The system of record refuses** an instruction the authority never claimed | Forging the authority's signature, or the executor's, or compromising the host | `SIGNED_REQUEST` covers the grant, the decision and the authority's claim attestation; the provider verifies both signatures |
| **The credential the agent never holds**                                    | Taking it out of the executor's memory                                         | Enforced in the process; the kind decides how much it is worth                                                               |
| **The network**                                                             | One hop, where the CNI does not enforce                                        | Declared in `deploy/`, enforced by the cluster, probed from the zone                                                         |

### The provider is the only party that can refuse

A network control stops an agent _reaching_ the provider. A provider-side control stops it
_effecting_ anything. Only the second is a property of the system of record, and only the second
survives a path nobody thought to close.

`SIGNED_REQUEST` is the mechanism: an RFC 9421 signature, made with an Ed25519 key that lives
only in the executor's secret store and is resolved inside the dispatch, over `@method`, `@path`,
`content-digest`, `idempotency-key`, `x-agent-safe-intent-hash`, and on a dispatch
`x-agent-safe-grant-id`, `x-agent-safe-decision-id` and `x-agent-safe-claim-attestation`. A
caller with a perfect route and a copied set of headers cannot produce it.

The attestation is what makes this the provider's check rather than the executor's word. On a
live claim the authority returns a compact EdDSA JWS, signed with its execution-grant key, whose
subject is the grant and whose payload names the decision, the dossier, the intent hash, the
digest of the canonical parameters and the profile it used, a digest of the claim token, and an
expiry equal to the claim lease. The executor forwards it and signs over it. The provider
verifies the executor's signature with the executor's key, then the attestation with the
authority's published JWKS, then checks that the request in hand is the one the attestation
describes: grant, decision, intent hash, and the digest of the body it received. Two signatures
from two parties over one request, and a body digest the authority committed to before the
executor ever saw the provider.

What a compromised executor can still do: sign a request the authority never claimed, which the
provider refuses for lacking a valid attestation; or replay a claimed one inside the lease, which
the provider refuses by keeping the grant id for the length of the lease. What it cannot do is
make the authority attest to something it did not claim, because the attestation key is not in
the executor. The [Verifying Provider Profile](./authority/verifying-provider.md) is the full
verification procedure stated normatively, with vectors any implementation runs to claim it;
`packages/agentsafe/README.md` carries the executor's side of it, and the offline proof's strict
provider double runs it against nothing but the authority's public keys. A provider at the
profile's VP-3 also answers with its own signed receipt of the effect, which the executor forwards
and the authority records: the first row of the table then holds in both directions, the provider
refusing what was never claimed and saying under its own key what it did with what was.

### The credential is the strongest thing under this repository's control

A handler never holds a credential value; headers are resolved at the moment of dispatch from the
secret store (BEAP §21, and a gate keeps it that way). The agent zone is given no provider
credential at all. So bypass by credential theft means reading the executor's memory, which is
host compromise rather than a network hop.

But the credential **kind** decides how much that is worth. A bearer is usable by whoever holds
it, which quietly puts the network back in charge; a per-request signature is not. The ranking is
in the package README's "Downstream credentials". For a system of record, prefer
`SIGNED_REQUEST`.

### The network is declared, not enforced, and now measured

`deploy/kubernetes/AgentZone.yaml` gives labelled callers egress to kube-dns and the executor's
listener only, with no `ipBlock` anywhere, so on an enforcing CNI there is no route to a provider.
`pnpm test:automation` holds that manifest to its shape. What no manifest can do is verify that
the cluster reads it: a cluster with no NetworkPolicy-enforcing CNI accepts every policy in the
kit and ignores it.

The network is also where a workload's actions can be _captured_ without its cooperation:
[transparent interception](./gateway/transparent-interception.md) redirects a pod's or a
container's outbound 80 and 443 into an AgentSafe process beside it and reports, by name and
count, every destination the workload reached. That is a different job from enforcement, and the
distinction is the point of this page: the network is where requests are seen and, in the govern
phase, held; the credential and the provider are what make refusing them stick, because they hold
whatever path the request took.

The containment probe (`agentsafe probe-containment`, shipped as a CronJob in
`deploy/kubernetes/ContainmentProbe.yaml`, and run by `agentsafe test name=host:port` from a
developer's machine) makes that failure visible from inside the agent zone.
Each finding is one JSON line in its own envelope, `agent-safe.containment/1`, carrying a target
name, a host and a port, a verdict and a code -- never a path, a parameter or a body. It is
deliberately not part of the executor's evidence plane: the probe is a different process in a
different zone, so its lines are not in the executor's hash chain and must not be read as though
they were.

Read its verdicts asymmetrically:

- `REACHABLE` is **proof of a hole**. Something off the zone answered. A refusal counts here too:
  an RST means a packet reached a host willing to reply, and an enforced policy drops instead.
- `CONTAINED` is **not proof of containment**. A drop is indistinguishable from a provider that is
  down, a route briefly black-holed, or an address that stopped being the provider's.
- `INCONCLUSIVE` is a name that did not resolve, which is both what a policy does and what an
  outage does.

Two limits are structural rather than incidental. The probe never authenticates, because holding
the downstream credential in the agent zone to find out whether it works would create the hole it
is looking for; it can only say a path exists, never that the path is usable. And it runs in the
agent zone, so a compromised caller can report whatever it likes: nothing in the executor reads a
finding, and the probe is given no standing that any other caller lacks. It is an operator's
instrument, not a control.

Where real network enforcement is wanted, it comes from outside the cluster's honour system: a
provider that allowlists a source identity only the executor has, an egress gateway requiring the
executor's client certificate, or a private link whose route exists only in the executor's
namespace. Each of those is the credential chokepoint wearing a network hat, which is the reason
they work.

## Why network enforcement would not settle the question anyway

Even a perfectly enforced policy answers one path of several. An agent or a workflow can also
reach a system of record through:

- another API of the same provider that nobody put behind the executor;
- a tool, plugin or MCP server carrying its own credential;
- a batch or file channel into the core;
- the provider's own web console, with a person's session;
- a person it persuades to run something.

Network policy addresses the first only by accident and the rest not at all. The one control that
generalizes across every path is the system of record declining to effect an instruction that
does not carry proof of a claim. That is why the first row of the table is the first row, and why
it is the one worth insisting on: a provider that requires the attestation is a provider no
agent, workflow, plugin or person can instruct without the authority having claimed it first.

## What to check, in order

1. Set `DOWNSTREAM_CREDENTIAL_KIND=SIGNED_REQUEST` for anything touching a system of record, and
   have the provider require the signature to cover the grant, the decision and the attestation,
   and verify the attestation against the authority's JWKS. Without the provider's half the
   executor's half is decoration.
2. Confirm no provider credential exists anywhere in the agent zone.
3. Apply the kit in `kustomization.yaml` order and confirm the CNI enforces NetworkPolicy, once,
   from a caller pod: see "Proving the boundary before you trust it" in `deploy/Runbook.md`.
4. Schedule the containment probe and alert on a failed job. A green run is not assurance; a
   failed one is a finding.
5. Keep `EXECUTOR_POSTURE` enforced in production, so the executor refuses to run in a shape where
   its own guarantees do not hold.

See also [THREAT-MODEL.md](../THREAT-MODEL.md) "Agent calls the provider directly" and its
accepted risks, and [EVALUATION-PATH.md](../EVALUATION-PATH.md) "Who owns which control".
