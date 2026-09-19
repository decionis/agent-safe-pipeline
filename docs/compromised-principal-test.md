# The Compromised Principal Test

**A valid identity with valid access is not an authorized execution.** That sentence is the whole
of this page; the rest is how to check it in under a minute, on your own machine, against code
you can read.

Identity systems answer who is asking. They answer it well, and the answer is necessary. What
they cannot answer is whether _this_ action, with _these_ parameters, against _this_ target, right
now, is one anybody authorized, because a credential is issued before the action exists and is
good for every action inside its scope until it expires. That gap was tolerable while a human sat
between the credential and the consequence. An agent removes the human, and it acts faster than
one, so the gap is where the damage now happens: the realistic adversary is not a forged
credential but a valid one, an agent whose identity is real, whose credential is current, and
whose request is not what anyone authorized. As agents get faster and more autonomous, identity
becomes a weaker proxy for authority.

The test states that adversary and holds a boundary to it:

```text
valid principal → valid credential → permitted API → unauthorized consequential intent → BLOCK | ESCALATE
```

Decision intelligence determines what an AI wants to do. Execution authority determines whether
it is permitted to happen. The boundary in this repository binds the second to the exact action,
never to the identity that proposed it, and the test is what that binding is measured by.

## Run it

Three ways, from cheapest to most complete. Nothing real is called by any of them.

**1. The boundary test.** Install the runtime and send the same consequential requests three
ways at a synthetic target: directly, through the gateway in shadow, and through the gateway in
enforcement.

```bash
brew tap decionis/agent-safe https://github.com/decionis/agent-safe-pipeline && brew trust decionis/agent-safe && brew install agentsafe
agentsafe test
```

Read the `direct` column: the target took every request. Then read the `Caller` line under the
table: it is the same caller on every row, and it was never the reason anything was refused. The
only thing that differed between the row that was forwarded and the rows that were held or
refused is the action. [What the test is and is not](./architecture/decisions/0002-boundary-test-on-a-synthetic-target.md).

**2. The infrastructure demo.** The test end to end, as a self-checking proof:

```bash
git clone https://github.com/decionis/agent-safe-pipeline.git && cd agent-safe-pipeline
pnpm install --frozen-lockfile
pnpm --filter @decionis/agent-safe-example-infra-scale demo
```

An infrastructure agent with a valid identity proposes `deployment.scale` for `inference` in
`prod-eu` at 96 replicas and is allowed. The same agent, with nothing forged, then proposes 960
replicas, a service outside its remit, another cluster, the 96 decision with 960 substituted after
authorization, an approval for 256 presented for 512, a consumed grant replayed, and a direct call
to the cluster with the credential it holds. The run exits 0 only if none of the seven executed
and each legitimate path executed exactly once per verified grant; its last line is
`PROVEN: 7 adversarial attempts by a valid principal, 0 unauthorized executions`.
[`examples/infra-scale-demo`](../examples/infra-scale-demo).

**3. The hash vector.** The same test as arithmetic any implementation can check:

```bash
agentsafe verify intent conformance/vectors/compromised-principal.json
```

One `deployment.scale` intent and eight single-field changes a valid principal could make after
authorization: the replica count, the service, the cluster, the resource, the principal, the
expiry, the idempotency key, the environment. Nine distinct hashes, each reproduced from its
bytes. A grant is good for one hash, once; it covers none of the other eight.
[`conformance/vectors/compromised-principal.json`](../conformance/vectors/compromised-principal.json),
under the [Agent-Safe Intent v1](../spec/intent/v1/README.md) specification.

## What each proves, and what it does not

| Run                     | It proves                                                                                                                                                        | It does not prove                                                                                                                                                                                                                                                                                                      |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `agentsafe test`        | The runtime you installed forwards what the authority allowed, once, and holds or refuses the rest, against a target that accepts everything sent to it directly | Anything about Decionis' policy (the authority is a local demo with a synthetic policy), or about your network: whether an agent can reach the target around the gateway is [`agentsafe test name=host:port`](./reference/cli.md#agentsafe-test-namehostport) and the [bypass-resistance](./bypass-resistance.md) page |
| The infrastructure demo | Authority bound to the exact action defeats every listed mutation by a valid principal, including a change made after authorization and a replayed grant         | Anything about the hosted authority or a real Presence ceremony: the demo runs a fixture authority and an in-process approval double that keep the semantics that matter                                                                                                                                               |
| The hash vector         | The binding covers every field a principal could change, and two implementations that agree on the vectors agree on the hash                                     | Anything about enforcement: a hash is what authority is bound to, not the act of binding                                                                                                                                                                                                                               |

None of them proves that the host running the executor is uncompromised; the
[threat model](../THREAT-MODEL.md#accepted-risks) says what is assumed and what is accepted.

## Why the binding, and not a better identity check

Scoped credentials are evaluated when they are issued. From then until they expire, the resource
checks the token, and the token says "may call `deployment.scale`". It cannot say "may scale
`inference` in `prod-eu` to 96, this once, before 12:05, under idempotency key `a`", because none
of that existed when the token was minted. A better identity check makes the first statement more
certain; it cannot make it into the second.

The binding is the second statement. The eight fields the vector mutates are the eight things a
valid principal can change, and each is inside the hash, so a change to any of them is another
intent the authority never decided over. The grant that comes back is good for that hash, once,
and the executor compares the bytes it is about to send with the bytes the intent bound before it
sends them. Scopes stay necessary: they say which actions may even be proposed. They stop being
sufficient the moment the proposer is not a person.

## Reproduce, cite, correct

- The test is run on every pull request (`pnpm examples:prove`) and in the release smoke test of
  every packaged binary (`agentsafe test`). Name the release tag or commit when you cite a run;
  the corpus grows.
- Archived releases are citable under the Zenodo concept DOI
  [`10.5281/zenodo.22312955`](https://doi.org/10.5281/zenodo.22312955); the architecture is
  Jejelowo, Festus, "The Execution Verifiability Gap", Decionis Research, 2026,
  <https://decionis.com/research/execution-verifiability-gap>.
- A run that does not do what this page says is a bug here, not a property of your system:
  [open an issue](https://github.com/decionis/agent-safe-pipeline/issues) with
  `agentsafe test --json`, or use the
  [security policy](https://github.com/decionis/agent-safe-pipeline/security/policy) if it
  touches security. A claim on this page that you can show to be wrong is corrected the same way.

This page names no vendor and compares no product. It describes a failure mode and a test for it;
whether a given system passes is for that system's own artifacts to show.
