# The Changed Conditions Test

**An authorization is a decision about the world as it was when it was made.** By the time the
work reaches its commit, the configuration it read may have changed, the group it targets may have
grown, another operation may have taken the capacity it relied on, the approval behind it may have
been withdrawn, and a new policy may be in force. None of that makes the agent dishonest, and none
of it shows in the agent's request, which is exactly the request that was approved. This page is
how to check, on your own machine, that a boundary notices.

The [Compromised Principal Test](./compromised-principal-test.md) holds the world still and lets a
valid principal ask for something nobody authorised. This test is its counterpart: the principal is
honest, its proposal was allowed, and the world changes between the decision and the commit.

```text
honest principal → decision in force → conditions change before the commit → refused at the claim | a legitimate counterpart completes
```

The boundary in this repository re-derives authority at the claim, immediately before the commit,
and the authority, not the executor, does it. A claim compares the policy release the grant was
decided under, and every material signal the decision read, with what is current. A grant decided
under an earlier release fails `POLICY_VERSION_STALE`; a grant whose signal was published again
fails `SIGNAL_VERSION_STALE`; neither is consumed, so the same work can be decided again on the
world as it now is. A claim on a scope another open claim holds fails `AUTHORIZATION_SCOPE_BUSY`,
and one behind an attempt whose outcome is unknown fails `CURRENT_STATE_UNRESOLVED` until that
attempt is reconciled.

A refusal is only half of the test. A boundary that refuses everything after any change has
prevented nothing worth claiming, so each case is paired with a legitimate counterpart that must
still complete: a valid renewal proceeds, a safe retry keeps its identity, and a repaired
dependency allows reauthorized work.

## Run it

Nothing real is called. The authority is the loopback Decionis double; the target is the recording
target behind `agentsafe test`.

**1. The corpus.** The test end to end, as a self-checking proof:

```bash
git clone https://github.com/decionis/agent-safe-pipeline.git && cd agent-safe-pipeline
pnpm install --frozen-lockfile
pnpm --filter @decionis/agent-safe-example-changed-conditions demo
```

A deploy agent's canary rollout meets a configuration changed at the path it read, a canary group
that grew past the ceiling, a second rollout racing for the last unit of the allowance, a change
approval withdrawn while the rollout was queued, and a policy release between its grant and its
claim. A network agent's firewall rule meets the invariant that no administrative port of a
production security group opens to every address, at the decision and again at the commit, when
the group it targeted is reclassified as production while the rule waits. The same corpus replays a
consumed grant, substitutes the proposal content, carries a grant into another organisation, and
has the agent try to raise its own ceiling with the credential it holds. A request lost on the wire
and an acknowledgement lost after the rollout landed both end `INDETERMINATE`, are reconciled from
the deploy API's own record, and are never sent twice. The run exits 0 only if nothing on changed
conditions reached the target and every counterpart reached it exactly once:

```text
PROVEN: 19 changed-condition attempts, 0 stale commits; 13 legitimate counterparts completed, each exactly once.
OPEN: 1 case the boundary does not close today: with the allowance published after the commit instead of with it, 2 rollouts committed against an allowance of 1. That window, and any limit nobody publishes as a signal, need a reservation the authority takes with the grant.
```

[`examples/changed-conditions-demo`](../examples/changed-conditions-demo) has the case table.

**2. The authority's own refusals.** The loopback authority's commit-time revalidation, tested on
its own over real HTTP through the production clients:

```bash
pnpm --filter @decionis/agent-safe-pipeline exec vitest run test/testing/LocalCommitRevalidation.test.ts
```

Each refusal in its hosted order, that none of them consumes the grant, that a commit or a failure
releases a scope and an `INDETERMINATE` holds it until reconciled, that a key bound to one
organisation cannot carry a grant into another, and that no key reaches the policy lifecycle.

## How it is observed

The corpus does not take any component's word for what happened. The recording target is the
deploy and network API, and it records every request that reaches it. Each attempt is judged by
whether anything arrived while it ran; each counterpart by whether exactly one request arrived
under the identity it was proposed with; and at the end, every request the target ever received has
to belong to a counterpart's identity or to the open case. The results are counts: attempts and how
many reached the target, counterparts and how many reached it exactly once, requests no step
accounts for. They are structural, so they are reported as counts and never as a rate.

## The open case

Two rollouts racing for the last unit of an allowance are refused when the allowance is a material
signal published with each commit. The signal is the claim's concurrency scope, held while a claim
is open or its outcome unknown, so the second rollout waits (`AUTHORIZATION_SCOPE_BUSY`); once the
first commits, the next claim reads the new version (`SIGNAL_VERSION_STALE`), and a top-up lets the
second proceed. That is the corpus's third case.

What stays open is narrower. When the system of record publishes the consumed allowance after the
commit rather than with it, a claim inside that window reads the old value, and for it nothing has
changed yet: both rollouts commit. A limit nobody publishes as a signal is not seen at all. Closing
either takes the authority reserving the limit with the grant and settling the reservation at the
commit, which is not built. The corpus asserts today's result for the window and reports it as open,
so the day it changes, the case has to be moved rather than quietly passing.

## What each proves, and what it does not

| Run                       | It proves                                                                                                                                                                                                                                                                                                                    | It does not prove                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The corpus                | With the production gate, verifier and runner over real HTTP, a grant presented after its conditions changed never reaches the target and is never consumed, each legitimate counterpart reaches it exactly once, a lost outcome is reconciled without a second send, and every request the target received is accounted for | Anything about the hosted authority: the corpus runs the loopback double, which mirrors the hosted reason codes and their order but not its storage. It does not re-run the policy at the claim (`POLICY_STATE_CHANGED`), recover an expired claim lease into an unresolved one, or, for a grant that binds no material signal, hold the execution target as its scope as the hosted claim store does |
| The authority's own tests | The double refuses each changed condition in the hosted order with the hosted codes, without consuming the grant, and holds and releases scopes as the hosted claim store does for material signals                                                                                                                          | That a deployment publishes the signals its policy needs. A change nobody publishes is invisible at the claim, here and hosted, because the grant names no state version of the target                                                                                                                                                                                                                |

Neither proves that a refusal prevented an effect on a real target: the observer is a synthetic
target the run starts itself, and a real one can be reached by a route the boundary does not sit on
([bypass resistance](./bypass-resistance.md)). Neither runs against a hosted tenant; the policy
releases and published signals the corpus changes are the authority's own state, which a shadow
tenant does not hand to a test.

## Where the cases come from

The case list follows the benchmark of the governance contract proposed in John M. Willis, "AARM
Needs Governance Through Commit", _The Commit Boundary_, 20 October 2026: substitute the proposal
content, expire an approval while the action is queued, replay, change a dependency, race two
actions against a shared limit, reuse authority across governance domains, and alter the controls,
each paired with a legitimate counterpart and observed at the target. The firewall invariant is his
example of a direct effect that can be specified and refused before commitment. The corpus is this
repository's own implementation of that list against its own contract; passing it is not a claim of
conformance to any other specification.

## Reproduce, cite, correct

- The corpus runs on every pull request (`pnpm examples:prove`). Name the release tag or commit
  when you cite a run; the corpus grows, and the open case moves when it closes.
- Archived releases are citable under the Zenodo concept DOI
  [`10.5281/zenodo.22312955`](https://doi.org/10.5281/zenodo.22312955).
- A run that does not do what this page says is a bug here, not a property of your system:
  [open an issue](https://github.com/decionis/agent-safe-pipeline/issues), or use the
  [security policy](https://github.com/decionis/agent-safe-pipeline/security/policy) if it touches
  security.
