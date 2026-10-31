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
that grew past the ceiling, a second rollout racing for the last unit of the allowance (and the same
race when the allowance is published after the commit instead of with it), a change
approval withdrawn while the rollout was queued, a partner bank's signed mandate that lapses or
whose key the organisation revokes while a rollout under it is queued, and a policy release between
its grant and its claim. A network agent's firewall rule meets the invariant that no administrative port of a
production security group opens to every address, at the decision and again at the commit, when
the group it targeted is reclassified as production while the rule waits. The same corpus replays a
consumed grant, substitutes the proposal content, carries a grant into another organisation, and
has the agent try to raise its own ceiling with the credential it holds. A request lost on the wire
and an acknowledgement lost after the rollout landed both end `INDETERMINATE`, are reconciled from
the deploy API's own record, and are never sent twice. The run exits 0 only if nothing on changed
conditions reached the target and every counterpart reached it exactly once:

```text
PROVEN: 24 changed-condition attempts, 0 stale commits; 16 legitimate counterparts completed, each exactly once.
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
to belong to a counterpart's identity. The results are counts: attempts and how
many reached the target, counterparts and how many reached it exactly once, requests no step
accounts for. They are structural, so they are reported as counts and never as a rate.

## A shared limit and its window

Two rollouts racing for the last unit of an allowance are refused when the allowance is a material
signal published with each commit. The signal is the claim's concurrency scope, held while a claim
is open or its outcome unknown, so the second rollout waits (`AUTHORIZATION_SCOPE_BUSY`); once the
first commits, the next claim reads the new version (`SIGNAL_VERSION_STALE`), and a top-up lets the
second proceed. That is the corpus's third case.

The signal alone leaves a window. When the system of record publishes the consumed allowance after
the commit rather than with it, a claim inside that window reads the old value, and for it nothing
has changed yet: both rollouts would commit. A limit nobody publishes as a signal is not seen at all.

The twelfth case closes the window with a held allowance: the authority holds the allowance itself.
The rule that approves a canary draws one unit on it. The draw is reserved with the grant, kept by
the commit, released by a failure, and never a concurrency scope. With one unit left, the second
rollout is refused at the decision while the first's grant holds that unit: `BLOCK`, with
`ALLOWANCE_EXHAUSTED`. It is refused again inside the window, after the first commit and while the
published signal still reads 1, because the authority counted the commit when it happened. A top-up
then lets it proceed. Without the held allowance, those two attempts reach the target and the run
reports 2 stale commits.

In the loopback double the held allowance is `LocalAuthority`'s `allowanceDraws` option
([local testing](./local-testing.md#held-allowances)). Hosted, the same contract is Decionis's held
allowance at `/v1/authority/allowances`: a policy rule draws on it in `then.allowance`, and a draw
that does not fit is refused before any grant exists. A deployment whose limits draw on no held
allowance keeps the window described above.

## A mandate another institution withdraws

The thirteenth case is a joint pilot's question. An agent proposes under a mandate that another
institution signed, and that institution has since withdrawn it. The ledger service is run for a
partner bank, whose change board signs a standing mandate for this agent: a producer's signed
signal, verified against the key the organisation registered for the bank. Policy lets the ledger's
canary roll out only under it.

The claim looks at the mandate again, as the hosted claim does: who signed it, and until when. The
contract gives the other institution two ways to withdraw a mandate, and the case runs both:

- **It lets the mandate lapse.** A mandate is signed to stand for a set time. A rollout queued under
  it and claimed after that time is refused at the claim with `CURRENT_STATE_UNRESOLVED`, and the
  grant is not consumed. The demo moves the authority's clock past the mandate's end, as a month
  would pass.
- **The organisation stops trusting the bank's key.** A rollout queued before the key was revoked
  is refused at the claim the same way. Proposed again under the same mandate, it is refused at the
  decision with `SIGNED_SIGNAL_KEY_UNKNOWN`.

The counterpart: the bank signs a new mandate under a key the organisation registered, and the
rollout proceeds once.

The contract cannot say "this one mandate is withdrawn, now". A producer cannot revoke a single
signal it issued before that signal runs out. Its lifetime bounds how long a withdrawal takes to
bite, which is why a standing signal lives thirty days at most and a tap for one intent five minutes.
Revoking the key is immediate, but it withdraws everything that key signed. A producer that needs
to withdraw one mandate at once signs mandates with short lifetimes and renews them.

In the loopback double this is `LocalAuthority`'s signed-signal check at the claim and
`revokeProviderKey` (`DELETE /v1/execution/provider-keys/{kid}`), which the hosted routes mirror.

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
  when you cite a run; the corpus grows.
- Archived releases are citable under the Zenodo concept DOI
  [`10.5281/zenodo.22312955`](https://doi.org/10.5281/zenodo.22312955).
- A run that does not do what this page says is a bug here, not a property of your system:
  [open an issue](https://github.com/decionis/agent-safe-pipeline/issues), or use the
  [security policy](https://github.com/decionis/agent-safe-pipeline/security/policy) if it touches
  security.
