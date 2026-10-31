# Changed conditions demo: the Changed Conditions Test

An honest agent's authorized work meets a world that changed before the commit. Thirteen cases,
twenty-four attempts on changed conditions and sixteen legitimate counterparts run offline in a few
seconds with no credentials. Every expectation is asserted, so the run is a
self-checking proof: it exits 0 only when no attempt reached the target and every counterpart
reached it exactly once.

```bash
pnpm --filter @decionis/agent-safe-example-changed-conditions demo
```

## The test

The [Compromised Principal Test](../infra-scale-demo) holds the world still and lets the principal
misbehave. This test holds the principal honest and changes the world:

```text
honest principal → decision in force → conditions change before the commit → refused at the claim | a legitimate counterpart completes
```

An earlier authorization is not an unconditional grant. The claim, immediately before the commit,
is where authority is re-derived: the authority compares the policy release and every material
signal the decision read with what is current and refuses a stale grant without consuming it, and a
claim on a scope another open claim holds waits. A refusal is half of the test. Each case has a
legitimate counterpart that must still complete, because a boundary that holds everything has
prevented nothing worth claiming: a valid renewal proceeds, a safe retry keeps its identity, a
repaired dependency allows reauthorized work.

## The scenario

A deploy agent rolls `checkout` out to its canary group, and a network agent adds security-group
rules. Systems of record publish what the policy reads as material signals: the configuration
digest at `checkout/prod/app.yaml`, the canary group's size, the rollout allowance left today, the
state of change `CHG-1042`, and each security group's classification. Synthetic policy allows a
canary that names the configuration it read and the group as it is, stays inside the host ceiling,
has an allowance left and an approved change, and is not a blocked build. It never opens an
administrative port of a production security group to every address. The authority also holds the
canary allowance itself: the rule that approves a canary draws one unit on a held allowance,
reserved with the grant and kept by the commit.

The authority is the loopback Decionis double from the pipeline's testing entry; the production
`DecionisGate`, `DecionisGrantVerifier` and `GovernedExecutionRunner` carry the work over real
HTTP. The target is the recording target behind `agentsafe test`, standing in for the deploy and
network APIs: it is the observer, and every count is what reached it.

## What it proves

| Case                                                 | Changed condition, and the refusal                                                                                                                                                                                       | Legitimate counterpart                                                     |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| The configuration changes at the same path           | `c41` becomes `c42` while the rollout is queued: `SIGNAL_VERSION_STALE`                                                                                                                                                  | The agent reads `c42` and the work is reauthorized                         |
| The target group grows                               | Four hosts become six: `SIGNAL_VERSION_STALE`, then `BLOCK` for six                                                                                                                                                      | The group is pinned back to four; a repaired dependency allows the work    |
| Two rollouts race for the last unit of the allowance | One unit left, a material signal the deploy API re-versions with each commit; the second rollout while the first holds it: `AUTHORIZATION_SCOPE_BUSY`; after the first committed: `SIGNAL_VERSION_STALE`, then `BLOCK`   | The first rollout completes once; after a top-up, the second proceeds      |
| The approval is withdrawn while queued               | `CHG-1042` withdrawn: `SIGNAL_VERSION_STALE`, then `BLOCK`                                                                                                                                                               | A valid renewal: the change is approved again                              |
| A policy release lands between grant and claim       | `synthetic-policy-v2` released: `POLICY_VERSION_STALE`                                                                                                                                                                   | The same rollout, decided under the new release                            |
| The agent tries to change the controls               | A six-host canary is refused; the agent's own credential gets `401` at the policy lifecycle and at signal ingestion, and so does the executor's key                                                                      | The policy owner releases a six-host ceiling, outside the agent            |
| The proposal content is substituted                  | 2.4.7 presented with the 2.4.6 decision: `INTENT_BINDING_MISMATCH`, before the authority is asked                                                                                                                        | 2.4.7 decided in its own right                                             |
| A lost request, a replay, a safe retry               | The connection drops before the request is written; reconciled as not executed; the consumed grant replayed: `NONCE_REPLAY_DETECTED`                                                                                     | A new decision under the same rollout identity completes once              |
| A lost acknowledgement                               | The rollout lands and the answer is lost; an eager retry while it is unresolved: `CURRENT_STATE_UNRESOLVED`                                                                                                              | Reconciled from the deploy API's record as completed, and never sent again |
| A grant is carried into another organisation         | Another organisation's executor presents it: `403 TENANT_MISMATCH`; with the intent rewritten: `INTENT_BINDING_MISMATCH`                                                                                                 | The grant used where it was issued                                         |
| No admin port of a production group open to all      | SSH to `0.0.0.0/0` on a production group: `BLOCK`; decided while staging, presented after reclassification: `SIGNAL_VERSION_STALE`, then `BLOCK`                                                                         | SSH from the bastion range, on both groups                                 |
| The allowance is published after the commit          | The same race with a producer that publishes late, and one unit left in the held allowance: the second rollout while the first's grant holds it, and again inside the window: `BLOCK` `ALLOWANCE_EXHAUSTED`              | The first rollout completes once; after a top-up, the second proceeds      |
| A mandate from another institution is withdrawn      | The partner bank's signed standing mandate for the ledger lapses: `CURRENT_STATE_UNRESOLVED` at the claim; the organisation revokes the bank's key: `CURRENT_STATE_UNRESOLVED`, then `BLOCK` `SIGNED_SIGNAL_KEY_UNKNOWN` | The bank signs a new mandate under a key the organisation registered       |

The last line reads:

```text
PROVEN: 24 changed-condition attempts, 0 stale commits; 16 legitimate counterparts completed, each exactly once.
```

The observer's counts come before it: the requests the target received, how many of them came from
an attempt (zero), how many counterparts reached it exactly once under their own identity, and how
many requests no step accounts for (zero). They are counts of what reached the target, never a rate.

## A shared limit and its window

The race is closed when the limit is a material signal published with each commit, as case three
shows: the signal is the claim's concurrency scope, held while a claim is open or its outcome
unknown, so the second rollout waits (`AUTHORIZATION_SCOPE_BUSY`), and once the first commits the
next claim reads the new version (`SIGNAL_VERSION_STALE`).

The signal alone leaves a window. When the producer publishes the consumed allowance after the
commit rather than with it, a claim inside that window reads the old value, and nothing has changed
yet for revalidation to see. A limit nobody publishes as a signal is not seen at all.

Case twelve closes the window with the held allowance. The draw is reserved with the grant, so the
second rollout is refused at the decision while the first's grant holds the last unit. The commit
is counted when it happens, so the second rollout is refused again inside the window, while the
published allowance still reads 1. Both refusals are `ALLOWANCE_EXHAUSTED`: the policy, reading the
stale signal, would have allowed them. Without the held allowance, both reach the target and the run
fails with 2 stale commits. The held allowance is a counter, never a concurrency scope, so rollouts
that fit are claimed side by side.

## What the doubles keep, and what they do not

The loopback authority re-derives authority at the claim in the hosted order, with the hosted
reason codes, and refuses a stale grant without consuming it. It does not re-run the policy at the
claim (`POLICY_STATE_CHANGED`), recover an expired claim lease into an unresolved one, or, for a
grant that binds no material signal, hold the execution target as its scope as the hosted claim
store does. A change to the target that no system of record publishes is not seen at the claim,
here or hosted: the grant names no state version of the target. Its held allowance has no window
and serves every tenant alike. See
[testing locally](../../docs/local-testing.md) for what the doubles verify and
[the Changed Conditions Test](../../docs/changed-conditions-test.md) for what each run proves and
does not.
