# Staged change demo: a governed plan

One production change carried out as four governed steps, with the attempts a plan has to refuse
in between, run offline in a few seconds with no credentials. Every expectation is asserted, so the
run is a self-checking proof: it exits 0 only when no step ran out of the plan's order, every
admitted step ran exactly once, and the rollback ran under a grant of its own.

```bash
pnpm --filter @decionis/agent-safe-example-staged-change demo
```

## The change

```text
CHG-1042   open change → drain lb:prod-eu/web → deploy web:2.4.1 → re-enable lb:prod-eu/web
           rollback deployment:prod-eu/*, only after a failed deploy
```

The plan is an `agent-safe.plan/1` document ([ADR 0008](../../docs/architecture/decisions/0008-governed-plans.md)):
the steps, which depends on which (`ordered` for the first three, `all_or_escalate` from the deploy
to the re-enable), and the one compensation that may be proposed. It is registered with the
authority and **authorizes nothing**. Each step is proposed by the agent, matched to its step by the
trusted executor, stamped into the hashed intent as `agent_safe.plan`, decided by policy, granted,
claimed and finalized on its own.

The authority derives each step's plan facts from its own records of what was claimed and how each
claim was finalized, never from the request: a predecessor counts as committed only when it was
finalized COMMITTED with a CONFIRMED effect. The executor writes to the in-process systems once
after each claim and reads every write back, so its finalization carries that confirmation. The
policy is the starter rules: a step still waiting for its predecessors, or not admissible at all, is
a `BLOCK`; one a person must decide is an `ESCALATE`; an admissible step and a compensation are
allowed, each with its own grant.

## What it proves

| Attempt                                            | Plan fact                                | Outcome                                                 |
| -------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------- |
| Register the plan                                  |                                          | no grant exists                                         |
| The deploy, proposed first                         | `WAITING` `PREDECESSOR_NOT_COMMITTED`    | `BLOCK`                                                 |
| A rollback before anything failed                  | `INADMISSIBLE` `NOTHING_TO_COMPENSATE`   | `BLOCK`                                                 |
| Open the change                                    | `ADMISSIBLE`                             | `ALLOW`, committed, effect confirmed                    |
| The deploy, before the drain committed             | `WAITING` `PREDECESSOR_NOT_COMMITTED`    | `BLOCK`                                                 |
| Drain the pool                                     | `ADMISSIBLE`                             | `ALLOW`, committed, effect confirmed                    |
| The deploy with an image the plan does not pin     |                                          | refused by the executor: `PLAN_STEP_PARAMETER_MISMATCH` |
| The same image stamped as the deploy step anyway   | `INADMISSIBLE` `STEP_MISMATCH`           | `BLOCK`: the authority makes the match too              |
| The drain again                                    | `INADMISSIBLE` `STEP_ALREADY_ATTEMPTED`  | `BLOCK`                                                 |
| Deploy; the canary fails its health check          | `ADMISSIBLE`                             | `ALLOW`, the rollout is aborted: FAILED                 |
| Re-enable after the failed deploy                  | `ESCALATE` `PREDECESSOR_FAILED_ESCALATE` | `ESCALATE`: a person decides                            |
| The rollback, presented with the deploy's decision |                                          | `INTENT_BINDING_MISMATCH`, before any claim             |
| The rollback, decided on its own                   | `COMPENSATION` `COMPENSATION_ADMISSIBLE` | `ALLOW` with its own grant, committed                   |

The run ends with the plan `PARTIAL`, the SCITT `partially_completed`
([SCITT](../../docs/authority/scitt.md)): the change did not complete as approved, the release
rolled back, and the pool still drained, waiting for the person the re-enable escalated to.

## What it does not show

- **The claim.** The hosted authority binds each step's view of the plan as a material signal and
  re-derives it at the claim, so a grant decided before the plan moved (a step failed, an outcome
  became unknown) is refused there with `SIGNAL_VERSION_STALE`. The loopback double decides with
  the same facts, through `LocalPlans`, but does not re-derive them at the claim.
- **A hosted run.** The demo does not create a hosted gate: a hosted evaluation of a plan step needs
  the plan registered with Decionis first.
- **A real system.** The ticket system, load balancer and deployment API are in-process doubles,
  and every identity is synthetic.
