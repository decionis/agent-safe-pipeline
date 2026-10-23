# ADR 0008: governed plans for composite decisions

Status: accepted, 2026-10-23. Decision D3 below (plan state as a material signal) is the user's,
taken 2026-10-23, and reversible: the alternative is recorded under "Options considered".

## Problem

An institutional decision is rarely one operation. A production change opens a ticket, drains a
pool, deploys, and puts traffic back. Each step is a separate operation against a separate system,
some may be admissible while others are not, and stopping halfway can itself leave a hazardous
state. Willis puts it as "the action boundary is not the consequence boundary" (_The Commit
Boundary_, Edition 29, 23 October 2026), and the AGCP requirements catalog names the pieces:
composite proposal representation, dependency-graph evaluation, coupling classification and
partial-bind governance.

The repository could not express any of it:

- One intent is one action, target and parameter set. Nothing ties two intents into one change.
- Decionis keeps Decision Chain lineage (`workflow_id`, `step_id`, `sequence`, parents) and
  projects it into `history.sequence`, but that projection carries verdicts and no commit status.
  Enforce-and-bind sends no `decision_chain` at all, and a caller-supplied `history.sequence`
  wins. So "deploy only after drain has committed" cannot be written as policy.
- Nothing says what remains admissible after a step fails, or that a rollback needs authority.
- BEAP §17 batch manifests ([conformance](../../beap-conformance.md)) are a different object: one
  grant for an atomic batch, one effect. They are not built either.

## Options considered

1. **Decionis runs the plan.** An orchestrator in the authority would call each system in turn. It
   puts the authority in the effect path of every step, makes it responsible for retries and
   timeouts it cannot observe, and contradicts the line the sequence design drew
   (`docs/architecture/sequence-authority.md` in Decionis: "not orchestration"). The customer's
   workflow engine already runs steps; what it lacks is a governed answer to "may this step
   commit now".
2. **One grant for the whole plan.** Batch-manifest style: approve the plan, issue one grant,
   execute everything. A grant issued before the drain commits would authorize a deploy whose
   precondition does not hold yet, and one grant cannot be revalidated per step at the commit
   boundary. This is the shape a batch should have and a plan must not.
3. **A first-class plan check at claim, with its own reason codes.** The claim route would load
   the plan and refuse `PLAN_PREDECESSOR_NOT_COMMITTED`, `PLAN_SUSPENDED`, and so on, beside the
   revalidator. It is explicit, and it is a second revalidation mechanism with its own codes,
   tests and evidence, parallel to the one every other fact already goes through.
4. **A plan as a governance object; plan facts derived by the authority; plan state as a material
   signal.** The plan is registered, each step is proposed and granted on its own, the authority
   derives the step's plan facts from its own finalization records, and the existing revalidation
   rechecks them at the claim.

## Decision

Option 4. Option 3 is the alternative D3 rejected; returning to it replaces the signal described
under "Plan state as a material signal" and changes nothing else here.

### The plan object: `agent-safe.plan/1`

[`plan/GovernedPlan.ts`](../../../packages/pipeline/src/plan/GovernedPlan.ts) is the schema, the
digest and the step match; Decionis mirrors it in `packages/shared` and both pin the same digest
vector.

| Field            | Meaning                                                                                                                         |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `version`        | `agent-safe.plan/1`                                                                                                             |
| `plan_id`        | the organisation's name for the change; one registered digest per id                                                            |
| `tenant_id`      | the one organisation the plan belongs to                                                                                        |
| `steps[]`        | `step_id`, `action`, `target` (exact, or a prefix ending in `*`), optional `parameters` (pinned values), optional `compensates` |
| `edges[]`        | `from`, `to`, `coupling`: `to` depends on `from`                                                                                |
| `partial_commit` | `admissible` (steps that stay admissible after a failure) and `otherwise` (`ESCALATE` or `BLOCK` for the rest)                  |

The digest is SHA-256 over the plan's canonical JSON (sorted keys), `sha256:` and 64 hex. A plan is
immutable: a changed plan is a new `plan_id`. The schema refuses duplicate steps, unknown or
self-referencing edges, cycles, a compensation step inside an edge, and a compensation of a
compensation.

**Coupling, per edge.** It says what the predecessor's outcome means for the dependent step:

| Coupling          | Predecessor committed | Predecessor not yet committed | Predecessor failed         |
| ----------------- | --------------------- | ----------------------------- | -------------------------- |
| `ordered`         | admissible            | waiting                       | inadmissible               |
| `all_or_escalate` | admissible            | waiting                       | escalate: a person decides |
| `independent`     | admissible            | admissible                    | admissible                 |

"Committed" means COMMITTED with a CONFIRMED effect. A commit whose effect nobody confirmed is
reported separately and escalates under `ordered` and `all_or_escalate`: somebody has to accept
that the drain happened before the deploy may assume it.

**Partial commitment.** Once a step has FAILED the plan is PARTIAL. A remaining step is admissible
only if its edges allow it and it is listed in `partial_commit.admissible`; otherwise it takes
`partial_commit.otherwise`. A compensation step (`compensates: ["deploy"]`) is admissible only
after a step it compensates has FAILED, and never otherwise.

### Approval authorizes nothing

Registering a plan grants no step. Every step, compensations included, is proposed, decided by
policy, granted, claimed and finalized like any other intent. A rollback is a governed action with
its own grant: the plan only says it may be proposed. Policy decides each step with the plan's
facts in front of it, so a plan can narrow what is admissible and can never widen it.

### Stamping

The trusted executor states which step an intent is: `TrustedIntentContext.plan` =
`{plan_id, plan_digest, step_id}`. `IntentCapture` writes it into the hashed context as
`context.agent_safe.plan`. `agent_safe` is a reserved key, refused in a caller's context
(`INTENT_CONTEXT_KEY_RESERVED`), and an agent's proposal cannot reach `context` at all. Before it
stamps, the executor matches the proposal to the step with `matchPlanStep` and refuses a different
action, a target outside the step's scope, or a parameter that differs from a pinned one. The
authority repeats that match; the executor's check only fails fast.

An intent without a plan carries no `agent_safe` key, so it hashes exactly as before and every
published vector holds.

### Plan facts

The authority derives them, and the caller cannot. In Decionis the server rebuilds `agent_safe`
on every evaluation, so a caller's `context.agent_safe` never reaches policy; the derived facts
are written to `agent_safe.plan` in its place.
[`plan/PlanState.ts`](../../../packages/pipeline/src/plan/PlanState.ts) is the derivation, and
Decionis mirrors it:

- **Step status**, from the step's finalization records: `PENDING` (never claimed), `IN_FLIGHT`
  (claimed, not finalized), `COMMITTED` (COMMITTED with a CONFIRMED effect), `UNCONFIRMED`
  (COMMITTED without one), `INDETERMINATE`, `FAILED`.
- **Plan state**: `SUSPENDED` while any step is INDETERMINATE (nothing proceeds on an outcome
  nobody knows), else `PARTIAL` once any step FAILED, else `COMPLETE` when every non-compensation
  step COMMITTED, else `ACTIVE`. PARTIAL is sticky in v1: a plan that failed a step did not
  complete as approved, and compensating does not make it so.
- **The step's admissibility**: `ADMISSIBLE`, `COMPENSATION`, `ESCALATE`, `WAITING` or
  `INADMISSIBLE`, with one reason code. A suspended or complete plan, a step already attempted, an
  unknown plan or step, a digest that is not the registered one, and a proposal outside its step
  are all `INADMISSIBLE`.

Policy maps them to verdicts. The starter rules are `WAITING` and `INADMISSIBLE` to BLOCK and
`ESCALATE` to ESCALATE; `ADMISSIBLE` and `COMPENSATION` fall through to the organisation's other
rules. That is what refuses a deploy before the drain commits, turns a re-enable after a failed
deploy into an ESCALATE, and lets a rollback be proposed for its own grant.

### Plan state as a material signal (D3)

Each step's facts carry a material signal: `signal_id` = `agent_safe.plan:<plan_id>:<step_id>`,
`version` = the digest of the step's **view** of the plan (the plan state, the step's own status,
its predecessors' statuses, and for a compensation the statuses it compensates), `observed_at` =
the latest record time in that view. The binding records it like any material signal, and at the
claim the authority re-derives the view from current records: a changed view fails the claim with
the existing `SIGNAL_VERSION_STALE`, before the nonce is consumed, and the policy re-run sees the
re-derived facts. No new reason code exists.

**The concurrency-scope hazard.** Every material signal id in a binding is a concurrency scope, held
while a claim is open or unknown, and with any material signal the binding's target-resource scope
is dropped. A plan-wide signal on every step would serialize steps that are independent by
construction, and would silently remove the target scope from every plan step. Two choices close
both:

1. **The signal is per step, not per plan.** Its id names the step, so two steps never share it;
   only two grants for the same step do, and those should never claim at once. Plan state still
   reaches every step, because it is part of every step's view and so of every step's version.
2. **An additive exclusion in scope derivation.** A plan-step signal does not count when deciding
   whether the target-resource scope is dropped: a plan step keeps its target scope (or its other
   signals' scopes) and gains a `PLAN_STEP` scope beside it. A binding with no plan-step signal
   derives exactly the scopes it derived before, so no existing binding, claim or digest changes.
   The prefix is reserved: a caller-supplied material signal with it is refused, so the rule
   cannot be reached from outside.

Re-deriving the facts through the policy re-run alone (option 4 without the signal) would avoid
scopes entirely, but the binding would not record what the decision rested on, and a view change
that leaves the verdict unchanged would claim silently. The per-step signal records it and refuses
it, and costs one scope per step.

What the signal does not do: a grant decided while a predecessor was still in flight carries that
view, and is refused at the claim once the predecessor settles. While the predecessor is still in
flight the view has not changed, so a policy that ignored the plan facts and granted early would
not be stopped at the claim. The starter rules never grant a `WAITING` step; organisation
invariants that make them mandatory are a separate phase.

### One organisation in v1

A plan belongs to one organisation and every step is decided by its policy. A change spanning
separate authorities (the hospital example in Willis) needs each authority to see the other's
commit status, and waits for a design partner.

## Reason

It reuses every mechanism at the commit boundary: the intent, the grant, the claim, revalidation
and finalization. A step is governed exactly like an action outside a plan, and the plan only adds
facts. Nothing models consequences: the plan states dependencies the organisation already knows,
and the authority reports what its own records say happened.

## Protocol impact

None to `agent-safe.intent/1`: the stamp is a reserved key in the hashed `context`, which the
Decionis contract declares `additionalProperties: true`. `agent-safe.plan/1` is a new, separate
document. Decionis gains a plan registry and a read of it (`POST /v1/authority/plans`,
`GET /v1/authority/plans/{plan_id}`), a fact namespace (`agent_safe.plan`), and the scope rule
above. The SCITT mapping gains `partially_completed` for a PARTIAL plan
([SCITT](../../authority/scitt.md)).

## Compatibility impact

Nothing is required. An executor that states no plan stamps nothing. A caller that already wrote
`agent_safe` into a trusted context is refused, which no code in this repository did. The fixture
and edge authorities derive no plan facts; a plan-stamped intent decided there is decided without
them.

## Security impact

- The agent cannot name a plan or a step: the stamp is the executor's, the key is reserved, and the
  proposal schema is strict.
- The facts are the authority's: Decionis rebuilds `agent_safe` server-side at bind and at claim,
  so a caller cannot assert that a predecessor committed.
- A forged plan signal in a binding is refused at the claim, because the authority re-derives the
  current one and compares.
- Registering a plan authorizes no step, so a plan written to make a step look admissible still
  has to pass policy at bind, and the re-derived facts at claim.
- A plan step keeps its target-resource scope, so a plan cannot be used to run two writes to one
  resource at once.

## Migration impact

To govern a change as a plan: write it as `agent-safe.plan/1`, register it with Decionis, and have
the executor state `plan` in each step's trusted context after `matchPlanStep` accepts the
proposal. Add the starter rules, or rules of your own over `agent_safe.plan.admissibility`.
[`examples/staged-change-demo`](../../../examples/staged-change-demo) is the whole flow against the
loopback authority.
