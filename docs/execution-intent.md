# Execution intent

The binding this page describes is published as [Agent-Safe Intent v1](../spec/intent/v1/README.md):
the specification, a JSON Schema generated from this package's validator, the changelog, the
conformance requirements, and the framework coverage matrix. This page is how the runtime uses it.

The versioned `agent-safe.intent/1` authority binding is the Decionis `ExecutionIntentBinding`
contract: `protocol_version`, `tenant_id`, `intent_id`, `captured_at`, `expires_at`, `actor`,
`action` (type, resource, parameters), `context`, `downstream_target` (system, operation, optional
environment and endpoint), and the optional `policy_projection` and `expected_effect_digest`. The
contract rejects every other top-level property. Keys are sorted by UTF-16 code unit before JSON encoding and SHA-256 hashing, which is how
Decionis recomputes the hash on receipt.

Input validation and canonicalization are bounded to 100 KiB by default, nesting depth 20, 5,000
entries, and arrays of 1,000 values. Cycles, non-JSON object prototypes, `__proto__`, `prototype`, and
`constructor` keys are rejected before recursive schema parsing. Numbers must be finite JSON numbers.

The trusted runtime, not the agent, supplies the idempotency key and correlation ID. The idempotency
key stays part of the canonical binding by riding inside the trusted `context` under the reserved
`idempotency_key` entry; `IntentCapture` rejects a caller-supplied context key of that name. The
authority request's `Idempotency-Key` header carries the `intent_id`, because the contract defines the
intent as the grant-issuance boundary and rejects a header that differs from it. The correlation ID
remains operational metadata and must not affect execution semantics.

## The policy projection

`policyProjection` is an optional trusted-context input naming the policy path the authority decides
the intent under: `decisionType`, and `transactionType`, `workflowKey` and `channel`, each a string
or `null`. Without one, Decionis evaluates `action.type` as the decision type, transaction type and
workflow key, which is right when an action's name is its policy vocabulary. An executor whose policy
names a write otherwise states it: a Walmart order acknowledgement is decided as `ORDER_ACCEPTANCE`,
not as `order.acknowledge`. A `null` field is one the authority leaves out of the evaluation.

The binding carries it as the top-level `policy_projection`, in the contract's snake case, so it is
inside `intent_hash`, inside the grant request (`POST /v1/authority/grants`, a managed escalation
included), and inside the claim's `intent`. Decionis routes the grant by it and recomputes the hash
over it, so a claim re-validates the policy path the grant was decided on, and a projection dropped or
rewritten between the decision and the claim is an `INTENT_HASH_MISMATCH`. A native executor states it
on its `PreparedAction`; `GovernedExecutionRunner` captures it and refuses, as
`INTENT_BINDING_MISMATCH`, an executor whose `prepare` names another path than the decided one.

Only the trusted runtime may state it: the agent proposal is strict, and an agent that could name its
projection could choose the policy it is evaluated under. An intent that states none hashes and
travels byte-identically to 0.4.0, before the property could be stated
(`conformance/vectors/policy-projection-absent.json`).

## The expected-effect commitment

`expectedEffectDigest` is an optional trusted-context input: `sha256:` followed by 64 lowercase hex
characters, a digest-only commitment to the downstream state predicted before dispatch. Only the
trusted runtime may supply it. The agent proposal cannot carry it, because `AgentProposalSchema` is
strict and rejects the key; an agent that could name its own expected effect could name the one it
intends to cause.

Supplying it changes one thing and binds everything. The digest becomes a top-level binding property,
so it is inside `intent_hash`, inside the enforce-and-bind request, inside the claim's `intent`, and
inside the signed grant the authority returns. Decionis re-checks it with an exact comparison before
issuing any grant, and `DecionisGrantVerifier` refuses the authorization unless the returned grant
echoes exactly that digest, so the commitment is the authority's and not merely the executor's. The
refusal happens before dispatch and `SafeExecutor` blocks with `AUTHORIZATION_INVALID`. The echo is
read from the claim response the configured authority origin returned over TLS; this package verifies
no signature of its own, so the check binds the executor to the authority's answer, not to a proof
that survives a compromised authority endpoint.

The comparison is symmetric and fail-closed in both directions. A grant that reports a digest for an
intent that bound none is refused too: the digest is inside `intent_hash`, so an authority cannot
derive one the intent did not carry, and a grant that claims otherwise is not describing this intent.
A binding property reported as `null` means the same as an absent one — no commitment — and is
accepted for an intent that bound none.

An intent that omits the field is unaffected. The property is added through a conditional spread and
is never set to `undefined`, so the binding object, the canonical JSON, the byte length, and the hash
are identical to what the same intent produced before the property existed, and the pinned
conformance vector in `conformance/agent-safe-intent-v1.json` reproduces unchanged.

A deployment whose authority predates the field issues no grant for an intent that carries it: the
action is blocked, never mis-authorized. Because the field is opt-in and absent by default, no
existing caller is affected.

## The plan step

`plan` is an optional trusted-context input: `{plan_id, plan_digest, step_id}`, the step of an
`agent-safe.plan/1` governed plan this intent is ([ADR 0008](./architecture/decisions/0008-governed-plans.md)).
The runtime states it only after `matchPlanStep` accepted the proposal as that step: the step's action,
a target inside its scope, and every parameter the step pins. `IntentCapture` writes it into the hashed
context as `agent_safe.plan`. `agent_safe` is reserved, like `idempotency_key`, so a caller-supplied
context key of that name is refused (`INTENT_CONTEXT_KEY_RESERVED`), and the agent proposal cannot
reach `context` at all.

The reference says which step the intent claims to be, and nothing more. Whether the step is
admissible is the authority's to derive, from the registered plan and its own finalization records:
predecessors committed with a confirmed effect, the plan's state, and what a failure left admissible.
Registering a plan authorizes no step; each step is decided, granted, claimed and finalized like any
other intent. An intent that states no plan carries no `agent_safe` key and hashes as it did before.

## What the binding covers, and the Compromised Principal Test

The hash is over the whole binding, so authority is bound to the exact action and never to the
identity that proposed it. That is the property the realistic adversary tests. Most corpora test a
forged credential: a token the attacker should not hold, a signature that does not verify. The
failure that matters as agents get faster and more autonomous is the other one, and it is the case
identity cannot catch, because identity is exactly what is in order:

```text
valid principal → valid credential → permitted API → unauthorized consequential intent → BLOCK | ESCALATE
```

An agent that may call `deployment.scale` is not an agent that may scale anything to anything. The
binding holds the principal (`actor`), the target (`action.resource`), every parameter
(`action.parameters`), the trusted runtime's context, the downstream target with its environment,
and the expiry; Decionis decides over that hash against the policy revision in force, and the
grant it issues is good for that hash, once. A change to any bound field after authorization is
another intent with another hash, which the grant does not cover: the executor refuses it with
`INTENT_BINDING_MISMATCH` before anything is dispatched. Identity says who is asking; execution
authority says whether this is permitted to happen.

An implementation of `agent-safe.intent/1` MUST therefore produce a different hash for every
single-field change to a binding, and
[`conformance/vectors/compromised-principal.json`](../conformance/vectors/compromised-principal.json)
holds it to that: an infrastructure agent's `deployment.scale` intent (`prod-eu`, `inference`,
96 replicas) and eight mutations a valid principal could make after authorization, each with its
own canonical bytes and hash. The replica count raised to 960, the service changed to `payments`,
the cluster changed to `prod-us`, the resource renamed with the parameters left alone, the
principal replaced by a stronger identity, the expiry extended, the idempotency key changed, and
the environment changed to `staging`: nine distinct hashes, and a grant for the first authorises
none of the others. [`examples/infra-scale-demo`](../examples/infra-scale-demo) runs the same
test against the boundary end to end, and [`THREAT-MODEL.md`](../THREAT-MODEL.md) states it as a
threat.
