# Native Executor v1: changes

Every entry names the pull request that made it and the vectors that pin it.

## 2026-10-23: the target's state version

- An optional sixth operation, `readState(action, prepared, scope)`: the executor reads its target
  once, read-only, after `prepare` and before the authority is asked. `GovernedExecutionRunner.submit`
  binds what it returns into the intent as `context.agent_safe.precondition`
  ([Agent-Safe Intent v1](../../../intent/v1/CHANGELOG.md)), and refuses a read that fails, or
  answers anything but a precondition or null, with `TARGET_STATE_UNREADABLE` before anything is
  decided. An executor that does not implement it is unchanged, and so are the wire profile and its
  vectors.

## 2026-10-20: the policy projection

- `prepare` may state the policy path the authority decides the action under (`PreparedAction`'s
  optional `policyProjection`). The runner binds it into the intent as `policy_projection`
  ([Agent-Safe Intent v1](../../../intent/v1/CHANGELOG.md)) and, at admission, refuses as
  `INTENT_BINDING_MISMATCH` an executor whose `prepare` names another path than the decided one
  (§4.1, step 6). An executor that states none is unchanged. The wire profile and its vectors are
  unchanged: the projection is the executor host's, never the platform's request.

## 2026-10-18: the contract, the runner, the permit wire profile

- The profile is written down: the executor interface in two styles (dispatch and permit), the
  runner's obligations (admission, the authority calls on the grant's REST resources, the journal and
  single-use idempotency keys, deadlines, failure posture, evidence and the six outcomes) and the
  permit wire profile for platforms that do not run the reference implementation
  ([README.md](./README.md)).
- [`schema.json`](./schema.json), JSON Schema 2020-12 of the wire objects (`ExecutionCapability`,
  `ExecutionRequest`, `ExecutionResponse`, `NativeReceipt`, `ReceiptResponse`,
  `ReconciliationRequest`, `ReconciliationResponse`, `ExecutorEvidenceLine`, `ExecutorVector`),
  generated from the reference implementation's validators; a test holds the file to the generator.
- [`vectors/`](./vectors): eighteen vectors over both styles, a refusal before and after dispatch,
  an `INDETERMINATE` dispatch and its reconciliation, a duplicate receipt, an expired and a replayed
  permit, an unreadable receipt, an escalation and every failure posture.
