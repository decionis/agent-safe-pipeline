# Native Executor v1: changes

Every entry names the pull request that made it and the vectors that pin it.

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
