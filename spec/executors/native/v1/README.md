# Native Executor v1

**Identifier:** `agent-safe.executors.native/1` · **Status:** published, in force · **Publisher:**
Decionis · **Reference implementation:** `NativeExecutor` and `GovernedExecutionRunner` in
[`@decionis/agent-safe-pipeline`](../../../../packages/pipeline) · **Schema:**
[`schema.json`](./schema.json) · **Vectors:** [`vectors/`](./vectors) · **Changes:**
[`CHANGELOG.md`](./CHANGELOG.md)

A native executor is the one piece of code that carries a decided action into a system of record:
a core banking ledger, an ERP posting, a marketplace feed, a card issuer's authorization. This
profile is the contract every native executor implements, on every platform, and the rules the one
runner around it enforces, so that every write by any component carries one single-use permit from
one authority and ends in one of six outcomes. It is published by Decionis and implemented by its
reference runtime; it is not a standard approved by any standards body.

The key words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119 and RFC 8174.

## 1. Scope

This profile defines:

1. **The executor interface** (§3): what an executor states, prepares, writes, observes and
   reconciles, in two styles.
2. **The runner's obligations** (§4): admission, the authority calls, the journal, deadlines,
   failure posture, evidence and the outcome table. An executor never does any of these itself.
3. **The permit wire profile** (§5): the same contract over HTTP, for platforms that do not run the
   reference implementation (Business Central AL, F&SCM X++, SAP ABAP/CAP).
4. **Conformance** (§7): the vectors both styles are held to.

It does not define policy, verdicts or the canonical intent. The intent and its hash are
[Agent-Safe Intent v1](../../../intent/v1/README.md); the decision, the grant and its dossier are
the Decionis execution-authority contract.

## 2. Terms

- **Executor**: the platform-specific code behind this interface. It is trusted, and it knows its
  platform and nothing else.
- **Runner**: the one implementation of §4 (`GovernedExecutionRunner`). Every executor runs inside
  it.
- **Grant**: the authority's single-use authorization for exactly one intent hash. Its id is the
  `jti` the authority signs into it and returns as `execution_token_jti`.
- **Claim**: the authority consuming a grant, once, immediately before the write.
- **Permit**: what a native boundary presents with its write in permit style. It stands for one
  grant and names its id, its intent hash and its expiry; it never carries the token.
- **Receipt**: the platform's native answer about a write (a posting entry, a feed id, an HTTP
  status, an issuer result), in the platform's own vocabulary.
- **Scope**: the connection an action runs under (`orgId`, `workspaceId`, `connectionId`,
  `connectionRevision`, `company`, `store`, `environment`). The host resolves it from the
  authenticated connection; a client MUST NOT be able to supply it.

## 3. The executor interface

An executor states `platform`, `version`, `style` (`dispatch` or `permit`) and the `actionTypes` it
answers for, and implements five operations.

| Operation                   | Called                                                       | It MUST                                                                                                                                                                                                            |
| --------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `capabilities(scope)`       | at admission                                                 | state, per action type, whether the connection is `connected`, `scopeGranted` and `enabled`, and in `requirement` what is still missing. Field for field the capability Commerce's executor seam reports.          |
| `prepare(action, scope)`    | before the authority is asked, and again at admission        | return the action as the intent binds it (action, resource, parameters, downstream target), its idempotency key, the expected-effect digest when it can predict one, a request digest, and platform facts. No I/O. |
| `execute(run)`              | once, after the claim (dispatch) or at presentation (permit) | dispatch: perform the write once, inside `run.dispatch`, within `run.deadline`. permit: return the permit; never write.                                                                                            |
| `observe(effect, prepared)` | on the platform's answer                                     | map the receipt to `COMMITTED`, `FAILED` or `INDETERMINATE`, purely: no second call, and silence is never success.                                                                                                 |
| `reconcile(context)`        | only after `INDETERMINATE` or a missing receipt              | ask the platform read-only what happened under the idempotency key: `COMPLETED`, `NOT_EXECUTED` or `UNKNOWN`. It MUST NOT initiate or retry anything.                                                              |

An executor MUST NOT call the authority, sign anything, map a verdict, retry a write, or decide an
outcome. Those are the runner's (§4), so that no platform's code can weaken them.

### 3.1 The dispatch boundary

In dispatch style the runner opens one dispatch per attempt. Everything before `dispatch.run` is
before the boundary: an error there is a failure before dispatch, and nothing was sent. Everything
after it has left the process: an error there is an outcome nobody knows, unless the platform itself
refused deterministically (a 4xx naming its rule), which is a refusal. A timeout, a 5xx, a dropped
connection or an unreadable answer is never a refusal. The runner, not the executor, decides which
side of the boundary an error fell on, and it never moves "nobody knows" to "definitely not".

### 3.2 Styles

- **dispatch**: the executor performs the write (core banking, a Walmart price feed, an agent's API
  call). Admission claims the grant; `execute` writes once; `observe` reads the answer.
- **permit**: the platform performs the write and presents a permit (a Business Central posting, a
  card issuer's authorization). Admission holds the grant unclaimed and returns the permit
  descriptor; presentation claims it once and `execute` returns the claimed permit; the platform's
  receipt settles it.

## 4. The runner's obligations

### 4.1 Admission

An execution is admitted only when every one of these holds, in this order, and a refusal at any
step consumes nothing:

1. the decision is authoritative (not a shadow or observational artifact);
2. the verdict is `ALLOW` (or Commerce's `PROCEED`, which means the same), and the decision did not
   fail closed;
3. the decision carries a dossier;
4. the decision is for this intent hash, carries a grant, and the intent re-hashes to itself;
5. the intent was captured at this enforcement boundary and by this workload, when those are set;
6. the executor's `prepare` describes exactly the intent that was decided;
7. the scope's capability for the action type is connected, scope-granted and enabled.

### 4.2 Authority calls

The runner reaches the authority through its verifier, on the grant's REST resources:

| Purpose                                   | Request                                               | Deprecated alias (same handler)                       |
| ----------------------------------------- | ----------------------------------------------------- | ----------------------------------------------------- |
| Evaluate an intent and bind a grant       | `POST /v1/authority/grants`                           | `POST /v1/authority/enforce-and-bind`                 |
| Read and verify a grant                   | `GET /v1/authority/grants/{grantId}`                  | `POST /v1/execution/verify-token`                     |
| Claim the grant, once                     | `POST /v1/authority/grants/{grantId}/claims`          | `POST /v1/execution/claim-token`, `.../consume-token` |
| Record how the attempt ended (finalize)   | `POST /v1/authority/grants/{grantId}/receipts`        | `POST /v1/execution/finalize-token`                   |
| Report how an indeterminate attempt ended | `POST /v1/authority/grants/{grantId}/reconciliations` | none                                                  |

`grantId` is the grant's `jti`. A path whose id is not the presented token's grant is refused with
`GRANT_ID_MISMATCH`. Finalization and reconciliation reports are evidence, never authority: they
never retry a write, never change an outcome, and a report that cannot be delivered is `PENDING`.

### 4.3 Journal and idempotency

When the runner has a journal (`agent-safe.attempts/1`) it MUST open the attempt before anything is
consumed and MUST write the claim durably after the grant is consumed and before the executor is
called; a journal that cannot take the claim fails the attempt before dispatch. A journal that
answers which idempotency keys were already claimed lets the runner refuse a second dispatch under
the same key before a grant is spent (`IDEMPOTENCY_KEY_DISPATCHED`); a journal shared by replicas
MUST refuse the second claim under one key itself, so two replicas racing on a key write once.

### 4.4 Deadlines

The dispatch window is the smallest of the configured timeout, what is left of the grant, and what
is left of the authority's claim lease. A window that has already closed fails before dispatch
(`DISPATCH_WINDOW_CLOSED`): a commit the authority will no longer record leaves an outcome nobody
can reconcile.

### 4.5 Failure posture

Posture applies only when the authority could not be reached (the decision failed closed). It never
overrides a verdict from an authority that answered, and under no posture does the runner write
without a grant.

| Posture              | The runner's outcome | Disposition the evidence reports                                          |
| -------------------- | -------------------- | ------------------------------------------------------------------------- |
| `STRICT`             | `BLOCKED`            | `NOT_FORWARDED`                                                           |
| `BOUNDED_CONTINUITY` | `BLOCKED`            | `FORWARDED_UNGOVERNED`: the surface may continue, ungoverned              |
| `CUSTOM`             | `BLOCKED`            | the institution's rule: `NOT_FORWARDED`, `HELD` or `FORWARDED_UNGOVERNED` |

An ungoverned continuation is the surface's own act. It is never approved, and it is reported as a
coverage gap rather than hidden.

### 4.6 Outcomes

Every run ends in exactly one of six outcomes:

| Outcome                   | Meaning                                                       | May the caller retry the write?      |
| ------------------------- | ------------------------------------------------------------- | ------------------------------------ |
| `BLOCKED`                 | No valid execution authority reached the executor             | Obtain or correct authority first    |
| `HELD`                    | Admitted; the grant waits, unclaimed, for the native boundary | No; the boundary presents the permit |
| `FAILED_BEFORE_DISPATCH`  | A grant was consumed and nothing was sent                     | Only with a fresh decision and grant |
| `COMPLETED`               | The platform effected the action                              | No; return or persist the result     |
| `DEFINITELY_NOT_EXECUTED` | The platform was reached and refused; nothing was effected    | Only with a fresh decision and grant |
| `UNKNOWN_AFTER_DISPATCH`  | The write left, and nobody can yet say what happened          | No; reconcile first                  |

A settlement is the permit-style end of a held execution: `COMPLETED`, `DEFINITELY_NOT_EXECUTED` or
`UNKNOWN_AFTER_DISPATCH`. A receipt is accepted once; a second receipt is refused with
`RECEIPT_DUPLICATE`, and a receipt for a permit nobody presented with `PERMIT_NOT_PRESENTED`.

### 4.7 Evidence

The runner writes one `agent-safe.executor-evidence/1` line per step (run, presentation,
settlement, reconciliation): the executor, the action type, the intent, decision, dossier and grant
identifiers, the outcome, whether a grant governed the step, the authority state, the posture and
disposition, the finalization and the duration. A line carries identifiers, statuses and timings
only, never a parameter, token, receipt, credential or response body. Its shape is
`ExecutorEvidenceLine` in [`schema.json`](./schema.json).

## 5. The permit wire profile

A platform that does not run the reference implementation implements the permit style over HTTP,
against an executor host that runs the runner (for Business Central, Commerce):

1. **Create an execution.** `POST /v1/connections/{connectionId}/executions` with
   `ExecutionRequest`: the executor identity, the action type, and the platform's own description of
   the action. The host resolves the scope from the authenticated connection, prepares the action,
   asks the authority (§4.2) and holds the grant.
2. **Receive the permit.** `ExecutionResponse`:
   `{execution_id, outcome, decision, reason_codes, dossier_id, permit_id, intent_sha256, expires_at}`.
   `permit_id`, `intent_sha256` (the bare SHA-256 of the intent) and `expires_at` are present only
   when `outcome` is `HELD`.
3. **Post with the permit.** The platform's posting presents `permit_id` to the host, which claims
   the grant once; a replayed or expired permit is refused.
4. **Report the receipt.** `POST /v1/connections/{connectionId}/executions/{executionId}/receipts`
   with `NativeReceipt`: the permit and the platform's receipt in its own vocabulary
   (`{platform, kind, reference, status, observed_at, digest?}`). The host's executor observes it,
   the runner finalizes the grant through `POST /v1/authority/grants/{grantId}/receipts`, and the
   host answers `ReceiptResponse`.

Reading an execution is `GET /v1/connections/{connectionId}/executions/{executionId}`. An execution
whose receipt never arrived, or arrived unreadable, is reconciled through
`POST /v1/connections/{connectionId}/executions/{executionId}/reconciliations`
(`ReconciliationRequest`), which asks the executor read-only and reports a proven answer through
`POST /v1/authority/grants/{grantId}/reconciliations`.

## 6. Versioning

Within `/1` a change MAY add an optional field to a wire object, a new platform identifier, or a new
vector. Anything that changes the meaning of an existing field, an outcome, or an obligation in §4
is `agent-safe.executors.native/2`. Every change is recorded in [`CHANGELOG.md`](./CHANGELOG.md)
with the pull request that made it and the vector that pins it.

## 7. Conformance

Each file under [`vectors/`](./vectors) is an `ExecutorVector`: a decision (verdict, and whether it
failed closed), a posture, a style, and steps — `run` with a scripted write, `hold`, `present`,
`receipt` with a native status, `reconcile` with the platform's answer, `advance` of the clock —
each with the outcome it MUST produce, the commit outcome the authority MUST have recorded, and how
many writes MUST have been attempted. Together they cover both styles, a refusal before and after
dispatch, an `INDETERMINATE` dispatch and its reconciliation, a duplicate receipt, an expired and a
replayed permit, an unreadable receipt, an escalation, and every posture.

`NativeExecutorVectors.test.ts` in the reference implementation runs every vector against
`GovernedExecutionRunner` with a development authority, holds every evidence line the runner writes
to the published shape, and holds [`schema.json`](./schema.json) to the validators the package runs.
An executor host implementing §5 SHOULD replay the same vectors over its HTTP interface.
