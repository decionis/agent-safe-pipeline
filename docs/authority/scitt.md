# SCITT statement profiles

Two individual Internet-Drafts profile SCITT ([RFC 9943](https://www.rfc-editor.org/rfc/rfc9943))
for agent actions. This page says how the records this repository writes relate to them, at the
revisions named here, read on 21 October 2026. Neither draft is a working-group document, nothing
in this repository produces either format, and nothing here is a claim of conformance to them.

| Draft                                                                                                                    | What one record says                                                                       | Who signs it                     | Here                                                                                       |
| ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ | -------------------------------- | ------------------------------------------------------------------------------------------ |
| [Agent Action Capsule](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/), `-04` (`-05` is current) | how one action was disposed: the decision, the constraints evaluated, the confirmed effect | the party that made the decision | Decionis exports a Decision Dossier as a `-04` capsule; this package builds and signs none |
| [AI Agent Execution Profile](https://datatracker.ietf.org/doc/draft-emirdag-scitt-ai-agent-execution/), `-01`            | what an agent executed: the AgentInteractionRecord (AIR)                                   | the agent operator, with ES256   | the executor's evidence holds most of what an AIR says; nothing here writes one            |

The two describe different moments. The execution profile records what was executed, says it does
not define the authorisation record (§10.1), and says a deployment can record a capsule and an AIR
for the same action and correlate them by `trace_id` or `external_refs` (§10.2). Its outcome values
have nothing for a blocked or denied action, which a capsule records.

## From executor evidence to a capsule

Decionis exports a capsule from one dossier, so a capsule exists only for a dossier Decionis holds;
a run against `LocalAuthority`, which tests use, has none. Every evidence line names the dossier and the intent
([evidence](./evidence.md)), and those are the two joins between the lines and a capsule:

- **`dossier_id`** names the dossier the capsule was exported from.
- **`intent_id`** is the capsule's `action_id`. Decionis binds the execution to the intent id, and
  `DecionisGrantVerifier` claims and finalizes with it as the commit correlation id.

The capsule's other identifiers are the dossier's: `decision_id` is its evaluation id, `epoch_id`
the policy digest or version in its execution binding, and `effect` Decionis's reading of the
commit evidence recorded when the claim was finalized ([claim and finalize](./claim-finalize.md)).
The executor's lines carry none of them, and the capsule names neither the intent hash nor the
grant; the dossier names both.

## The execution profile's record, field by field

The execution profile's issuer is the agent operator: in a deployment of this repository, the
organisation running the executor or the gateway. The table maps the AIR's required fields, and
the optional ones this repository has a value for, onto where that value is recorded.

| AIR field (`-01` §5.3)                         | Where a deployment of this repository records it                                                                                                                                                        |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `record_id`, `session_id`                      | no equivalent. `intent_id` is a random UUID, not the UUIDv7 the draft asks for; `correlation_id` groups runs when the caller sets one                                                                   |
| `action_type`                                  | `action.type`, in the deployment's own vocabulary; the draft's values (`payment_execution`, `configuration_change`, …) or a reverse-DNS name would be a mapping                                         |
| `action_timestamp_ms`                          | `at` on the terminal execution event                                                                                                                                                                    |
| `captured_timestamp_ms`                        | not the intent's `captured_at`: the draft means when the evidence pipeline recorded the finished action, and `captured_at` is when the proposal was captured, before any decision                       |
| `agent_id`, `agent_version`                    | `caller_principal` on the executor's line names who asked; `context.workload` names the software, with its trust source ([workload provenance](./workload-provenance.md))                               |
| `operator_id`, `operator_pubkey_id`            | the deployment's; the executor's evidence key, when `EXECUTOR_EVIDENCE_SIGNING_KEY_FILE` is set, signs exported bundles, not lines                                                                      |
| `input_hash`                                   | not observed. The draft means the raw input to the agent; this repository sees the proposed action, never the agent's input                                                                             |
| `outcome_state`                                | the [execution outcome](../execution-outcomes.md), below                                                                                                                                                |
| `outcome_hash`                                 | `outcome.response_digest` in an adapter's effect evidence; the gateway does not record one                                                                                                              |
| `tool_calls`                                   | one call per governed action: `intent_hash` or `context.body_sha256` in, the response digest out, always a write                                                                                        |
| `jurisdiction`, `retention_class`              | not recorded; deployment constants an exporter would supply                                                                                                                                             |
| `policy_refs`                                  | the policy revision on the decision event, and the policy path an intent states inside its hash ([execution intent](../execution-intent.md))                                                            |
| `external_refs`                                | `dossier_id`, `decision_id`, `grant_id`, the provider's reference on its effect receipt ([Verifying Provider Profile](./verifying-provider.md)): the draft's place for the authorisation record (§10.1) |
| `redaction_receipts`                           | none. The evidence never holds a raw value to redact; it holds identifiers and digests from the start                                                                                                   |
| `principal_id`                                 | the intent's `actor`                                                                                                                                                                                    |
| `intent_attestation`                           | the Presence receipt or provider attestation the dossier records; this package never records the attestation itself ([human approval](../human-approval.md))                                            |
| `delegation_chain`, `auth_context`, `trace_id` | not recorded                                                                                                                                                                                            |

The draft requires at least one redaction receipt for `payment_initiation`, `payment_execution`,
`credit_decision` and the two regulated-data types (§6.4), so an exporter of those types would have
to state that nothing was redacted in a form the draft has no receipt for.

The outcomes map onto `outcome_state` only where something was dispatched:

| Outcome                   | `outcome_state`                                                      |
| ------------------------- | -------------------------------------------------------------------- |
| `COMPLETED`               | `completed`                                                          |
| `DEFINITELY_NOT_EXECUTED` | `failed`                                                             |
| `UNKNOWN_AFTER_DISPATCH`  | `pending_confirmation`, until reconciliation settles it              |
| `FAILED_BEFORE_DISPATCH`  | none: nothing reached the provider                                   |
| `BLOCKED`, `HELD`         | none: nothing was executed, and the draft has no value for a refusal |

A single action has no partial outcome: it committed, it did not, or nobody knows yet. A change
carried out as a governed plan ([ADR 0008](../architecture/decisions/0008-governed-plans.md)) does,
and the state of the plan, derived by the authority from the finalization records of its steps,
maps onto the plan as a whole:

| Plan state  | `outcome_state`                                                                        |
| ----------- | -------------------------------------------------------------------------------------- |
| `COMPLETE`  | `completed`: every ordinary step committed with a confirmed effect                     |
| `PARTIAL`   | `partially_completed`: a step failed after others committed; it stays so once reached  |
| `SUSPENDED` | `pending_confirmation`, until reconciliation settles the step whose outcome is unknown |
| `ACTIVE`    | none: the plan has not finished                                                        |

Each step keeps its own record and its own outcome above; the plan's is a record about the
change, correlated to its steps by `plan_id`. A compensation that committed (a rollback) leaves the
plan `PARTIAL`: compensating restores a state, it does not make the change complete as approved.
`reversed` has no counterpart here.

## Integrity and custody

The two chains are built alike and trusted differently.

- **Both link records by SHA-256 and detect a gap.** The executor's streams carry `seq` and
  `prev_hash` and `agentsafe verify-chain` reports `CHAIN_SEQ_GAP`; the draft carries
  `sequence_number` and `prev_chain_hash` and fails a gap (§5.8). The draft's chain is per agent,
  its chain hash covers the action's timestamp and agent id, and its genesis is sequence 0; the
  executor's chains are per stream, per tenant and per process, and start at 1.
- **The draft signs every record; this repository does not.** An AIR is a COSE_Sign1 under an
  ES256 key the draft requires in an HSM (§11.3). The executor's chain is unkeyed
  ([executor evidence](../executor-evidence.md#what-this-is-not)); a signature covers only an
  exported bundle, and `agentsafe verify bundle` reports `ORIGIN_AND_CONSISTENCY` only against a
  public key the checker supplies ([incident response](../incident-response.md)).
- **An unrecorded action.** The draft notes that an action never recorded leaves no gap (§11.5).
  The executor, and the gateway with evidence enabled, record under `REQUIRE_BEFORE_EXECUTION`:
  nothing is dispatched unless the events up to the start of execution were written
  ([audit events](../audit-events.md)). A terminal event that fails to write after dispatch leaves
  the action recorded as started, never as absent.
- **Custody is a trust assumption.** The draft's guarantees hold only while the Transparency
  Service is independent of the operator; if one party runs both, they are void (§11.2(a)). The
  lines this repository writes are the operator's own, kept wherever the operator sends them. The
  Decision Dossier is a record another party keeps, signed with that party's key and verifiable
  offline ([Decision Dossiers](../decision-dossiers.md)); it is independent of the operator's
  lines, not of Decionis.

## What this page does not claim

That this repository produces or consumes a capsule or an AIR, that either draft is a standard,
or that the mapping above is the one either draft's authors would choose. Field names are pinned to
the revisions named at the top; a later revision may change them.
