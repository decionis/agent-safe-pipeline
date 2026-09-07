# Redacted lifecycle audit events

`AuditRecorder` provides one versioned integration point for intent capture, authority decisions,
Presence evidence, grant consumption, execution, ambiguous outcomes, and reconciliation. Events use
schema `agent-safe.audit/1`, are deeply frozen before delivery, and contain bounded correlation and
evaluation references rather than raw business payloads.

## Event contract

Every event contains an event ID and timestamp; an explicit `AUTHORITATIVE`, `OBSERVATIONAL`, or
`NON_AUTHORITATIVE` classification; intent and optional correlation IDs; bounded reason codes and
duration; and empty-by-default metadata. Decision events also carry the verdict, decision and
dossier IDs, an evaluation ID, a material-input digest, and an optional immutable policy revision.
Grant and execution events add the consumed grant ID. They never include execution tokens, API
keys, raw intent parameters or context, raw targets, or provider results.

An observational event remains observational after JSON serialization. Its shape is an audit
record, not a `GateDecision`, and `SafeExecutor` rejects it with `DECISION_NOT_AUTHORITATIVE` if
application code attempts an unsafe cast. `ShadowPipeline` emits `SHADOW_EVALUATED`, which is
always `OBSERVATIONAL`; the recorder refuses a shadow event with any other classification and
refuses any observational event that references a grant. Presence events are `NON_AUTHORITATIVE`:
a human receipt is evidence for Decionis re-evaluation, never execution authority.

## Sink configuration

```ts
const audit = new AuditRecorder({
  sink: {
    write: async (event) => securityEventQueue.send(event),
  },
  timeoutMs: 100,
  failurePolicy: "BEST_EFFORT",
  metadataAllowlist: ["deployment_region"],
});

const executor = new SafeExecutor(registry, verifier, audit);
```

Each event gets one bounded sink attempt. Exceptions and timeouts are converted to a failed
delivery and are never retried by the library, so sink health cannot reorder events or duplicate a
provider action. `BEST_EFFORT` preserves execution availability. `REQUIRE_BEFORE_EXECUTION` blocks
before grant consumption if initial evidence cannot be recorded, and stops after consumption but
before provider dispatch if grant or execution-start evidence cannot be recorded. A post-dispatch
sink failure never changes or retries the provider outcome.

`SafeExecutor` emits this order when the applicable stages occur:

```text
INTENT_CAPTURED
  -> AUTHORITY_DECISION | AUTHORITY_FAILED_CLOSED
  -> EXECUTION_BLOCKED
     or GRANT_CONSUMED -> EXECUTION_STARTED
          -> EXECUTION_COMPLETED
             | EXECUTION_FAILED_BEFORE_DISPATCH
             | EXECUTION_OUTCOME_UNKNOWN
  -> RECONCILIATION_COMPLETED
     | RECONCILIATION_NOT_EXECUTED
     | RECONCILIATION_UNKNOWN
```

`PresenceApprovalCoordinator` emits `PRESENCE_ESCALATED` and `PRESENCE_RESOLVED` with
`NON_AUTHORITATIVE` classification. `ShadowPipeline` emits one `SHADOW_EVALUATED` event per
observation whose reason codes begin with `SHADOW_<status>`; see [shadow mode](./shadow-mode.md). `IntentCapture.captureAndAudit` is available when capture must be
recorded even if the caller never reaches `SafeExecutor`; avoid using both automatic paths if the
sink treats two capture observations as duplicates.

## Metadata and redaction

Consumer metadata is dropped unless its top-level key is explicitly allowlisted. Keys suggesting
tokens, credentials, passwords, secrets, authorization, raw parameters/context, or provider results
are always excluded even if listed. An optional redaction hook may replace or omit remaining values.
The post-redaction object is limited to 4 KiB, depth four, 50 entries, arrays of 20, and strings of
500 characters. Invalid metadata fails that event delivery; it never relaxes an authorization
decision.

## Policy revision and evidence retention

An authority-decision event may attach `{policyId, revisionId, version, digest}`. `revisionId` must
be immutable; aliases such as `current` and `latest` are rejected. The digest commits to the exact
evaluation semantics without copying confidential policy rules into the audit stream. The event
also commits to the material input digest and points to the Decision Dossier as evidence when one is
available.

Once a revision has participated in an authoritative decision, do not mutate it in place. A hotfix
creates a new revision identity and digest. Keep the referenced revision or an immutable archival
representation for at least as long as dependent authoritative evidence is retained:

```text
retained authoritative evidence => verifiable referenced policy revision
```

Before deleting a live revision, verify that every retained event can resolve an archived policy
artifact whose digest matches the event. Historical replay must select the pinned revision, never
the current alias. Missing artifacts or digest mismatches are evidence-retention failures, not a
reason to reinterpret the historical decision using new policy.

`AuditPolicyRevisionVerifier` performs that bounded lookup through a consumer-supplied resolver and
reports `VERIFIED`, `MISSING`, `DIGEST_MISMATCH`, `IDENTITY_MISMATCH`, `UNAVAILABLE`, or
`NOT_REFERENCED`. A verified result returns the exact archived artifact reference selected by the
event's policy and revision IDs for an authorized replay system.

The audit record is reproducible evidence, not necessarily self-contained evidence: an authorized
verifier combines its commitments with retained policy and dossier artifacts. Confidential rules
and evaluation inputs do not need to be duplicated into each event.
