# Architecture

Agent-Safe Pipeline separates proposal, authorization, and execution. The agent is outside the trusted computing base.

```text
Untrusted                              Trusted control plane

Agent proposal                         runtime identity/config
     |                                         |
     +--------------> IntentCapture <----------+
                            |
                    canonical intent hash
                            |
                       DecionisGate
                     /      |       \
                 ALLOW  ESCALATE   BLOCK
                   |        |         |
                   |     Presence     stop
                   |        |
                   |  verified receipt
                   |        |
                   +--- Decionis re-evaluation
                            |
                     single-use grant
                            |
                       SafeExecutor
                            |
                sealed trusted ActionRegistry
                            |
                    downstream credential
```

## Components

`IntentCapture` validates the limited agent proposal separately from trusted context, assigns UUID/timestamps, applies a maximum five-minute lifetime, canonicalizes sorted-key JSON, and hashes the authority binding with SHA-256.

`DecionisGate` sends exactly the Decionis `ExecutionAuthorityRequest` contract to the authenticated authority API: the nine-property intent binding, its hash, the evaluation mode, optional direct Presence evidence, and optional managed-escalation constraints outside the canonical intent, with the `Idempotency-Key` header equal to the intent ID. It requires HTTPS except for an explicitly enabled loopback development endpoint, applies a finite timeout and response-size limit, parses the documented decision shape strictly, and converts every ambiguous state to a fail-closed BLOCK. A managed ESCALATE response is grant-free; the gate polls Decionis only, checks escalation ID, intent ID, action hash, expiry, and monotonic pending state, and accepts only a normal ALLOW grant in `GRANT_READY` before the original intent expires.

`PresenceApprovalCoordinator` presents the action, target, and intent hash to the human. Only a terminal receipt dossier is accepted as evidence. The coordinator sends that evidence back to Decionis; it never turns approval into ALLOW itself.

These are complementary integration levels. DIRECT keeps Presence request creation and polling in the
trusted executor through `PresenceApprovalCoordinator`. MANAGED keeps those operations inside
Decionis and exposes only secret-free lifecycle status through `DecionisGate`. Presence still signs
its own evidence independently in both modes; delivery of an opaque invitation is not authority.

`SafeExecutor` checks ALLOW, exact intent binding, and the existence of a grant. Its verifier atomically claims the grant before a registered handler can run, and after the attempt the executor finalizes the outcome with the authority as commit evidence that can never alter the result. A handler is registered by trusted application startup code and the registry is sealed before use. The handler's one-shot provider-dispatch boundary distinguishes a definite pre-dispatch failure from an unknown post-dispatch outcome; read-only reconciliation uses the intent-bound idempotency key and never retries a side effect. See [execution outcomes](./docs/execution-outcomes.md).

`AuditRecorder` sends deeply immutable, bounded, redacted lifecycle events to a consumer sink. It correlates intent, decision, dossier, grant, policy-revision, and execution evidence without copying raw parameters, provider results, credentials, or execution tokens. Its sink policy can preserve availability or require evidence before dispatch, but a sink failure can never allow a blocked action or cause duplicate execution. See [audit events](./docs/audit-events.md).

`ShadowPipeline` runs an existing execution unchanged while asking a `SHADOW`-mode authority what it would have decided. The observation is bounded by its own timeout, never rejects, and cannot delay or fail production. It has no `authorization` field, is marked `mode: "SHADOW"` and `authority: "OBSERVATIONAL"`, discards any grant an authority returns, and is refused by `SafeExecutor` with `DECISION_NOT_AUTHORITATIVE`. `ShadowPipeline` refuses an authority that declares `ENFORCEMENT` mode. See [shadow mode](./docs/shadow-mode.md).

## Trust and data boundaries

- The agent controls only `action`, `target`, and JSON `parameters`.
- The runtime controls tenant, actor identity, target system/operation, idempotency key, and credentials.
- Decionis controls policy decisions and execution grants.
- Presence controls human-verification evidence, not execution authorization.
- The executor controls handler selection and downstream secrets.

## Contract ownership

`agent-safe.intent/1` is the portable binding format. The AgentSafe package is the TypeScript reference implementation. The public Decionis OpenAPI contract defines authority and grant-redemption transport. Any cross-repository change must update tests and discovery documents together.
