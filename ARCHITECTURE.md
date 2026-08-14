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

`DecionisGate` sends the exact binding to the authenticated Decionis authority API. It requires HTTPS except for an explicitly enabled loopback development endpoint, applies a finite timeout and response-size limit, and converts every ambiguous state to a fail-closed BLOCK.

`PresenceApprovalCoordinator` presents the action, target, and intent hash to the human. Only a terminal receipt dossier is accepted as evidence. The coordinator sends that evidence back to Decionis; it never turns approval into ALLOW itself.

`SafeExecutor` checks ALLOW, exact intent binding, and the existence of a grant. Its verifier atomically consumes the grant before a registered handler can run. A handler is registered by trusted application startup code and the registry is sealed before use.

`ShadowPipeline` observes existing execution and obtains a hypothetical authority decision without granting the shadow result execution authority. Its output is labeled `SHADOW` to prevent accidental enforcement claims.

## Trust and data boundaries

- The agent controls only `action`, `target`, and JSON `parameters`.
- The runtime controls tenant, actor identity, target system/operation, idempotency key, and credentials.
- Decionis controls policy decisions and execution grants.
- Presence controls human-verification evidence, not execution authorization.
- The executor controls handler selection and downstream secrets.

## Contract ownership

`agent-safe.intent/1` is the portable binding format. The AgentSafe package is the TypeScript reference implementation. The public Decionis OpenAPI contract defines authority and grant-redemption transport. Any cross-repository change must update tests and discovery documents together.
