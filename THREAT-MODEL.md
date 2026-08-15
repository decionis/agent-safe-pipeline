# Threat model

## Assets

- Downstream privileged credentials and irreversible actions.
- Tenant and actor identity.
- Policy decisions, Presence receipts, and Decision Dossiers.
- Intent integrity, grant uniqueness, and audit evidence.

## Adversaries and assumptions

The agent, its prompt, retrieved content, tool arguments, and model output are untrusted. The host running `IntentCapture`, `DecionisGate`, `SafeExecutor`, and registered handlers is trusted and must be isolated from the agent. Decionis and Presence service identities are independently authenticated.

Compromise of the trusted executor host or downstream provider is outside what this library alone can prevent. The design reduces that host's exposed interface and makes authorization evidence independently verifiable.

## Threats and controls

| Threat                                           | Control                                                                        | Residual risk                                                                              |
| ------------------------------------------------ | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| Prompt injection asks the agent to ignore policy | Gate is outside the prompt and independently decides                           | A developer can still bypass the architecture                                              |
| Agent changes tool arguments after approval      | Exact canonical parameters and target bind to the intent hash                  | Non-deterministic downstream interpretation must be avoided                                |
| Approval for action A is swapped onto action B   | Presence display and receipt bind the exact hash; Decionis re-verifies         | Presence integration must preserve immutable fields                                        |
| Old approval or grant is replayed                | Short expiry, hash-bound idempotency key, `jti`, and atomic single-use consume | A downstream timeout after consume needs a fresh decision or provider idempotency recovery |
| Agent calls the provider directly                | Provider credential and egress live behind the executor                        | Network policy must actually prevent agent egress                                          |
| Agent chooses arbitrary code to run              | Sealed action registry; no agent-supplied callback                             | Trusted registration code remains security-critical                                        |
| Authority is unavailable or malformed            | Timeout, bounded response, strict validation, fail closed                      | Reduced availability is accepted over unauthorized execution                               |
| JSON ambiguity or prototype pollution            | Strict schemas, forbidden keys, bounded canonical JSON, exact SHA-256 binding  | Cross-language canonicalization requires conformance tests                                 |
| Human approves misleading content                | Action, target, and exact hash are mandatory display fields                    | A human can still make a poor but authentic decision                                       |
| Shadow result is mistaken for authorization      | Separate `SHADOW` result type and no execution grant                           | Consumer logs/UI must preserve the label                                                   |

## Credential architecture

Unsafe:

```text
agent runtime: model key + Decionis key + provider admin token
```

Required:

```text
agent runtime -> proposal -> trusted executor: Decionis key + provider admin token
```

The agent runtime should have denied-by-default network egress. Open only the proposal channel to the executor. Give each handler the narrowest provider scope possible and use provider-side idempotency keys.

## Security invariants worth testing

- Changing any bound field, including the idempotency key, invalidates authorization.
- Exactly one of 100 concurrent consume attempts can execute.
- ALLOW without a grant cannot execute.
- Presence approval alone cannot execute.
- Production cannot instantiate fixture authority or verifier.
- Authority outage, timeout, oversized response, and invalid JSON all block.

## Accepted risks

These risks are accepted for the reference library rather than silently presented as mitigated. The Decionis maintainers own them and review the table before every stable release or when the trust boundary changes.

| Accepted risk                                              | Rationale                                                                        | Required compensating control                                                                             | Review trigger                                          |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| A trusted executor host can bypass the library             | Host compromise cannot be solved inside an in-process package                    | Isolate the executor, deny agent egress, restrict provider credentials, and monitor direct provider calls | Executor deployment or credential architecture changes  |
| Authority failure reduces availability                     | Failing open would permit unauthorized execution                                 | Fail closed and require a fresh decision after recovery                                                   | Availability target or timeout policy changes           |
| A human can approve misleading but correctly bound content | Cryptographic binding proves what was approved, not that the judgment was wise   | Display the exact action, target, amount, and hash; apply policy limits before escalation                 | Approval UX or Presence receipt schema changes          |
| Cross-language canonicalization can drift                  | Multiple implementations may encode otherwise equivalent JSON differently        | Keep the published conformance vector and require contract tests in every implementation                  | Protocol or canonicalization changes                    |
| In-memory replay protection is process-local               | The implementation is a development primitive, not a distributed consume service | Production uses the authority's atomic consume endpoint and provider idempotency                          | Any proposal to use `InMemoryReplayStore` in production |
