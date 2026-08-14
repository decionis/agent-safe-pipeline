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

| Threat                                           | Control                                                                       | Residual risk                                                                              |
| ------------------------------------------------ | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Prompt injection asks the agent to ignore policy | Gate is outside the prompt and independently decides                          | A developer can still bypass the architecture                                              |
| Agent changes tool arguments after approval      | Exact canonical parameters and target bind to the intent hash                 | Non-deterministic downstream interpretation must be avoided                                |
| Approval for action A is swapped onto action B   | Presence display and receipt bind the exact hash; Decionis re-verifies        | Presence integration must preserve immutable fields                                        |
| Old approval or grant is replayed                | Short expiry, `jti`, idempotency key, and atomic single-use consume           | A downstream timeout after consume needs a fresh decision or provider idempotency recovery |
| Agent calls the provider directly                | Provider credential and egress live behind the executor                       | Network policy must actually prevent agent egress                                          |
| Agent chooses arbitrary code to run              | Sealed action registry; no agent-supplied callback                            | Trusted registration code remains security-critical                                        |
| Authority is unavailable or malformed            | Timeout, bounded response, strict validation, fail closed                     | Reduced availability is accepted over unauthorized execution                               |
| JSON ambiguity or prototype pollution            | Strict schemas, forbidden keys, bounded canonical JSON, exact SHA-256 binding | Cross-language canonicalization requires conformance tests                                 |
| Human approves misleading content                | Action, target, and exact hash are mandatory display fields                   | A human can still make a poor but authentic decision                                       |
| Shadow result is mistaken for authorization      | Separate `SHADOW` result type and no execution grant                          | Consumer logs/UI must preserve the label                                                   |

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

- Changing any bound field invalidates authorization.
- Exactly one of 100 concurrent consume attempts can execute.
- ALLOW without a grant cannot execute.
- Presence approval alone cannot execute.
- Production cannot instantiate fixture authority or verifier.
- Authority outage, timeout, oversized response, and invalid JSON all block.
