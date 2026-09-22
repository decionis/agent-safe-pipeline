# ExecutionBinding

The intent the gateway captures is the same `agent-safe.intent/1` contract the library and the
executor use ([execution intent](../execution-intent.md)), and what Decionis binds its decision
and its grant to. This page says what the HTTP ingress puts in it, and what that binding
guarantees on the way out.

## What is bound

| Intent field                                                       | From an intercepted request                                                                                                                  |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `action.type`                                                      | the route's action, or `http.<method>`                                                                                                       |
| `action.resource`                                                  | `<METHOD> <path>`                                                                                                                            |
| `action.parameters`                                                | `method`, `path`, `query`, and `body` when it is JSON within the embedding limit                                                             |
| `context.body_sha256`                                              | SHA-256 over the raw bytes, embedded or not                                                                                                  |
| `context.body_bytes`                                               | their length                                                                                                                                 |
| `context.content_type`, `context.body_embedded`, `context.ingress` | what kind of body, whether policy can see its fields, `http`                                                                                 |
| `context.claimed_principal`                                        | the configured principal header's value, unverified, when present                                                                            |
| `context.idempotency_key`                                          | the client's `Idempotency-Key`, else a fresh one                                                                                             |
| `context.enforcement_boundary`                                     | which boundary captured it: id, versions, deployment type, environment, stable placement ([enforcement boundary](./enforcement-boundary.md)) |
| `context.workload`                                                 | what software proposed it, when a runtime declared one, with its trust source ([workload provenance](./workload-provenance.md))              |
| `actor`, `tenant_id`                                               | the configuration's actor and the key's organization                                                                                         |
| `downstream_target`                                                | the upstream as `system`, the action as `operation`, the configured `environment`, the upstream URL as `endpoint`                            |
| `expires_at`                                                       | `intentTtlSeconds` after capture, at most 300 seconds                                                                                        |

Request headers are not bound: a credential to the upstream is the client's business with the
upstream and never reaches the authority or the evidence. The canonical form is RFC 8785 over the
binding, hashed with SHA-256 by `CanonicalIntentHasher`; the [conformance vectors](../../conformance)
pin it, and the intent hash is what every later record names.

## What the binding guarantees

- **The decision is about this request.** `DecionisGate` refuses a decision whose `action_hash` is
  not the captured hash, and `SafeExecutor` refuses to run a decision whose hash is not the
  intent's (`INTENT_BINDING_MISMATCH`).
- **The forwarded bytes are the bound bytes.** The forwarding handler holds the raw request beside
  the intent and, before the point of no return, recomputes the digest of what it is about to send
  and compares it, with the method and the path, to what the intent bound; a mismatch fails before
  dispatch. `SafeExecutor` re-checks the intent's own conformance immediately before the handler
  runs.
- **The boundary is the one that admitted it.** The enforcement boundary is inside the canonical
  bytes, so an authority issued at one boundary is bound to an intent naming that boundary, and
  `SafeExecutor` refuses one captured elsewhere with `BOUNDARY_MISMATCH` before the claim.
- **The workload is the one that proposed it.** Where a workload identity is bound, the
  artifact's digest is inside the canonical bytes, and an executor given its own digest
  refuses an intent proposed by another with `WORKLOAD_MISMATCH` before the claim.
- **A stale authorization does nothing.** The intent expires; a grant is bound to the intent's
  expiry and refused after it; a decision is refused for an intent that expired before evaluation.
- **Policy-version drift is visible.** The Decision Dossier records the policy version the decision
  was made under; a resume after an escalation is a fresh evaluation under current policy, never a
  replay of the old one.

## What it does not guarantee

That the upstream's business effect matches the request's intent beyond the bytes sent: the
gateway observes the upstream's status, not its ledger. The trusted executor's banking adapters
add an effect plane for that ([BEAP conformance](../beap-conformance.md)); the gateway does not.
