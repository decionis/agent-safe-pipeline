# Execution intent

The versioned `agent-safe.intent/1` authority binding is exactly the Decionis `ExecutionIntentBinding`
contract: `protocol_version`, `tenant_id`, `intent_id`, `captured_at`, `expires_at`, `actor`,
`action` (type, resource, parameters), `context`, and `downstream_target` (system, operation, optional
environment and endpoint). The contract rejects any other top-level property. Keys are sorted by UTF-16
code unit before JSON encoding and SHA-256 hashing, which is how Decionis recomputes the hash on
receipt.

Input validation and canonicalization are bounded to 100 KiB by default, nesting depth 20, 5,000
entries, and arrays of 1,000 values. Cycles, non-JSON object prototypes, `__proto__`, `prototype`, and
`constructor` keys are rejected before recursive schema parsing. Numbers must be finite JSON numbers.

The trusted runtime, not the agent, supplies the idempotency key and correlation ID. The idempotency
key stays part of the canonical binding by riding inside the trusted `context` under the reserved
`idempotency_key` entry; `IntentCapture` rejects a caller-supplied context key of that name. The
authority request's `Idempotency-Key` header carries the `intent_id`, because the contract defines the
intent as the grant-issuance boundary and rejects a header that differs from it. The correlation ID
remains operational metadata and must not affect execution semantics.
