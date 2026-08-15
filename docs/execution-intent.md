# Execution intent

The versioned `agent-safe.intent/1` authority binding contains protocol version, tenant, intent ID,
idempotency key, capture/expiry timestamps, actor, action/resource/parameters, context, and downstream
target. Keys are lexicographically sorted before JSON encoding and SHA-256 hashing.

Canonicalization is bounded to 100 KiB by default, nesting depth 20, 5,000 object entries, and arrays of 1,000 values. `__proto__`, `prototype`, and `constructor` keys are rejected. Numbers must be finite JSON numbers.

The trusted runtime, not the agent, supplies the idempotency key and correlation ID. The idempotency
key is part of the canonical authorization binding and is also sent as the authority request's
idempotency header. The correlation ID remains operational metadata and must not affect execution
semantics.
