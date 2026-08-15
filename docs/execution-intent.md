# Execution intent

The versioned `agent-safe.intent/1` authority binding contains protocol version, tenant, intent ID, capture/expiry timestamps, actor, action/resource/parameters, context, and downstream target. Keys are lexicographically sorted before JSON encoding and SHA-256 hashing.

Input validation and canonicalization are bounded to 100 KiB by default, nesting depth 20, 5,000
entries, and arrays of 1,000 values. Cycles, non-JSON object prototypes, `__proto__`, `prototype`, and
`constructor` keys are rejected before recursive schema parsing. Numbers must be finite JSON numbers.

The idempotency key and correlation ID are operational metadata on the captured intent; the idempotency key is sent separately to the authority. They are not controlled by the agent.
