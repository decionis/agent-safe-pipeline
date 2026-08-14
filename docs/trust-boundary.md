# Trust boundary

The agent is untrusted even when it runs in the same process. For meaningful enforcement, deploy the executor in a separate service or runtime boundary and prevent agent egress to downstream APIs.

Agent-controlled fields:

- action name
- resource target
- JSON parameters

Trusted fields:

- tenant and actor identity
- runtime identity and trust level
- downstream system, operation, and endpoint
- idempotency key and credentials
- registered handler and parameter schema

Do not copy identity, tenant, role, endpoint, authorization headers, or approval evidence out of model output. Resolve them from authenticated server context.
