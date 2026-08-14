# Shopify refund agent

This synthetic example encodes the reference thresholds: up to $100 ALLOW, $100–$1,000 ESCALATE, and over $1,000 BLOCK. It demonstrates that a Presence receipt goes back to the authority for re-evaluation before execution.

```bash
pnpm --filter @decionis/agent-safe-example-shopify-refund demo
```

No Shopify network call or real credential is used. A production handler should hold the narrow Shopify credential behind the executor and send a provider idempotency key.
