# Shopify refund agent

This synthetic example encodes the reference thresholds: up to $100 ALLOW, $100–$1,000 ESCALATE, and over $1,000 BLOCK. It demonstrates that a Presence receipt goes back to the authority for re-evaluation before execution.

```bash
pnpm --filter @decionis/agent-safe-example-shopify-refund demo
```

No Shopify network call or real credential is used. A production handler should hold the narrow Shopify credential behind the executor and send a provider idempotency key.

`DECIONIS_HOSTED=1` (or `DECIONIS_API_KEY` with `DECIONIS_TENANT_ID`) has Decionis evaluate the same intent beside the fixture; with no key, the run mints a free provisional workspace and stores its key for the next run. The synthetic Presence receipt cannot be verified by a real authority, so the re-evaluation is recorded as fail-closed on the hosted side while the fixture still governs; the first evaluation's ESCALATE leaves a signed record, and the run ends with it. Unset, nothing changes.
