# Procurement agent

This synthetic example requests a USD 4,800 software purchase against a USD 5,000 remaining budget for four concurrent users. Two existing tools still have combined capacity for five concurrent users, so the procurement-facing decision is `HOLD` for a utilization review.

```bash
pnpm --filter @decionis/agent-safe-example-procurement demo
```

`HOLD` maps to the pipeline's `ESCALATE` enforcement verdict. The decision carries no execution grant, so the purchase handler does not run. The example performs no procurement or vendor network request.
