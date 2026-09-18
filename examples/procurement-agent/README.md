# Procurement agent

This synthetic example requests a USD 4,800 software purchase against a USD 5,000 remaining budget for four concurrent users. Two existing tools still have combined capacity for five concurrent users, so the procurement-facing decision is `HOLD` for a utilization review.

```bash
pnpm --filter @decionis/agent-safe-example-procurement demo
```

`HOLD` maps to the pipeline's `ESCALATE` enforcement verdict. The decision carries no execution grant, so the purchase handler does not run. The example performs no procurement or vendor network request.

`DECIONIS_HOSTED=1` (or `DECIONIS_API_KEY` with `DECIONIS_TENANT_ID`) has Decionis evaluate the same intent beside the fixture; with no key, the run mints a free provisional workspace and stores its key for the next run. The run ends with the signed Decision Dossier it left, its verification page when the authority attaches one, and how to verify it offline. Unset, nothing changes.
