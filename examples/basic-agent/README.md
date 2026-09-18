# Basic agent

An agent proposes deleting a synthetic customer. Independent policy returns BLOCK, so the registered handler cannot run.

```bash
pnpm --filter @decionis/agent-safe-example-basic demo
```

The fixture authority is forbidden when `NODE_ENV=production`. Replace it with `DecionisGate` and `DecionisGrantVerifier` for a real deployment.

`DECIONIS_HOSTED=1` (or `DECIONIS_API_KEY` with `DECIONIS_TENANT_ID`) has Decionis evaluate the same intent beside the fixture; with no key, the run mints a free provisional workspace and stores its key for the next run. The run ends with the signed Decision Dossier it left, its verification page when the authority attaches one, and how to verify it offline. Unset, nothing changes.
