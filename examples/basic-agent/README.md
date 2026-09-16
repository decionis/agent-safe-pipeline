# Basic agent

An agent proposes deleting a synthetic customer. Independent policy returns BLOCK, so the registered handler cannot run.

```bash
pnpm --filter @decionis/agent-safe-example-basic demo
```

The fixture authority is forbidden when `NODE_ENV=production`. Replace it with `DecionisGate` and `DecionisGrantVerifier` for a real deployment.

With `DECIONIS_API_KEY` and `DECIONIS_TENANT_ID` set, Decionis evaluates the same intent beside the fixture and the run ends with the identifier of the signed record it left, and how to verify it. Unset, nothing changes.
