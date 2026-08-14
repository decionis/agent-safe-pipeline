# Basic agent

An agent proposes deleting a synthetic customer. Independent policy returns BLOCK, so the registered handler cannot run.

```bash
pnpm --filter @decionis/agent-safe-example-basic demo
```

The fixture authority is forbidden when `NODE_ENV=production`. Replace it with `DecionisGate` and `DecionisGrantVerifier` for a real deployment.
