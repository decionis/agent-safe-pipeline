# GitHub deploy agent

Staging deploys are allowed, production deploys require escalation, and force-push is blocked. Only staging receives a grant and reaches the trusted handler.

```bash
pnpm --filter @decionis/agent-safe-example-github-deploy demo
```

This example is synthetic and performs no GitHub request.

`DECIONIS_HOSTED=1` (or `DECIONIS_API_KEY` with `DECIONIS_TENANT_ID`) has Decionis evaluate each intent beside the fixture; with no key, the run mints a free provisional workspace and stores its key for the next run. The run ends with one block per proposal: the signed record, its verification page when the authority attaches one, and how to verify it offline. In a workflow, the same records are appended to `GITHUB_STEP_SUMMARY`. Unset, nothing changes.
