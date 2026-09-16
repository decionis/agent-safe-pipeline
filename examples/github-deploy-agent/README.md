# GitHub deploy agent

Staging deploys are allowed, production deploys require escalation, and force-push is blocked. Only staging receives a grant and reaches the trusted handler.

```bash
pnpm --filter @decionis/agent-safe-example-github-deploy demo
```

This example is synthetic and performs no GitHub request.

With `DECIONIS_API_KEY` and `DECIONIS_TENANT_ID` set, Decionis evaluates each intent beside the fixture and the run ends with one block per proposal naming the signed record. In a workflow, the same records are appended to `GITHUB_STEP_SUMMARY`. Unset, nothing changes.
