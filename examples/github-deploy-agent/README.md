# GitHub deploy agent

Staging deploys are allowed, production deploys require escalation, and force-push is blocked. Only staging receives a grant and reaches the trusted handler.

```bash
pnpm --filter @decionis/agent-safe-example-github-deploy demo
```

This example is synthetic and performs no GitHub request.
