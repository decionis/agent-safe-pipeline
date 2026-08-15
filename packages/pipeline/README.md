# `@decionis/agent-safe-pipeline`

TypeScript reference implementation of Agent-Safe Pipeline: capture an immutable agent proposal, obtain an independent Decionis decision, coordinate Presence escalation, and execute only through an intent-bound single-use grant and sealed trusted handler registry.

## Install

The package is versioned `0.1.2` but is not claimed as published until a registry release succeeds. Consume it from the workspace today:

```bash
pnpm install --frozen-lockfile
```

Production credentials belong in the trusted executor process, never the agent runtime:

```text
DECIONIS_API_URL=https://api.decionis.com
DECIONIS_API_KEY=server-side-secret
```

```ts
import {
  ActionRegistry,
  DecionisGate,
  DecionisGrantVerifier,
  IntentCapture,
  SafeExecutor,
} from "@decionis/agent-safe-pipeline";
import { z } from "zod";

const gate = new DecionisGate({
  baseUrl: process.env.DECIONIS_API_URL!,
  apiKey: process.env.DECIONIS_API_KEY!,
});
const captured = new IntentCapture().capture(agentProposal, trustedServerContext);
const registry = new ActionRegistry()
  .register("refund_order", {
    parametersSchema: z.object({ orderId: z.string(), amountMinor: z.number().int() }).strict(),
    execute: ({ parameters }) => shopify.refund(parameters),
  })
  .seal();
const executor = new SafeExecutor(
  registry,
  new DecionisGrantVerifier({
    baseUrl: process.env.DECIONIS_API_URL!,
    apiKey: process.env.DECIONIS_API_KEY!,
  }),
);
const result = await executor.run(captured, await gate.evaluate(captured));
```

| Outcome                           | Execution behavior                                   |
| --------------------------------- | ---------------------------------------------------- |
| ALLOW plus valid single-use grant | Consume grant, then invoke registered handler        |
| ESCALATE                          | Stop; obtain Presence receipt and ask Decionis again |
| BLOCK or any error/mismatch       | Fail closed; do not invoke handler                   |

Presence transport/schema failures and Decionis reauthorization failures return stable fail-closed
decisions; raw downstream error text is never part of the coordinator result.

Support: use [GitHub private vulnerability reporting](https://github.com/decionis/agent-safe-pipeline/security/advisories/new) or `security@decionis.com` for vulnerabilities and [GitHub Issues](https://github.com/decionis/agent-safe-pipeline/issues) for non-sensitive problems. Architecture: [Agent-Safe Pipeline README](https://github.com/decionis/agent-safe-pipeline#readme). License: Apache-2.0. Trademark terms: [TRADEMARKS.md](https://github.com/decionis/agent-safe-pipeline/blob/master/TRADEMARKS.md).
