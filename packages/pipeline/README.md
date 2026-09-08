# `@decionis/agent-safe-pipeline`

TypeScript reference implementation of Agent-Safe Pipeline, the Execution Authority architecture: capture an immutable agent proposal, obtain an independent Decionis decision, coordinate Presence escalation, and execute only through an intent-bound single-use grant and sealed trusted handler registry.

## Install

Install the latest stable release:

```bash
npm install @decionis/agent-safe-pipeline
```

To evaluate this prerelease explicitly:

```bash
npm install @decionis/agent-safe-pipeline@0.1.3-rc.2
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

| Outcome                           | Execution behavior                                  |
| --------------------------------- | --------------------------------------------------- |
| ALLOW plus valid single-use grant | Consume grant, then invoke registered handler       |
| ESCALATE                          | Stop; resolve direct or managed Presence escalation |
| BLOCK or any error/mismatch       | Fail closed; do not invoke handler                  |

Every outcome that consumed a grant also reports `finalization` (`RECORDED`, `PENDING`, or
`UNSUPPORTED`): the executor records COMMITTED, FAILED, or INDETERMINATE with Decionis after the
attempt so commit evidence joins the Decision Dossier chain. Finalization never changes the outcome.

Presence transport/schema failures and Decionis reauthorization failures return stable fail-closed
decisions; raw downstream error text is never part of the coordinator result.

For Decionis-managed Presence, pass constraints outside the canonical intent and then poll Decionis
only:

```ts
const pending = await gate.evaluate(captured, undefined, {
  escalation: {
    mode: "MANAGED",
    approver: { principal_id: approverId, role_id: "APPROVER" },
    verification_requirements: { methods: ["WEBAUTHN"] },
  },
});
const authorized = await gate.waitForAuthorization(captured, pending, { signal });
const result = await executor.run(captured, authorized);
```

An initial managed result remains `ESCALATE`, carries `managedEscalation`, has no authorization, and
cannot execute. `waitForAuthorization` uses capped exponential backoff with bounded jitter and stops
at the intent or escalation expiry. It returns a normal ALLOW grant only after Decionis verifies the
Presence evidence and re-evaluates current policy. The executor never needs Presence credentials and
does not send managed Presence evidence during claim. The existing `PresenceApprovalCoordinator`
continues to support developer-controlled DIRECT mode.

To measure before enforcing, wrap an existing execution with `ShadowPipeline` over a gate built
with `mode: "SHADOW"`. Production runs unchanged and returns immediately; the observation is
bounded, never rejects, carries no grant, and is refused by `SafeExecutor`. See
[shadow mode](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/shadow-mode.md).

Support: use [GitHub private vulnerability reporting](https://github.com/decionis/agent-safe-pipeline/security/advisories/new) or `security@decionis.com` for vulnerabilities and [GitHub Issues](https://github.com/decionis/agent-safe-pipeline/issues) for non-sensitive problems. Architecture: [Agent-Safe Pipeline README](https://github.com/decionis/agent-safe-pipeline#readme). Research: [The Execution Verifiability Gap](https://decionis.com/research/execution-verifiability-gap) (Decionis Research). License: Apache-2.0. Trademark terms: [TRADEMARKS.md](https://github.com/decionis/agent-safe-pipeline/blob/master/TRADEMARKS.md).
