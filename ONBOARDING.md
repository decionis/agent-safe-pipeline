# Onboarding

The adopter's journey through this repository, packaged once and walked four times. The shape is
the same whatever the workflow: install, capture the first intent, get a verdict, resolve an
approval, hold a grant, execute once, keep the outcome and its evidence. Each family below points
at the example that already runs that journey and at the live property that owns the workflow.
Nothing here is a new capability; it is the order in which to meet the ones that exist.

Read [EVALUATION-PATH.md](./EVALUATION-PATH.md) first if you are deciding whether to adopt at all;
this page is for once you have decided to try.

## The journey

| Step            | What you do                                                                                                                                    | Where it is defined                                                                                          |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| 1. Install      | `npm install @decionis/agent-safe-pipeline`; the `latest` dist-tag is the supported release                                                    | [packages/pipeline/README.md](./packages/pipeline/README.md)                                                 |
| 2. Capture      | The agent proposes action, target and parameters; your host attaches tenant, actor, downstream target and idempotency key from trusted context | [docs/execution-intent.md](./docs/execution-intent.md), [docs/trust-boundary.md](./docs/trust-boundary.md)   |
| 3. Verdict      | The authority returns `ALLOW`, `ESCALATE` or `BLOCK`; in development the fixture authority, in production `DecionisGate`                       | [docs/allow-escalate-block.md](./docs/allow-escalate-block.md)                                               |
| 4. Approval     | On `ESCALATE`, a named person approves this exact intent through Presence; the receipt goes back to the authority, which evaluates again       | [docs/human-approval.md](./docs/human-approval.md), [docs/presence-evidence.md](./docs/presence-evidence.md) |
| 5. Grant        | Only an `ALLOW` carries a short-lived, single-use grant bound to the intent                                                                    | [docs/decision-dossiers.md](./docs/decision-dossiers.md)                                                     |
| 6. Execute once | `SafeExecutor` claims the grant immediately before the registered handler runs; the handler holds the credential, the agent never does         | [ARCHITECTURE.md](./ARCHITECTURE.md)                                                                         |
| 7. Outcome      | `COMPLETED`, `BLOCKED`, `FAILED_BEFORE_DISPATCH` or `UNKNOWN_AFTER_DISPATCH`; an unknown outcome is reconciled, never retried on its own       | [docs/execution-outcomes.md](./docs/execution-outcomes.md)                                                   |
| 8. Evidence     | Every decision leaves a Decision Dossier; every executed result keeps its consumed-grant binding; audit events carry the rest                  | [docs/audit-events.md](./docs/audit-events.md)                                                               |

Before any of it reaches production, run it in shadow mode against the actions you already
execute: [docs/shadow-mode.md](./docs/shadow-mode.md). Shadow mode issues no grant and cannot
block a production action; it tells you what the authority would have decided.

## Four families

Each row names the example that runs the journey for that family, the live property that owns the
workflow, what a green run proves, and what it does not. Every property URL resolved on
2026-09-12; the link probe in `pnpm discovery --check-links` re-checks them.

| Family               | Start with                                                                                                                    | The live property                                                                               | A green run proves                                                                       | It does not prove                                                                         |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| AI agent             | `examples/mcp-tool-gate` (a real stdio MCP server with one governed tool), then `examples/basic-agent`                        | [decionis.com/agents](https://decionis.com/agents)                                              | A tool call the agent proposed reached the executor and was refused or run once          | That your agent framework, host isolation or egress controls are in place                 |
| Commerce             | `packages/commerce-mcp` (`@decionis/commerce`, the Commerce Gate MCP server), then `examples/shopify-refund-agent`            | [commerce.decionis.com](https://commerce.decionis.com)                                          | A price, refund, return or order step was checked against policy before acting           | That a marketplace or ERP connector exists for your platform; the server writes nothing   |
| Banking              | `profiles/beap/v0.1` (the profile, mirrored here), read with `examples/golden-adversarial-demo` for the boundary              | [banking.decionis.com](https://banking.decionis.com) — BEAP v0.1, Draft / Design Partner Review | The boundary the profile builds on holds: one grant, one execution, every attack refused | Anything about a bank's production path; the profile's runtime is not in this repository  |
| Autonomous workflows | `examples/github-deploy-agent` (staging allowed, production escalated, force-push blocked), then `examples/procurement-agent` | [decionis.com](https://decionis.com)                                                            | An unattended workflow's consequential step was gated before it ran                      | That the workflow engine cannot bypass the executor; see THREAT-MODEL.md "Accepted risks" |

Who owns which control, in every family: the library captures, gates, verifies and dispatches;
the authority decides, issues and consumes grants, and keeps the record; your host isolates the
executor, denies the agent egress, and scopes the provider credentials. The seam is written down in
[OPEN-CORE.md](./OPEN-CORE.md).

## What a green run is not

A green run is the boundary holding against synthetic policy, a fixture authority and in-process
doubles. It is not evidence that a hosted integration exists, that a provider behaves this way, or
that a deployment is production-ready. "Every attack refused" is a statement about the run you
just made, on the commit you ran it from.
