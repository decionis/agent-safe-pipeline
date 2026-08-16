# Agent-Safe Pipeline

[![Continuous integration](https://github.com/decionis/agent-safe-pipeline/actions/workflows/deploy.yml/badge.svg?branch=master)](https://github.com/decionis/agent-safe-pipeline/actions/workflows/deploy.yml)
[![CodeQL](https://github.com/decionis/agent-safe-pipeline/actions/workflows/codeql.yml/badge.svg?branch=master)](https://github.com/decionis/agent-safe-pipeline/actions/workflows/codeql.yml)
[![Secret scanning](https://github.com/decionis/agent-safe-pipeline/actions/workflows/secrets.yml/badge.svg?branch=master)](https://github.com/decionis/agent-safe-pipeline/actions/workflows/secrets.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/decionis/agent-safe-pipeline/badge)](https://scorecard.dev/viewer/?uri=github.com/decionis/agent-safe-pipeline)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**Let agents propose. Let policy decide.**

Agent-Safe Pipeline is a reference architecture for executing AI-agent actions through an independent authorization boundary.

This repository is a library and runnable reference implementation, not a hosted authorization service or a substitute for provider-side identity, least privilege, network isolation, and incident response. Its safety claims apply only when the documented trust boundary is preserved.

```text
Agent -> immutable intent -> Decionis -> ALLOW / ESCALATE / BLOCK -> SafeExecutor -> API
                                      |
                                      +-> Presence -> verified human approval -> Decionis re-evaluation
```

Agents can reason, plan, and propose actions. They must not determine whether their own actions are authorized, possess downstream privileged credentials, or choose which trusted handler runs.

## Five-minute demo

Requirements: Node.js 22.14 or later and pnpm 9.

```bash
git clone https://github.com/decionis/agent-safe-pipeline.git
cd agent-safe-pipeline
pnpm install --frozen-lockfile
pnpm --filter @decionis/agent-safe-example-basic demo
```

The demos use an explicitly non-production fixture authority. A production integration uses `DecionisGate` and `DecionisGrantVerifier` with server-side credentials.

```ts
const captured = intentCapture.capture(agentProposal, trustedContext);
const decision = await gate.evaluate(captured);
const result = await executor.run(captured, decision);
```

The executor accepts a captured intent and a decision. It does not accept an arbitrary callback from the agent. A sealed `ActionRegistry` maps action names to trusted handlers and validates parameters before consuming a single-use grant.

## Repository map

- [`packages/pipeline`](./packages/pipeline) — `IntentCapture`, `DecionisGate`, Presence coordination, and `SafeExecutor`.
- [`examples/basic-agent`](./examples/basic-agent) — the smallest BLOCK flow.
- [`examples/shopify-refund-agent`](./examples/shopify-refund-agent) — amount-based ALLOW / ESCALATE / BLOCK.
- [`examples/github-deploy-agent`](./examples/github-deploy-agent) — environment and force-push controls.
- [`examples/mcp-tool-gate`](./examples/mcp-tool-gate) — a real stdio MCP server with a governed tool.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) and [`THREAT-MODEL.md`](./THREAT-MODEL.md) — trust boundary and abuse analysis.
- [`conformance/agent-safe-intent-v1.json`](./conformance/agent-safe-intent-v1.json) — portable canonical-hash test vector.
- [`conformance/vectors/`](./conformance/vectors/) — edge-case canonical-hash vectors (Unicode/astral, NFC vs NFD, negative zero, fractional/exponent numbers, nested arrays, UTF-16 key sort order), auto-discovered by the conformance test.
- [`FIXTURE-PROVENANCE.md`](./FIXTURE-PROVENANCE.md) — origin and permitted use of every fixture family.
- [`DEPENDENCY-LICENSES.md`](./DEPENDENCY-LICENSES.md) — generated inventory method and platform-conditional dependency notes.
- [`SECURITY-EVIDENCE.md`](./SECURITY-EVIDENCE.md) — control-to-artifact evidence map and published gaps.
- [`PUBLICATION-SIGNOFFS.md`](./PUBLICATION-SIGNOFFS.md) — human decisions that automation cannot make.

## Production invariants

1. Agent input contains only the proposed action, target, and parameters. Tenant, actor, downstream target, and credentials come from trusted runtime configuration.
2. The exact canonical intent is hashed and expires quickly.
3. Decionis independently decides. Network errors, malformed responses, missing grants, or binding mismatches fail closed.
4. Presence proves a human approved that exact intent; Presence never directly authorizes execution. Decionis verifies the receipt and re-evaluates policy.
5. The grant is bound to the intent, decision, audience, and expiry and is consumed atomically before the handler runs.
6. Downstream credentials exist only behind the trusted executor.

See [`docs/trust-boundary.md`](./docs/trust-boundary.md) before integrating a real downstream API.

## Public-repository policy

This is intended to be the public, canonical reference implementation. It should not be mirrored: mirrors create contract and security-fix drift. Public content belongs here—architecture, package source, synthetic policies, and runnable examples. Production policy bundles, customer data, credentials, internal infrastructure, and private incident material do not.

Decionis remains the authoritative decision service, Presence remains the human-verification service, and their server internals can evolve independently behind versioned contracts.

## Status

The workspace package is versioned `0.1.2` but is not claimed as published until the registry release workflow succeeds. Install it from this workspace today. The canonical repository URL was verified on 2026-08-14; availability of future package releases is intentionally not fabricated in these docs.

## Development

```bash
pnpm install --frozen-lockfile
pnpm verify
```

`pnpm verify` enforces formatting, Markdown lint, fixture conventions, canonical licensing, separate
production/toolchain audits, deterministic performance tests, types, tests, and coverage thresholds
of 90% for lines/functions/statements and 85% for branches. `pnpm mutation` checks that
trust-boundary tests kill deliberate code mutations. `pnpm fuzz` runs deterministic property tests
against canonical intent handling; CI also runs them weekly with a larger bounded sample.
Installation activates the repository's `simple-git-hooks` pre-commit guardrails.

Apache-2.0 licensed. See [`LICENSE`](./LICENSE), [`TRADEMARKS.md`](./TRADEMARKS.md), [`SECURITY.md`](./SECURITY.md), and [`CONTRIBUTING.md`](./CONTRIBUTING.md). Report suspected vulnerabilities through [GitHub's private advisory form](https://github.com/decionis/agent-safe-pipeline/security/advisories/new), not a public issue.
