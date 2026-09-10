# Agent-Safe Pipeline

[![Continuous integration](https://github.com/decionis/agent-safe-pipeline/actions/workflows/deploy.yml/badge.svg?branch=master)](https://github.com/decionis/agent-safe-pipeline/actions/workflows/deploy.yml)
[![CodeQL](https://github.com/decionis/agent-safe-pipeline/actions/workflows/codeql.yml/badge.svg?branch=master)](https://github.com/decionis/agent-safe-pipeline/actions/workflows/codeql.yml)
[![Secret scanning](https://github.com/decionis/agent-safe-pipeline/actions/workflows/secrets.yml/badge.svg?branch=master)](https://github.com/decionis/agent-safe-pipeline/actions/workflows/secrets.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/decionis/agent-safe-pipeline/badge)](https://scorecard.dev/viewer/?uri=github.com/decionis/agent-safe-pipeline)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14098/badge)](https://www.bestpractices.dev/projects/14098)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**Let agents propose. Let policy decide.**

Agent-Safe Pipeline is the reference implementation of the Execution Authority architecture: AI-agent actions execute only through an independent authorization boundary, and every authorization decision leaves a verifiable evidence record.

This repository is a library and runnable reference implementation, not a hosted authorization service or a substitute for provider-side identity, least privilege, network isolation, and incident response. Its safety claims apply only when the documented trust boundary is preserved.

```text
Agent -> immutable intent -> Decionis -> ALLOW / ESCALATE / BLOCK -> SafeExecutor -> API
                                      |
                                      +-> Presence -> verified human approval -> Decionis re-evaluation
                                      |
                                      +-> Decision Dossier -> compounding decision record
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

## Golden adversarial demo

One legitimate path and eight adversarial attempts against the same boundary, offline, in a few seconds, with every expectation asserted:

```bash
pnpm --filter @decionis/agent-safe-example-golden-adversarial demo
```

A treasury agent proposes a USD 250,000 wire, a remote Chief Risk Officer completes a FIDO2 plus liveness ceremony, and exactly one wire executes. Injected authorization fields, a fabricated ALLOW, an asserted approval, a swapped receipt, a post-approval amount change, a replayed grant, 25 concurrent claims, a shadow observation, and an expired grant all fail to execute. The run exits 0 only when that holds. See [`examples/golden-adversarial-demo`](./examples/golden-adversarial-demo), the bank-audience walkthrough in [`docs/remote-cro-authorization.md`](./docs/remote-cro-authorization.md), and the receipt semantics in [`docs/presence-evidence.md`](./docs/presence-evidence.md).

## From the fixture to Decionis

The package is used in three stages. Each stage uses the same `IntentCapture`, `ActionRegistry`, and handler code, so nothing is rewritten between them.

| Stage       | Authority                                                     | What it proves                                                                           |
| ----------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Development | `createFixtureAuthorityPair` (refuses `NODE_ENV=production`)  | The intent, registry, and executor wiring is correct                                     |
| Shadow      | `ShadowPipeline` over `DecionisGate` with `mode: "SHADOW"`    | What Decionis would have decided about actions that already run; no grant is ever issued |
| Enforcement | `DecionisGate` plus `DecionisGrantVerifier` in `SafeExecutor` | Nothing runs without an independent decision and a consumed single-use grant             |

Decionis credentials belong only in the trusted executor process, never in the agent runtime:

```text
DECIONIS_API_URL=https://api.decionis.com
DECIONIS_API_KEY=server-side-secret
```

See the [package README](./packages/pipeline/README.md) for the complete enforcement example and [`docs/shadow-mode.md`](./docs/shadow-mode.md) for the shadow rollout path.

## Repository map

- [`packages/pipeline`](./packages/pipeline) — `IntentCapture`, `DecionisGate`, Presence coordination, and `SafeExecutor`.
- [`packages/commerce-mcp`](./packages/commerce-mcp) — `@decionis/commerce`, the CommerceGate MCP server: lets an AI agent check a price change, stock change, order, fulfillment step, promotion, refund or return against the merchant's policy before acting, and read the signed record afterwards. A client adapter over the published Decionis contract; it holds no policy and contains no marketplace client.
- [`examples/golden-adversarial-demo`](./examples/golden-adversarial-demo) — the self-checking proof: one golden path, eight attacks, zero unauthorized executions.
- [`examples/basic-agent`](./examples/basic-agent) — the smallest BLOCK flow.
- [`examples/shopify-refund-agent`](./examples/shopify-refund-agent) — amount-based ALLOW / ESCALATE / BLOCK.
- [`examples/github-deploy-agent`](./examples/github-deploy-agent) — environment and force-push controls.
- [`examples/procurement-agent`](./examples/procurement-agent) — an in-budget software request held when existing tools still have user capacity.
- [`examples/mcp-tool-gate`](./examples/mcp-tool-gate) — a real stdio MCP server with a governed tool.
- [`examples/presence-live-approval`](./examples/presence-live-approval) — a Presence-bound enforcement against the real services with a FIDO2 or FIDO2-plus-liveness ceremony; needs real credentials.
- [`examples/presence-managed-approval`](./examples/presence-managed-approval) — Decionis-managed Presence orchestration with Decionis-only polling and no Presence credential in the executor.
- [`examples/local-escalation`](./examples/local-escalation) — both Presence integration modes against loopback Decionis and Presence doubles, no credentials, ceremony simulated.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) and [`THREAT-MODEL.md`](./THREAT-MODEL.md) — trust boundary and abuse analysis.
- [`OPEN-CORE.md`](./OPEN-CORE.md) — what is Apache-2.0 here, what Decionis operates, and the seam between them.
- [`docs/`](./docs) — concepts, execution intent, outcomes, human approval, [Presence Evidence semantics](./docs/presence-evidence.md), the [remote CRO sequence](./docs/remote-cro-authorization.md), shadow mode, Decision Dossiers, trust boundary, and assurance notes.
- [`conformance/agent-safe-intent-v1.json`](./conformance/agent-safe-intent-v1.json) — portable canonical-hash test vector.
- [`conformance/vectors/`](./conformance/vectors/) — edge-case canonical-hash vectors (Unicode/astral, NFC vs NFD, negative zero, fractional/exponent numbers, nested arrays, UTF-16 key sort order), auto-discovered by the conformance test.
- [`dossiers/`](./dossiers/) — reproducible synthetic Decision Dossier corpus with canonical bytes, SHA-256 digests, Ed25519 signatures, and a deliberately published corpus key.
- [`tests/integration/contract/`](./tests/integration/contract/) — loopback Decionis and Presence stubs that exercise the packed package's complete wire contract over real HTTP.
- [`FIXTURE-PROVENANCE.md`](./FIXTURE-PROVENANCE.md) — origin and permitted use of every fixture family.
- [`DEPENDENCY-LICENSES.md`](./DEPENDENCY-LICENSES.md) — generated inventory method and platform-conditional dependency notes.
- [`SECURITY-EVIDENCE.md`](./SECURITY-EVIDENCE.md) — control-to-artifact evidence map and published gaps.
- [`PUBLICATION-SIGNOFFS.md`](./PUBLICATION-SIGNOFFS.md) — human decisions that automation cannot make.

## Production invariants

1. Agent input contains only the proposed action, target, and parameters. Tenant, actor, downstream target, and credentials come from trusted runtime configuration.
2. The exact canonical intent is hashed and expires quickly.
3. Decionis independently decides. Network errors, malformed responses, missing grants, or binding mismatches fail closed.
4. Presence proves a human approved that exact intent; Presence never directly authorizes execution. Decionis verifies the receipt and re-evaluates policy.
5. The grant is bound to the intent, decision, audience, and expiry and is claimed atomically before the handler runs; the attempt outcome is finalized with the authority afterwards as evidence, never as authority.
6. Downstream credentials exist only behind the trusted executor.
7. Every decision is evidence-bearing. An ALLOW whose response lacks a dossier identifier or grant is refused as non-executable, and an executed result retains its consumed `{decisionId, dossierId, grantId}` binding. A dossier identifier is never an execution credential.

Presence supports two explicit integration levels. In DIRECT mode, the trusted executor coordinates
Presence and returns the receipt reference to Decionis. In MANAGED mode, the executor asks Decionis
to orchestrate Presence and polls Decionis for a terminal status. Both modes require independently
signed Presence evidence, exact-intent verification, current-policy re-evaluation, and the same
claim-before-handler grant path. Invitation delivery and Presence evidence are never execution
authority, and approval cannot revive a five-minute intent after it expires.

See [`docs/trust-boundary.md`](./docs/trust-boundary.md) before integrating a real downstream API.

## Decision record

The Execution Authority architecture has two load-bearing properties. Position on the execution path creates control: nothing runs without an independent decision at the moment of action. The evidence record creates accountability that compounds: every decision adds to an auditable history of what was authorized, under which policy, on whose approval.

Every Decionis evaluation is recorded as a Decision Dossier, and each `GateDecision` returns the `decisionId` and `dossierId` of that record. Escalations attach the verified Presence `receiptDossierId`, and every executed action returns the consumed grant's `{decisionId, dossierId, grantId, intentHash}` binding, so execution results correlate to their evidence without extra bookkeeping. In the research vocabulary, dossiers compound into a Decision Chain: tamper-evident lineage linking evaluation, approval, and execution evidence across workflows. Decionis maintains that record; this repository's contribution is that execution cannot bypass it.

Treat dossier identifiers as audit and support references, never as execution credentials — see [`docs/decision-dossiers.md`](./docs/decision-dossiers.md).

## Research and specifications

Decionis Research defines the Execution Authority architecture, this repository demonstrates it as runnable, tested code, and the Decionis platform operates it as a hosted authority. The provenance chain is research paper -> protocol contract -> reference implementation (this repository) -> production service.

Published research:

- Jejelowo, Festus. "The Execution Verifiability Gap: Why Model Governance Cannot Authorize Consequential Actions." Decionis Research, version 1.0, 21 August 2026. [Canonical article](https://decionis.com/research/execution-verifiability-gap) · [Archival PDF](https://decionis.com/research/execution-verifiability-gap-v1.0.pdf) · [Research index](https://decionis.com/research).

Companion notes on the Execution Authority model, the authorization protocol, Presence-verified human approval, and Decision Dossiers are in preparation. Following this repository's discovery rules, a publication link is added here only after its canonical article resolves publicly.

| Research concept              | Implementation in this repository                                                                                                                                                                  |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Execution Authority boundary  | `IntentCapture` -> `DecionisGate` -> `SafeExecutor`                                                                                                                                                |
| Protocol contract             | Exactly the Decionis `ExecutionAuthorityRequest` and `ExecutionIntentBinding` contract on the wire; `DecionisGate` and `DecionisGrantVerifier` claim and finalize against the published OpenAPI    |
| Intent integrity              | `CanonicalIntentHasher` plus the [`conformance/`](./conformance) hash vectors                                                                                                                      |
| Human approval evidence       | DIRECT `PresenceApprovalCoordinator` or MANAGED `DecionisGate` polling; both require Presence receipt verification and Decionis re-evaluation                                                      |
| Trusted execution             | Sealed `ActionRegistry` and atomic single-use grant consumption in `SafeExecutor`                                                                                                                  |
| Decision evidence             | `decisionId` and `dossierId` on every gate decision; executed results retain the consumed-grant binding                                                                                            |
| Failure semantics             | Fail-closed production invariants and [`THREAT-MODEL.md`](./THREAT-MODEL.md)                                                                                                                       |
| Observation without authority | `ShadowPipeline` over a `SHADOW`-mode gate: failure-isolated, bounded, grant-free, and rejected by `SafeExecutor`; see [`docs/shadow-mode.md`](./docs/shadow-mode.md)                              |
| MCP governance                | [`examples/mcp-tool-gate`](./examples/mcp-tool-gate)                                                                                                                                               |
| Operational patterns          | [`examples/shopify-refund-agent`](./examples/shopify-refund-agent), [`examples/github-deploy-agent`](./examples/github-deploy-agent), [`examples/procurement-agent`](./examples/procurement-agent) |

## Open core

Everything in this repository is Apache-2.0: the architecture, the intent contract, the execution boundary, the client adapters, the audit contract, shadow mode, the conformance vectors, and the examples. Decionis operates the policy control plane behind `DecionisGate`: policy evaluation, grant issuance and atomic consumption, Decision Dossier signing and retention, and Presence. The seam is two exported interfaces, `DecisionAuthority` and `AuthorizationVerifier`, plus a published OpenAPI contract; the library checks no plan, key, or entitlement. [`OPEN-CORE.md`](./OPEN-CORE.md) states the boundary and the commitments that keep it stable.

## Public-repository policy

This is intended to be the public, canonical reference implementation. It should not be mirrored: mirrors create contract and security-fix drift. Public content belongs here—architecture, package source, synthetic policies, and runnable examples. Production policy bundles, customer data, credentials, internal infrastructure, and private incident material do not.

Decionis remains the authoritative decision service, Presence remains the human-verification service, and their server internals can evolve independently behind versioned contracts.

## Verify Decision Dossiers

The repository-owned [`dossiers/`](./dossiers/) corpus checks the offline verifier against synthetic
`ALLOW`, `BLOCK`, and `ESCALATE` proof bundles, including an owned-workspace, execution-bound
vector. Its private signing key is intentionally public so anyone can regenerate the corpus; it is
not a production credential and cannot establish that a production dossier is authentic.

```bash
pnpm exec decionis-verify \
  --file dossiers/vectors/allow.json \
  --jwks dossiers/corpus-jwks.json
```

To verify the distinct production claim, obtain a live dossier through an authorized route and run
the pinned verifier against the live JWKS without committing the dossier:

```bash
npx -y @decionis/verify@0.2.0 \
  --file /absolute/path/to/live-decision-dossier.json \
  --jwks https://api.decionis.com/v1/.well-known/decision-dossier-jwks.json
```

See the [corpus README](./dossiers/README.md) for regeneration, provenance, expected failures, and
the trust boundary between synthetic conformance and production verification.

## Status

The package is published as [`@decionis/agent-safe-pipeline`](https://www.npmjs.com/package/@decionis/agent-safe-pipeline). Install the latest stable release with `npm install @decionis/agent-safe-pipeline`; prereleases require an explicit version such as `npm install @decionis/agent-safe-pipeline@0.1.3-rc.2`.

Archived releases are citable under [Zenodo concept DOI
`10.5281/zenodo.22312955`](https://doi.org/10.5281/zenodo.22312955). The
[release-metadata contract](./docs/zenodo-release-metadata.md) explains the
preflight checks, version-DOI verification, and human publication boundary.

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

### Testing escalations locally

`@decionis/agent-safe-pipeline/testing` ships `LocalPresence` and `LocalAuthority`, loopback doubles
that the production clients talk to unchanged. They enforce the structural intent-hash binding,
verify receipts the way Decionis does, issue single-use grants, orchestrate managed escalations, and
record finalization. The person's ceremony is a method call or a local control route. See
[`docs/local-testing.md`](./docs/local-testing.md) and [`examples/local-escalation`](./examples/local-escalation).

### Fixture provenance and loopback origins

Every fixture-bearing file is listed in [`fixtures/manifest.json`](./fixtures/manifest.json) and
checked by `pnpm fixture:check`: the unit tests under `packages/pipeline/test`, example sources,
conformance vectors, the dossier corpus, synthetic policies, and the integration harness under
`tests/integration`. The gate requires synthetic identities (`synthetic-` or `fixture_` prefixes,
tenants in the reserved UUID block) and parses every URL-shaped literal it finds, which must resolve
to `localhost`, `127.0.0.1`, `example.com`, or a `.example` or `.invalid` domain. Nothing in the
tests, examples, or harness reaches the network beyond loopback.

Two consequences matter when you add or evaluate tests:

- Loopback stubs bind to `127.0.0.1` on an ephemeral port and build their base URL from a plain
  string constant, `const LOOPBACK_ORIGIN = "http://127.0.0.1"`, appending the port separately. A
  template literal that interpolates inside the URL, such as `` `http://127.0.0.1:${port}` ``, is
  read by the gate as literal text and rejected as an invalid URL. That is deliberate: the gate does
  not guess what an interpolated host would resolve to.
- A new fixture-bearing file needs its manifest entry in the same change. Discovery uses
  `git ls-files`, so an untracked file is invisible to the gate until it is staged, and the manifest
  and discovery must match exactly.

See [`FIXTURE-PROVENANCE.md`](./FIXTURE-PROVENANCE.md) for the full construction rules and
[`tests/integration/contract/`](./tests/integration/contract/) for the loopback harness that
follows them.

Apache-2.0 licensed. See [`LICENSE`](./LICENSE), [`TRADEMARKS.md`](./TRADEMARKS.md), [`SECURITY.md`](./SECURITY.md), and [`CONTRIBUTING.md`](./CONTRIBUTING.md). Report suspected vulnerabilities through [GitHub's private advisory form](https://github.com/decionis/agent-safe-pipeline/security/advisories/new), not a public issue.
