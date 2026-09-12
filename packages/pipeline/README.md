# `@decionis/agent-safe-pipeline`

[![npm version](https://img.shields.io/npm/v/@decionis/agent-safe-pipeline.svg)](https://www.npmjs.com/package/@decionis/agent-safe-pipeline)
[![Continuous integration](https://github.com/decionis/agent-safe-pipeline/actions/workflows/deploy.yml/badge.svg?branch=master)](https://github.com/decionis/agent-safe-pipeline/actions/workflows/deploy.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/decionis/agent-safe-pipeline/badge)](https://scorecard.dev/viewer/?uri=github.com/decionis/agent-safe-pipeline)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14098/badge)](https://www.bestpractices.dev/projects/14098)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/decionis/agent-safe-pipeline/blob/master/LICENSE)

**Let agents propose. Let policy decide.**

`@decionis/agent-safe-pipeline` is the TypeScript reference implementation of the Execution
Authority architecture. An AI agent may reason, plan, and propose a consequential action. It cannot
authorize that action, hold the credentials that perform it, or choose which trusted code runs. The
exact proposal is captured as an immutable, short-lived intent, evaluated independently by Decionis,
escalated to a verified human when policy requires it, and executed only through a single-use grant
bound to that one intent. Every decision leaves a Decision Dossier, so the record of what was
authorized, under which policy, and on whose approval compounds over time.

```text
Agent -> immutable intent -> Decionis -> ALLOW / ESCALATE / BLOCK -> SafeExecutor -> downstream API
                                      |
                                      +-> Presence -> verified human approval -> Decionis re-evaluation
                                      |
                                      +-> Decision Dossier -> compounding decision record
```

The package is a library, not a hosted service. It supplies the boundary; Decionis supplies the
decision. Its safety claims hold only when the documented trust boundary is preserved: the agent
runtime never sees Decionis credentials, downstream credentials, or the handler registry.

## Why an execution boundary

Model-level controls shape what an agent says. They cannot prove, after the fact, that a specific
side effect was authorized by a specific policy at the moment it happened. Prompt filtering,
fine-tuning, and evaluation all sit before the action; the gap is at execution. This package closes
it structurally:

- **The agent's input is only the proposal.** Action, target, and parameters. Tenant, actor,
  downstream system, and credentials come from trusted server configuration and cannot be injected.
- **The decision is made elsewhere.** Decionis evaluates the canonical intent hash and returns
  `ALLOW`, `ESCALATE`, or `BLOCK` with a decision identifier and a Decision Dossier identifier.
- **Approval is evidence, never authority.** Presence proves that a real person approved that exact
  intent. Decionis verifies the receipt and re-evaluates current policy before any grant exists.
- **Execution consumes a grant, not a callback.** `SafeExecutor` accepts a captured intent and a
  decision. It claims the grant atomically, then invokes a handler from a sealed registry.
- **Everything else fails closed.** A network error, a malformed response, a missing grant, an
  expired intent, a replayed token, or a binding mismatch all result in no execution.

## Requirements

- Node.js 22.14 or later. The package is ESM-only and ships its own TypeScript declarations.
- A server-side process that holds the Decionis credentials. Never load this package into a
  browser, an agent sandbox, or any runtime the model can influence.
- `zod` v4 for handler parameter schemas (installed as a dependency).

## Install

```bash
npm install @decionis/agent-safe-pipeline
```

Stable releases publish under the `latest` tag with npm provenance. Prereleases publish under the
`next` tag and are never installed by default:

```bash
npm install @decionis/agent-safe-pipeline@next
```

Decionis credentials belong only in the trusted executor process:

```text
DECIONIS_API_URL=https://api.decionis.com
DECIONIS_API_KEY=server-side-secret
```

## Quick start: enforcement

The complete production path in one file. The proposal comes from the agent; everything else comes
from trusted configuration.

```ts
import {
  ActionRegistry,
  DecionisGate,
  DecionisGrantVerifier,
  IntentCapture,
  SafeExecutor,
} from "@decionis/agent-safe-pipeline";
import { z } from "zod";

// 1. Capture the exact proposal. The agent supplies only action, target, and parameters.
const captured = new IntentCapture().capture(
  {
    action: "refund_order",
    target: "shopify:order:1001",
    parameters: { orderId: "1001", amountMinor: 35_000 },
  },
  {
    tenantId: config.tenantId,
    actor: { id: "refund-agent", type: "AI_AGENT" },
    downstreamTarget: { system: "shopify", operation: "refund", environment: "production" },
    idempotencyKey: "refund-1001-v1",
  },
);

// 2. Ask Decionis. The gate never returns an executable decision without a grant.
const gate = new DecionisGate({
  baseUrl: process.env.DECIONIS_API_URL!,
  apiKey: process.env.DECIONIS_API_KEY!,
});
const decision = await gate.evaluate(captured);

// 3. Register trusted handlers once, then seal the registry so nothing can be added at runtime.
const registry = new ActionRegistry()
  .register("refund_order", {
    parametersSchema: z.object({ orderId: z.string(), amountMinor: z.number().int() }).strict(),
    execute: ({ parameters }) => shopify.refund(parameters),
  })
  .seal();

// 4. Execute only through a claimed single-use grant bound to this intent.
const executor = new SafeExecutor(
  registry,
  new DecionisGrantVerifier({
    baseUrl: process.env.DECIONIS_API_URL!,
    apiKey: process.env.DECIONIS_API_KEY!,
  }),
);
const result = await executor.run(captured, decision);

if (result.outcome === "COMPLETED") {
  // result.result is the handler's return value.
  // result.authorization carries the consumed { decisionId, dossierId, grantId, intentHash }.
}
```

The executor validates parameters against the handler's schema before the grant is claimed, and the
grant is claimed before the handler runs. If either step fails, the handler is never invoked.

The trusted context also accepts an optional `expectedEffectDigest` (`sha256:` plus 64 lowercase hex):
a digest-only commitment to the downstream state predicted before dispatch. It is bound into the
canonical intent hash and into the signed grant, and `DecionisGrantVerifier` refuses the authorization
unless the returned grant echoes exactly that digest. The agent proposal can never carry it, and an
intent that omits it hashes byte-identically to before the field existed. After the attempt, a trusted
runtime that observed the effect may pass an `AuthorityEffectEvidence` record as `effectEvidence` to
`DecionisGrantVerifier.finalize`, and read the authority's own `AuthorityEffectReport` back through
`effectReport(authorization)`. See
[execution intent](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/execution-intent.md)
and [execution outcomes](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/execution-outcomes.md).

## Outcomes

Decionis returns one of three verdicts. The executor turns a verdict into exactly one execution
outcome.

| Verdict                               | Executor behavior                                                       |
| ------------------------------------- | ----------------------------------------------------------------------- |
| `ALLOW` with a valid single-use grant | Claim the grant atomically, then invoke the registered handler          |
| `ESCALATE`                            | Stop. Resolve a DIRECT or MANAGED Presence escalation, then re-evaluate |
| `BLOCK`, any error, any mismatch      | Fail closed. The handler is never invoked                               |

`SafeExecutor.run` resolves to a discriminated result rather than throwing:

| `outcome`                | Meaning                                                                                                                                                                                   |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `COMPLETED`              | The grant was consumed and the handler returned. `result` holds its value.                                                                                                                |
| `BLOCKED`                | Nothing ran. `reason` names the refusal: a non-authoritative or non-`ALLOW` decision, a missing or invalid grant, an intent binding or conformance failure, or an unavailable audit sink. |
| `FAILED_BEFORE_DISPATCH` | The grant was consumed but the handler failed before reaching the provider. Safe to reason about.                                                                                         |
| `UNKNOWN_AFTER_DISPATCH` | The provider was called and its outcome is unknown. A `recovery` reference supports reconciliation.                                                                                       |

Every outcome that consumed a grant also reports `finalization` (`RECORDED`, `PENDING`, or
`UNSUPPORTED`). The executor records `COMMITTED`, `FAILED`, or `INDETERMINATE` with Decionis after
the attempt so commit evidence joins the Decision Dossier chain. Finalization is evidence, never
authority: it cannot change `outcome` or `executed`.

### What each record establishes

Fluent summaries lose these distinctions first. Each row names the record or state, what it
establishes, and what it does not.

| Record or state                                         | What it establishes                                                                                                                      | What it does not establish                                                                                                                                                                                                                                                                  |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Captured intent (`IntentCapture`, `intentHash`)         | The exact action, target, and parameters the agent proposed, bound to trusted tenant, actor, and downstream context, hashed and expiring | That the agent's facts, identities, or amounts are true; that anything may execute                                                                                                                                                                                                          |
| Verified human approval (Presence `receiptDossierId`)   | A named person approved that exact intent hash under the assurance the receipt records                                                   | Permission to execute: Decionis re-evaluates policy with the receipt, and only that evaluation can issue a grant                                                                                                                                                                            |
| Execution grant (`authorization` on an `ALLOW`)         | Permission for one attempt at one intent, claimed once through the `AuthorizationVerifier` immediately before the handler runs           | Anything after expiry, for another intent hash, or on a second presentation; a dossier identifier, an invitation link, or an earlier `ALLOW` is not a substitute                                                                                                                            |
| Decision Dossier (`decisionId`, `dossierId`)            | The record of why Decionis allowed, escalated, or blocked: policy snapshot, inputs, evidence, and grant metadata                         | An execution credential; proof that the underlying business judgement was right                                                                                                                                                                                                             |
| Single claim, `COMPLETED`                               | The grant was consumed once and the trusted handler returned a provider result                                                           | An exactly-once downstream business effect or independent confirmation of settlement; whether an observation counts as `CONFIRMED` is the authority's judgement, not this package's                                                                                                         |
| `UNKNOWN_AFTER_DISPATCH`, finalized `INDETERMINATE`     | Dispatch began and completion could not be proved                                                                                        | Permission to repeat the side effect: reconcile through provider idempotency and read-only lookup, never by a second dispatch                                                                                                                                                               |
| Shadow observation (`ShadowPipeline`, `mode: "SHADOW"`) | What Decionis would have decided about an action that already ran: a verdict and a dossier, no grant                                     | Enforcement, a grant, or a no-write test environment; the production write happened as before                                                                                                                                                                                               |
| Library boundary (this package)                         | Intent capture, the gate, verification, and claim-before-handler dispatch inside the trusted integration                                 | Host isolation, IAM, network egress, credential storage, or incident response; see the [threat model](https://github.com/decionis/agent-safe-pipeline/blob/master/THREAT-MODEL.md) and [trust boundary](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/trust-boundary.md) |

The sequence that produces both records, and two synthetic records side by side, are in
[Decision Dossiers](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/decision-dossiers.md).

## Human approval through Presence

When policy escalates, a person must approve that exact intent with independently signed evidence.
Presence delivers the request to an enrolled device and returns a receipt bound to the intent hash.
Presence never authorizes execution; Decionis verifies the receipt and re-evaluates policy. The
package supports two integration levels, and the executor's grant path is identical in both.

| Mode      | Who coordinates Presence | Credentials in the executor | Entry point                                          |
| --------- | ------------------------ | --------------------------- | ---------------------------------------------------- |
| `DIRECT`  | Your trusted executor    | Decionis and Presence       | `PresenceApprovalCoordinator`                        |
| `MANAGED` | Decionis                 | Decionis only               | `DecionisGate.evaluate` with an `escalation` request |

In MANAGED mode, pass routing and ceremony constraints outside the canonical intent, then poll
Decionis only:

```ts
const pending = await gate.evaluate(captured, undefined, {
  escalation: {
    mode: "MANAGED",
    approver: { principal_id: approverId, role_id: "APPROVER" },
    verification_requirements: { methods: ["WEBAUTHN"], level: "HIGH_CONFIDENCE" },
  },
});
// pending.verdict === "ESCALATE"; pending.managedEscalation is set; no grant exists yet.

const authorized = await gate.waitForAuthorization(captured, pending, { signal });
const result = await executor.run(captured, authorized);
```

`waitForAuthorization` polls with capped exponential backoff and bounded jitter, and stops at the
intent or escalation expiry. It returns a normal `ALLOW` decision with a grant only after Decionis
has verified the Presence evidence and re-evaluated current policy. Approval cannot revive an intent
after it expires. Presence transport or schema failures and Decionis re-authorization failures
return stable fail-closed decisions; raw downstream error text never reaches the caller.

## Shadow mode

Measure before you enforce. `ShadowPipeline` wraps an execution path you already run and records
what Decionis would have decided, without the ability to stop, delay, or alter it.

```ts
import { DecionisGate, ShadowPipeline } from "@decionis/agent-safe-pipeline";

const shadow = new ShadowPipeline(new DecionisGate({ baseUrl, apiKey, mode: "SHADOW" }), {
  timeoutMs: 2_000,
});

const run = await shadow.observe(captured, () => existingRefund(order));
// run.production is your unchanged result, available as soon as production settles.
const observation = await run.observation;
// The observation runs under its own timeout and never rejects; it reports the verdict
// Decionis would have returned, the dossier identifier, and whether a grant was discarded.
```

A shadow observation carries no grant, is structurally distinct from a `GateDecision`, and is
rejected by `SafeExecutor` at runtime. See
[shadow mode](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/shadow-mode.md).

## Adoption path

The same `IntentCapture`, `ActionRegistry`, and handler code carry through every stage. Nothing is
rewritten between them.

| Stage       | Authority                                                     | What it proves                                                                   |
| ----------- | ------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Development | `createFixtureAuthorityPair` (refuses `NODE_ENV=production`)  | The intent, registry, and executor wiring is correct                             |
| Shadow      | `ShadowPipeline` over `DecionisGate` with `mode: "SHADOW"`    | What Decionis would have decided about actions that already run; no grant issued |
| Enforcement | `DecionisGate` plus `DecionisGrantVerifier` in `SafeExecutor` | Nothing runs without an independent decision and a consumed single-use grant     |

## Local testing

`@decionis/agent-safe-pipeline/testing` ships `LocalPresence` and `LocalAuthority`: loopback doubles
that the production clients talk to unchanged. They enforce the structural intent-hash binding,
verify receipts the way Decionis does, issue single-use grants, orchestrate managed escalations, and
record finalization. The person's ceremony becomes a method call.

```ts
import { DecionisGate, DecionisGrantVerifier } from "@decionis/agent-safe-pipeline";
import {
  LocalAuthority,
  LocalPresence,
  LOCAL_AUTHORITY_API_KEY,
} from "@decionis/agent-safe-pipeline/testing";

const presence = new LocalPresence({ autoComplete: "MANUAL", roles: { "synthetic-cro": "CRO" } });
const authority = new LocalAuthority({ presence });
await presence.start();
await authority.start();

const gate = new DecionisGate({
  baseUrl: authority.baseUrl,
  apiKey: LOCAL_AUTHORITY_API_KEY,
  allowInsecureLoopback: true,
});
// ... evaluate, then complete the ceremony with presence.approve(requestId)
// and assert on grants, receipts, and recorded commits.
```

Both doubles bind to `127.0.0.1` on an ephemeral port and refuse to construct under
`NODE_ENV=production`. The testing entry also exports the development fixture primitives
(`createFixtureAuthorityPair`, `FixtureDecisionAuthority`, `FixtureAuthorizationVerifier`,
`InMemoryReplayStore`). Those remain available at the package root until 1.0; new code should import
them from the testing entry. See
[local testing](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/local-testing.md).

## API overview

| Concern        | Exports                                                                                           | Role                                                                                           |
| -------------- | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Intent         | `IntentCapture`, `CanonicalIntentHasher`, `ExecutionIntentSchema`, `AgentProposalSchema`          | Build the immutable `agent-safe.intent/1` binding and its canonical SHA-256 hash               |
| Decision       | `DecionisGate`, `DecisionAuthority`, `GateDecision`, `FailClosedDecision`                         | Obtain an independent `ALLOW` / `ESCALATE` / `BLOCK` decision with dossier identifiers         |
| Human approval | `PresenceApprovalCoordinator`, `ManagedEscalationRequest`, `HumanApprovalEvidence`                | Coordinate DIRECT Presence ceremonies or request MANAGED orchestration by Decionis             |
| Execution      | `SafeExecutor`, `ActionRegistry`, `DecionisGrantVerifier`, `AuthorizationVerifier`, `ReplayStore` | Claim the single-use grant, validate parameters, invoke a sealed handler, finalize the attempt |
| Effect         | `AuthorityEffectEvidence`, `AuthorityEffectReport`, `DecionisGrantVerifier.effectReport`          | Forward a trusted runtime's downstream observation on finalize and read the authority's answer |
| Observation    | `ShadowPipeline`, `ShadowObservation`                                                             | Record what the authority would have decided without granting execution                        |
| Audit          | `AuditRecorder`, `AuditEventV1`, `AuditSink`                                                      | Emit immutable, redacted lifecycle records through one bounded sink call                       |
| Testing        | `LocalPresence`, `LocalAuthority`, `createFixtureAuthorityPair` (from `/testing`)                 | Loopback doubles and fixture authorities for development and CI                                |

The seam between this package and Decionis is two interfaces, `DecisionAuthority` and
`AuthorizationVerifier`, plus a published OpenAPI contract. Anyone can implement the interfaces; the
library checks no plan, key, or entitlement.

## Production invariants

1. Agent input contains only the proposed action, target, and parameters. Tenant, actor, downstream
   target, and credentials come from trusted runtime configuration.
2. The exact canonical intent is hashed and expires quickly.
3. Decionis decides independently. Network errors, malformed responses, missing grants, and binding
   mismatches fail closed.
4. Presence proves a human approved that exact intent. It never authorizes execution; Decionis
   verifies the receipt and re-evaluates policy.
5. The grant is bound to the intent, decision, audience, and expiry, and is claimed atomically before
   the handler runs. The attempt is finalized afterwards as evidence, never as authority.
6. Downstream credentials exist only behind the trusted executor.
7. Every decision is evidence-bearing. An `ALLOW` without a dossier identifier or grant is refused
   as non-executable. A dossier identifier is never an execution credential.

Read the [trust boundary](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/trust-boundary.md)
and the [threat model](https://github.com/decionis/agent-safe-pipeline/blob/master/THREAT-MODEL.md)
before integrating a real downstream API.

## Assurance and supply chain

- **Provenance.** Every release is published through npm trusted publishing with a provenance
  attestation, from a keyless-signed release tag, and archived under Zenodo concept DOI
  [`10.5281/zenodo.22312955`](https://doi.org/10.5281/zenodo.22312955).
- **Release evidence.** Each GitHub release carries the tarball, a CycloneDX SBOM, Sigstore
  provenance and SBOM attestations, and a checksum file. See
  [reproducible builds](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/reproducible-builds.md).
- **Testing.** Coverage gates of 90% lines, functions, and statements and 85% branches; mutation
  testing on the trust boundary; deterministic property-based fuzzing of canonical intent handling;
  a loopback wire-contract harness that exercises the packed package over real HTTP.
- **Adversarial proof.** The
  [golden adversarial demo](https://github.com/decionis/agent-safe-pipeline/tree/master/examples/golden-adversarial-demo)
  runs one legitimate path and eight attacks against the same boundary, offline, and exits 0 only
  when exactly one action executes.
- **Scanning.** CodeQL, secret scanning, OpenSSF Scorecard, and OpenSSF Best Practices, with
  separate production and toolchain dependency audits. The control-to-artifact map is in
  [SECURITY-EVIDENCE.md](https://github.com/decionis/agent-safe-pipeline/blob/master/SECURITY-EVIDENCE.md).

## Examples

Runnable, offline, and fixture-backed unless noted. Each one uses this package unchanged.

- [`basic-agent`](https://github.com/decionis/agent-safe-pipeline/tree/master/examples/basic-agent): the smallest `BLOCK` flow.
- [`shopify-refund-agent`](https://github.com/decionis/agent-safe-pipeline/tree/master/examples/shopify-refund-agent): amount-based `ALLOW` / `ESCALATE` / `BLOCK`.
- [`github-deploy-agent`](https://github.com/decionis/agent-safe-pipeline/tree/master/examples/github-deploy-agent): environment and force-push controls.
- [`procurement-agent`](https://github.com/decionis/agent-safe-pipeline/tree/master/examples/procurement-agent): an in-budget request held by policy.
- [`mcp-tool-gate`](https://github.com/decionis/agent-safe-pipeline/tree/master/examples/mcp-tool-gate): a real stdio MCP server with a governed tool.
- [`local-escalation`](https://github.com/decionis/agent-safe-pipeline/tree/master/examples/local-escalation): DIRECT and MANAGED Presence escalation against loopback doubles.
- [`presence-live-approval`](https://github.com/decionis/agent-safe-pipeline/tree/master/examples/presence-live-approval): DIRECT Presence enforcement against the real services with a FIDO2 or FIDO2-plus-liveness ceremony (needs credentials).
- [`presence-managed-approval`](https://github.com/decionis/agent-safe-pipeline/tree/master/examples/presence-managed-approval): Decionis-managed Presence orchestration against the real services (needs credentials).
- [`golden-adversarial-demo`](https://github.com/decionis/agent-safe-pipeline/tree/master/examples/golden-adversarial-demo): one golden path, eight attacks, zero unauthorized executions.

## Open core

This package and the repository's architecture, intent contract, execution boundary, client
adapters, audit contract, shadow mode, conformance vectors, and examples are Apache-2.0. The sole
license exception is the dedicated MIT-licensed Claude Desktop wrapper in
`packages/commerce-mcp-claude-extension`; the CommerceGate runtime it bundles remains Apache-2.0.
Decionis operates the policy control plane behind `DecionisGate`: policy evaluation, grant issuance
and atomic consumption, Decision Dossier signing and retention, and Presence.
[OPEN-CORE.md](https://github.com/decionis/agent-safe-pipeline/blob/master/OPEN-CORE.md) states the
boundary and the commitments that keep it stable.

## Research

Decionis Research defines the architecture, this package demonstrates it as tested code, and the
Decionis platform operates it as a hosted authority.

- Jejelowo, Festus. "The Execution Verifiability Gap: Why Model Governance Cannot Authorize
  Consequential Actions." Decionis Research, version 1.0, 21 August 2026.
  [Canonical article](https://decionis.com/research/execution-verifiability-gap) ·
  [Archival PDF](https://decionis.com/research/execution-verifiability-gap-v1.0.pdf)

To cite the software, use the
[CITATION.cff](https://github.com/decionis/agent-safe-pipeline/blob/master/CITATION.cff) in the
repository or the Zenodo record above.

## Support and license

- Vulnerabilities: [GitHub private vulnerability reporting](https://github.com/decionis/agent-safe-pipeline/security/advisories/new) or `security@decionis.com`. Never open a public issue for a security report.
- Everything else: [GitHub Issues](https://github.com/decionis/agent-safe-pipeline/issues).
- Architecture and full documentation: [Agent-Safe Pipeline README](https://github.com/decionis/agent-safe-pipeline#readme).

Apache-2.0. Trademark terms in
[TRADEMARKS.md](https://github.com/decionis/agent-safe-pipeline/blob/master/TRADEMARKS.md).
