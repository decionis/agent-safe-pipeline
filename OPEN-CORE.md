# Open-core boundary

This document states, in one place, what is open source in this repository, what Decionis operates
as a service, where the seam between them is, and what the project commits to about that seam. It
exists so that an engineer, a contributor, or a diligence reviewer does not have to infer the
business model from the code.

## The short version

- **Open (Apache-2.0, with one scoped MIT wrapper):** the Execution Authority architecture, the portable
  `agent-safe.intent/1` binding, the trusted execution boundary, the client adapters, the audit
  contract, shadow mode, the conformance vectors, and the runnable examples.
- **Operated (Decionis, not in this repository):** the policy control plane that evaluates
  intents, issues and atomically consumes execution grants, signs and retains Decision Dossiers,
  and verifies human approval through Presence.
- **The seam:** two TypeScript interfaces and four versioned HTTP operations. Anyone can implement
  the interfaces. The library does not check a plan, key, or entitlement.

## What is Apache-2.0 here

| Component                                                                 | Where                                         | Why it is open                                                                                                            |
| ------------------------------------------------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `IntentCapture`, `CanonicalIntentHasher`, `agent-safe.intent/1`           | `packages/pipeline/src/intent`                | The intent contract must be independently implementable or the hash binding proves nothing                                |
| `SafeExecutor`, `ActionRegistry`, `AuthorizationVerifier`, `ReplayStore`  | `packages/pipeline/src/execution`             | The execution boundary runs inside the customer's trust domain and must be inspectable                                    |
| `DecionisGate`, `DecionisGrantVerifier`                                   | `packages/pipeline/src/decision`, `execution` | Client adapters for the published Decionis contract; they hold no policy logic                                            |
| `PresenceApprovalCoordinator`                                             | `packages/pipeline/src/approval`              | The evidence-not-authority rule for human approval is part of the architecture, not the product                           |
| CommerceGate MCP server (`@decionis/commerce`)                            | `packages/commerce-mcp`                       | A local STDIO client adapter over the published CommerceGate contract; it holds no policy logic and no marketplace client |
| `AuditRecorder`, `AuditPolicyRevisionVerifier`, `agent-safe.audit/1`      | `packages/pipeline/src/audit`                 | Customers own their evidence stream; the redaction and immutability rules are public                                      |
| `ShadowPipeline`                                                          | `packages/pipeline/src/shadow`                | The adoption path has to be trustworthy before enforcement is; see [shadow mode](./docs/shadow-mode.md)                   |
| `FixtureDecisionAuthority` and fixture verifier                           | `packages/pipeline/src/decision`              | Development test doubles; refuse to construct under `NODE_ENV=production`                                                 |
| `LocalPresence`, `LocalAuthority` (`./testing` entry)                     | `packages/pipeline/src/testing`               | Loopback doubles so anyone can test escalations locally; refuse to construct under `NODE_ENV=production`                  |
| Conformance vectors and synthetic Decision Dossier corpus                 | `conformance/`, `dossiers/`                   | Cross-implementation proof that canonicalization and offline verification are stable                                      |
| Examples, synthetic policies, threat model, architecture, release tooling | `examples/`, `policies/`, root docs           | Reference material and reproducible supply-chain evidence                                                                 |

The two runtime dependencies published by Decionis, `@decionis/presence-node` and
`@decionis/verify`, are also Apache-2.0.

## Scoped MIT Claude Desktop wrapper

`packages/commerce-mcp-claude-extension` is a narrowly scoped MIT-licensed wrapper containing its
loader, Claude Desktop manifest, icon, documentation, tests, and packaging verifier. The wrapper
depends on the Apache-2.0 `@decionis/commerce` workspace package only at build time. Its MCPB keeps
the built CommerceGate runtime as a separate `vendor/commerce-mcp/Index.js` artifact and includes a
byte-identical copy of the runtime's full Apache license, the repository NOTICE, and an explicit
mixed-license notice. Nothing under `packages/commerce-mcp` is relicensed; its source and npm
package remain Apache-2.0.

## What Decionis operates

The **policy control plane** is the hosted authority behind `DecionisGate`. It owns:

- policy authoring, revisions, and evaluation of the exact canonical intent in `SHADOW` or
  `ENFORCEMENT` mode;
- issuance of short-lived Ed25519 execution grants for an enforceable `ALLOW`, and the atomic
  single-use consume endpoint that `DecionisGrantVerifier` calls;
- Decision Dossier creation, signing, JWKS publication, retention, and the decision chain that
  links evaluation, approval, and execution evidence;
- Presence, the human-verification service, and the receipt verification that turns an approval
  into evidence for re-evaluation;
- tenant identity, server-side API credentials, and hosted shadow reporting.

None of that code is in this repository, and this repository does not proxy it. Production policy
bundles, customer data, and credentials are explicitly excluded by the
[public-repository policy](./README.md#public-repository-policy).

## The seam

**Code interfaces** (all exported from the package root):

```ts
interface DecisionAuthority {
  readonly evaluationMode?: "ENFORCEMENT" | "SHADOW";
  evaluate(intent: CapturedIntent, evidence?: DecisionEvidence): Promise<GateDecision>;
}

interface AuthorizationVerifier {
  verifyAndConsume(
    captured: CapturedIntent,
    decision: GateDecision,
  ): Promise<VerifiedAuthorization | null>;
  finalize?(input: AuthorizationFinalizationInput): Promise<"RECORDED" | "PENDING">;
}
```

`SafeExecutor` depends only on these interfaces plus `ReplayStore` and `AuditSink`. It contains no
Decionis-specific code path. A third-party or self-built authority that returns a bound
`GateDecision` and consumes its own grants atomically is a first-class citizen of the executor.

**Wire operations** (schemas in the Decionis OpenAPI specification):

| Operation                             | Used by                 | Purpose                                                                 |
| ------------------------------------- | ----------------------- | ----------------------------------------------------------------------- |
| `POST /v1/authority/enforce-and-bind` | `DecionisGate`          | Evaluate the exact binding; grant only for an enforceable `ALLOW`       |
| `POST /v1/execution/claim-token`      | `DecionisGrantVerifier` | Revalidate and atomically claim the single-use grant before dispatch    |
| `POST /v1/execution/finalize-token`   | `DecionisGrantVerifier` | Record the commit outcome so execution evidence joins the dossier chain |
| `POST /v1/execution/verify-token`     | diagnostics only        | Verify a grant binding without consuming it                             |
| Decision Dossier JWKS                 | `@decionis/verify`      | Verify production dossier signatures offline                            |

## Questions a reviewer will ask

**Can I run this without Decionis?** You can run the architecture, the tests, every example, and
shadow comparisons in development with the fixture authority. The fixture authority refuses to
construct under `NODE_ENV=production` by design: it is a test double, not a crippled community
edition. There is no open-source production policy engine in this repository today. A production
deployment needs a `DecisionAuthority` and `AuthorizationVerifier` implementation: the Decionis
service, or your own implementation of the interfaces above.

**Is the library feature-gated?** No. Nothing in the package checks a license key, plan, seat
count, or entitlement, and there are no hidden network calls. Every export is fully functional
against any conforming authority, and the packed tarball is tested from a clean consumer directory
with no registry access.

**Will the boundary move?** The project commits to the following, and changes to any of them go
through the [governance process](./GOVERNANCE.md) as trust-boundary changes with project-lead
approval in a public pull request:

1. The pipeline and CommerceGate runtime packages stay Apache-2.0. The dedicated Claude Desktop wrapper stays MIT, and its bundle preserves the runtime's Apache license and notice. There is no source-available or delayed-open license in the plan.
2. The `agent-safe.intent/1` binding, its conformance vectors, and the audit event contract stay
   public and versioned.
3. The Decionis wire contract used by the adapters stays published as OpenAPI.
4. `SafeExecutor` never gains a Decionis-only code path or a capability that only the hosted
   authority can unlock.
5. Contributions are accepted under the [Developer Certificate of Origin](https://developercertificate.org/),
   not a contributor license agreement. Decionis does not collect copyright assignments or
   relicensing rights from contributors.

**What does Decionis sell?** Operating the authority: the policy control plane, grant issuance and
consumption, Decision Dossier retention and verification, Presence, and reporting. Commercial terms
are not part of this repository.

**Can I fork it?** Yes, under each package's applicable license: Apache-2.0 for the repository and
runtime packages, and MIT for the dedicated Claude Desktop wrapper. The
[trademark policy](./TRADEMARKS.md) asks that a modified distribution not present itself as the
official project or imply Decionis endorsement. The README's request not to mirror the canonical
repository is about avoiding security-fix drift, not about restricting forks.

## Why this shape

Position on the execution path creates control; the evidence record creates accountability that
compounds. The part that must be inspectable and independently implementable, the execution
boundary and the intent contract, is open. The part that must be operated with continuity,
retention, and independent identity, the authority and its evidence store, is a service. The
repository's contribution is that execution cannot bypass the authority; the authority's
contribution is that its decisions are worth trusting. Keeping those two contributions in separate
trust domains is the architecture, not only the business model.
