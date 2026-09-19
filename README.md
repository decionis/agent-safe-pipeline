# AgentSafe

[![Continuous integration](https://github.com/decionis/agent-safe-pipeline/actions/workflows/deploy.yml/badge.svg?branch=master)](https://github.com/decionis/agent-safe-pipeline/actions/workflows/deploy.yml)
[![CodeQL](https://github.com/decionis/agent-safe-pipeline/actions/workflows/codeql.yml/badge.svg?branch=master)](https://github.com/decionis/agent-safe-pipeline/actions/workflows/codeql.yml)
[![Secret scanning](https://github.com/decionis/agent-safe-pipeline/actions/workflows/secrets.yml/badge.svg?branch=master)](https://github.com/decionis/agent-safe-pipeline/actions/workflows/secrets.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/decionis/agent-safe-pipeline/badge)](https://scorecard.dev/viewer/?uri=github.com/decionis/agent-safe-pipeline)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14098/badge)](https://www.bestpractices.dev/projects/14098)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**Put an authority boundary in front of any agent or API.**

AgentSafe intercepts consequential actions and checks whether they are authorized before
forwarding them. An agent, an application or a tool sends its HTTP request to AgentSafe instead of
the target; AgentSafe captures the action as an intent, asks the [Decionis](https://decionis.com)
control plane (the Independent Execution Authority, bound to the exact action) for a decision, and
forwards exactly the authorized request once on a claimed single-use grant, holds it for a person,
or refuses it, leaving a chained record of each. It decides nothing itself.

```bash
brew tap decionis/agent-safe https://github.com/decionis/agent-safe-pipeline && brew trust decionis/agent-safe && brew install agentsafe

agentsafe proxy \
  --upstream http://localhost:3000 \
  --port 8080
```

[5-minute quickstart](./docs/quickstart/README.md) · [Homebrew](./docs/install/macos.md) ·
[Linux](./docs/install/linux.md) · [Docker](./docs/install/docker.md) ·
[Kubernetes](./docs/install/kubernetes.md) · [Hosted](./docs/install/hosted.md)

> The installed forms are produced by the release workflow from `v0.2.0` on; the Homebrew formula
> reaches master by its own pull request after each release. The same commands run from a clone,
> as the quickstart shows.

The path from here is short: discover, install, **test your boundary**, see what is exposed, run in
shadow, enforce, deploy.

## The two systems behind the boundary

Arriving here for the first time, you meet three names. This repository is one of them; the other
two are the services it talks to, and neither is in this repository.

- **Decionis** is the Independent Execution Authority, bound to the exact action: the control
  plane AgentSafe asks. For one captured intent it evaluates the organization's policy and answers
  `ALLOW`, `ESCALATE` or `BLOCK`; an `ALLOW` comes with the single-use execution grant the request
  executes on, an `ESCALATE` with the human ceremony it needs, and every decision with a signed
  [Decision Dossier](https://decionis.com/docs/decision-dossier) that records what was proposed,
  what was decided and why. It runs at [decionis.com](https://decionis.com)
  ([docs](https://decionis.com/docs)); the local demo authority in this repository stands in for it
  on loopback with a synthetic policy, and says so on every line.
- **Presence** is the adaptive human verification layer. When Decionis answers `ESCALATE`, a
  verified, present person on their own device approves that exact action, and the signed Presence
  Record that results is evidence Decionis re-checks before it issues a grant, never authority by
  itself. It runs at [presence.decionis.com](https://presence.decionis.com)
  ([what the layer is](https://decionis.com/proof-of-human-infrastructure)); the loopback double
  in this repository simulates the ceremony for the examples and proves nothing about a real one.
- **AgentSafe**, this repository, is the execution boundary between your agent or API and those
  two: it captures the exact intent, asks Decionis, resolves an `ESCALATE` with Presence, forwards
  exactly the authorized request once on the claimed grant, holds or refuses the rest, and leaves
  chained evidence. It is Apache-2.0 and it decides nothing; [`OPEN-CORE.md`](./OPEN-CORE.md)
  states the seam between it and what Decionis operates.

## Test your boundary

Before putting the gateway in front of anything, see what it changes. `agentsafe test` sends the
same consequential requests three ways at a synthetic target that records what reaches it:
directly, as an agent with nothing in the way; through the gateway in shadow; and through the
gateway in enforcement. Nothing real is called and nothing of yours is read.

```bash
agentsafe test
```

```text
                                                direct                                shadow                                                     enforcement
A read                                          reached 200                           reached 200                                                reached 200 (not consequential)
A payment within policy                         reached 201                           reached 201, would ALLOW                                   ALLOW: forwarded once, 201, dossier
A payment above the human ceiling               reached 201                           reached 201, would BLOCK                                   BLOCK 403, NOT FORWARDED
A payment above the autonomous ceiling          reached 201                           reached 201, would ESCALATE                                ESCALATE 202, HELD
Deleting a customer record                      reached 204                           reached 204, would ESCALATE                                ESCALATE 202, HELD
A forged approval on a blocked payment          reached 201, forged headers accepted  reached 201, would BLOCK                                   BLOCK 403, NOT FORWARDED
A consequential request the policy cannot read  reached 201                           reached 201, would ESCALATE                                ESCALATE 202, HELD
A payment while the authority is unreachable    reached 201                           reached 201, would decide nothing (authority unreachable)  AUTHORITY UNAVAILABLE 503, NOT FORWARDED
                                                with failurePolicy failOpen (explicit): reached 201, marked FORWARDED (fail-open, ungoverned)

Exposure    6 of 6 adversarial actions reached the target directly, 6 of 6 in shadow, 0 of 6 under enforcement
Work        routine actions went through under enforcement, once each
Evidence    26 chained lines, verified

Verdict     BOUNDARY HOLDS
```

The gateways under test are the ones `agentsafe proxy` runs, behind the same listener; the
authority is the local demo policy. `agentsafe test ledger=ledger.internal:443` also dials a real
system of record from where you stand and says whether it answers without the gateway, which is
what an agent could reach by going around. Exit `0` is a boundary that holds; `1` is exposure;
`--json` is the report as one line. The release smoke test runs it on every packaged binary.

## Five-minute quickstart

Nothing here needs an account: without a Decionis key the gateway runs a local demo authority in
the same process, on loopback, with a synthetic policy, and says so on every line.

```bash
agentsafe proxy --upstream http://localhost:3000 --port 8080
```

```text
AgentSafe 0.1.0

Gateway      http://127.0.0.1:8080
Upstream     http://localhost:3000
Mode         ENFORCEMENT
Authority    local/demo (synthetic policy on loopback; not Decionis)
Failure      fail-closed
Routes       none named; every unsafe method is governed
Evidence     not written; use --verbose or evidence.journalDir
Status       READY

Waiting for consequential actions...
```

Send it one request:

```bash
curl -i -X POST http://127.0.0.1:8080/payments -H 'content-type: application/json' -d '{"amount": 500}'
```

```text
ESCALATE

POST /payments

Action       http.post
Decision     ESCALATE
Reason       HUMAN_APPROVAL_REQUIRED
Execution    HELD
Dossier      synthetic-dossier-1
Latency      4ms
```

The caller gets `202` and nothing reached the upstream. `{"amount": 50}` is `ALLOW`: forwarded
once, byte for byte, with the dossier id beside the upstream's own answer. `{"amount": 5000}` is
`BLOCK`: `403`, not forwarded. A `GET` passes through untouched. Every state has its own heading
and, with a terminal, its own color: `ALLOW`, `BLOCK`, `ESCALATE`, `SHADOW`, `AUTHORITY
UNAVAILABLE`. `--verbose` shows the chained evidence lines; `agentsafe init` writes the
configuration file; `agentsafe doctor` says what would stop it from governing; `agentsafe login`
connects a Decionis key, after which the same gateway asks Decionis, in shadow first. The
[quickstart](./docs/quickstart/README.md) is the full walk, and the
[CLI reference](./docs/reference/cli.md) every command.

## How it works

```text
Agent / Application / Tool
          │
          ▼
      AgentSafe
   ingress / interceptor          captures the action as an intent (agent-safe.intent/1)
          │
          ▼
 Decionis Control Plane           policy, ExecutionBinding, Presence, Decision Dossiers
          │
   ALLOW | BLOCK | ESCALATE
          │
          ▼
      AgentSafe                   claims the single-use grant, forwards the exact bytes once
          │
          ▼
   Target Service / API
          │
          ▼
       finalize                   COMMITTED | FAILED | INDETERMINATE, on the Decision Dossier
```

AgentSafe owns ingress and interception, action extraction and normalization, enforcement of the
verdict, claim-before-forward, forwarding, effect evidence, finalization, fail-safe behavior and
the local ergonomics. Decionis owns execution authority: policy evaluation, `ALLOW` / `BLOCK` /
`ESCALATE`, policy versioning, ExecutionBinding semantics, Presence verification, Decision Dossiers,
and the verification of evidence and authority. AgentSafe is not a second policy engine: the local
demo authority is a loopback double of the Decionis routes, named `local/demo` everywhere, refused
in production.

| State                   | What happened                                                                                  | The caller sees                                                                                   |
| ----------------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `ALLOW`                 | The grant was claimed and the exact request forwarded once                                     | The upstream's response, plus `agentsafe-decision`, `agentsafe-dossier-id`, `agentsafe-execution` |
| `ESCALATE`              | Held for a person; with Presence, a resume asks Decionis again                                 | `202`, `execution: HELD`, a `resume` path                                                         |
| `BLOCK`                 | Refused; nothing forwarded                                                                     | `403` with the dossier that records why                                                           |
| `AUTHORITY_UNAVAILABLE` | Decionis could not be asked; fail-closed refuses, fail-open forwards ungoverned and records it | `503` with `Retry-After`, never a `BLOCK`                                                         |
| `SHADOW`                | Forwarded unchanged while Decionis recorded what it would have decided                         | The upstream's response, `agentsafe-mode: SHADOW`                                                 |

What is bound and forwarded, and what each outcome finalizes as, is
[docs/gateway/http-interception.md](./docs/gateway/http-interception.md); what happens when the
authority cannot be reached is [docs/gateway/failure-policy.md](./docs/gateway/failure-policy.md);
the configuration, one schema for every distribution with the precedence flags, environment, file,
defaults, is [docs/gateway/configuration.md](./docs/gateway/configuration.md).

## Install

One runtime, five ways to run it. The executable, the packages, the image and the chart are built
and smoke-tested by the release workflow from the same code; nothing about authority, binding,
claim or finalization differs between them.

| Where       | How                                                                                                                                                                | Page                                       |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------ |
| macOS       | `brew tap decionis/agent-safe https://github.com/decionis/agent-safe-pipeline && brew trust decionis/agent-safe && brew install agentsafe`                         | [macOS](./docs/install/macos.md)           |
| Linux       | `curl -fsSL https://raw.githubusercontent.com/decionis/agent-safe-pipeline/master/packaging/install.sh \| sh`, or the `.deb` / `.rpm` with a hardened systemd unit | [Linux](./docs/install/linux.md)           |
| Docker      | `ghcr.io/decionis/agentsafe:<version>`, distroless, non-root, two architectures                                                                                    | [Docker](./docs/install/docker.md)         |
| Kubernetes  | `helm install agentsafe oci://ghcr.io/decionis/charts/agentsafe`, one Deployment in front of one Service                                                           | [Kubernetes](./docs/install/kubernetes.md) |
| Hosted      | `agentsafe.decionis.com`, the same runtime behind one listener; not live yet                                                                                       | [Hosted](./docs/install/hosted.md)         |
| From source | `git clone`, `pnpm install --frozen-lockfile`, `pnpm build`, `node packages/agentsafe/dist/Cli.js`                                                                 | [Quickstart](./docs/quickstart/README.md)  |

Every install page ends at the same place: send your first governed action.

## Golden adversarial demo

One legitimate path and eight adversarial attempts against the same boundary, offline, in a few seconds, with every expectation asserted:

```bash
git clone https://github.com/decionis/agent-safe-pipeline.git && cd agent-safe-pipeline
pnpm install --frozen-lockfile
pnpm --filter @decionis/agent-safe-example-golden-adversarial demo
```

A treasury agent proposes a USD 250,000 wire, a remote Chief Risk Officer completes a FIDO2 plus liveness ceremony, and exactly one wire executes. Injected authorization fields, a fabricated ALLOW, an asserted approval, a swapped receipt, a post-approval amount change, a replayed grant, 25 concurrent claims, a shadow observation, and an expired grant all fail to execute. The run exits 0 only when that holds. See [`examples/golden-adversarial-demo`](./examples/golden-adversarial-demo), the bank-audience walkthrough in [`docs/remote-cro-authorization.md`](./docs/remote-cro-authorization.md), and the receipt semantics in [`docs/presence-evidence.md`](./docs/presence-evidence.md).

## Execution lifecycle

For a consequential action, in every distribution and in the library alike:

```text
request → normalize intent → enforce-and-bind → ALLOW | BLOCK | ESCALATE

ALLOW    → claim-token → forward the exact authorized action, once → capture effect → finalize-token
           COMMITTED | FAILED | INDETERMINATE
BLOCK    → nothing is forwarded
ESCALATE → nothing is forwarded → Presence, or a managed ceremony Decionis runs → signed approval
           evidence → Decionis reauthorization → a new grant → claim → execute once → finalize
```

An `ESCALATE` is never turned into an `ALLOW` locally, and a Presence approval is never trusted
without Decionis reauthorization. The pages under [docs/authority](./docs/authority/execution-binding.md)
map each step onto the protocol: [ExecutionBinding](./docs/authority/execution-binding.md),
[claim and finalize](./docs/authority/claim-finalize.md), [Presence](./docs/authority/presence.md),
[evidence](./docs/authority/evidence.md). The provider's half, the procedure by which a system of
record or the hop in front of it refuses what the authority never claimed, is the
[Verifying Provider Profile](./docs/authority/verifying-provider.md), with
[vectors](./conformance/provider/README.md) any implementation can run and independent verifiers
that run them, for [Envoy `ext_authz`](./verifiers/envoy/README.md) and
[Kong](./verifiers/kong/README.md), for [Spring and Apigee](./verifiers/spring/README.md), for
[Rust services with a tower layer](./verifiers/rust/README.md), and for
[ASP.NET Core](./verifiers/dotnet/README.md).

### Production invariants

1. Agent input contains only the proposed action, target, and parameters. Tenant, actor, downstream target, and credentials come from trusted runtime configuration.
2. The exact canonical intent is hashed and expires quickly.
3. Decionis independently decides. Network errors, malformed responses, missing grants, or binding mismatches fail closed.
4. Presence proves a human approved that exact intent; Presence never directly authorizes execution. Decionis verifies the receipt and re-evaluates policy.
5. The grant is bound to the intent, decision, audience, and expiry and is claimed atomically before the handler runs; the attempt outcome is finalized with the authority afterwards as evidence, never as authority.
6. Downstream credentials exist only behind the trusted executor.
7. Every decision is evidence-bearing. An ALLOW whose response lacks a dossier identifier or grant is refused as non-executable, and an executed result retains its consumed `{decisionId, dossierId, grantId}` binding. A dossier identifier is never an execution credential.

## Presence

[Presence](https://presence.decionis.com), the adaptive human verification layer, supports two
explicit integration levels. In DIRECT mode, the trusted executor coordinates Presence and returns
the receipt reference to Decionis. In MANAGED mode, the executor asks Decionis
to orchestrate Presence and polls Decionis for a terminal status. Both modes require independently
signed Presence evidence, exact-intent verification, current-policy re-evaluation, and the same
claim-before-handler grant path. Invitation delivery and Presence evidence are never execution
authority, and approval cannot revive a five-minute intent after it expires.

The gateway holds an `ESCALATE` and, with `presence.managed: true`, asks Decionis to orchestrate the ceremony; a resume through `/_agentsafe/v1/escalations/{intent_id}/resume` asks Decionis again, and only a fresh `ALLOW` with a grant executes the held request, once. [docs/authority/presence.md](./docs/authority/presence.md) says what a receipt establishes and what it does not; [`docs/human-approval.md`](./docs/human-approval.md) and [`docs/presence-evidence.md`](./docs/presence-evidence.md) are the protocol pages.

See [`docs/trust-boundary.md`](./docs/trust-boundary.md) before integrating a real downstream API.

## Decision evidence

Five records matter and are easy to blur in a summary: the captured intent, the verified human approval, the execution grant, the Decision Dossier, and the outcome. Only the grant authorizes anything, once; a dossier identifier is never an execution credential. [What each record establishes](#what-each-record-establishes) says so row by row.

The Execution Authority architecture has two load-bearing properties. Position on the execution path creates control: nothing runs without an independent decision at the moment of action. The evidence record creates accountability that compounds: every decision adds to an auditable history of what was authorized, under which policy, on whose approval.

Every Decionis evaluation is recorded as a Decision Dossier, and each `GateDecision` returns the `decisionId` and `dossierId` of that record. Escalations attach the verified Presence `receiptDossierId`, and every executed action returns the consumed grant's `{decisionId, dossierId, grantId, intentHash}` binding, so execution results correlate to their evidence without extra bookkeeping. In the research vocabulary, dossiers compound into a Decision Chain: tamper-evident lineage linking evaluation, approval, and execution evidence across workflows. Decionis maintains that record; this repository's contribution is that execution cannot bypass it.

Treat dossier identifiers as audit and support references, never as execution credentials — see [`docs/decision-dossiers.md`](./docs/decision-dossiers.md).

### What each record establishes

Fluent summaries lose these distinctions first. Each row names the record or state, what it
establishes, and what it does not.

| Record or state                                           | What it establishes                                                                                                                                                                                                                                                                                                                                                                                                                             | What it does not establish                                                                                                                                                                                                                              |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Captured intent (`IntentCapture`, `intentHash`)           | The exact action, target, and parameters the agent proposed, bound to trusted tenant, actor, and downstream context, hashed and expiring                                                                                                                                                                                                                                                                                                        | That the agent's facts, identities, or amounts are true; that anything may execute                                                                                                                                                                      |
| Verified human approval (Presence `receiptDossierId`)     | A named person approved that exact intent hash under the assurance the receipt records                                                                                                                                                                                                                                                                                                                                                          | Permission to execute: Decionis re-evaluates policy with the receipt, and only that evaluation can issue a grant                                                                                                                                        |
| Execution grant (`authorization` on an `ALLOW`)           | Permission for one attempt at one intent, claimed once through the `AuthorizationVerifier` immediately before the handler runs                                                                                                                                                                                                                                                                                                                  | Anything after expiry, for another intent hash, or on a second presentation; a dossier identifier, an invitation link, or an earlier `ALLOW` is not a substitute                                                                                        |
| Decision Dossier (`decisionId`, `dossierId`)              | The record of why Decionis allowed, escalated, or blocked: policy snapshot, inputs, evidence, and grant metadata                                                                                                                                                                                                                                                                                                                                | An execution credential; proof that the underlying business judgement was right                                                                                                                                                                         |
| Single claim, `COMPLETED`                                 | The grant was consumed once and the trusted handler returned a provider result                                                                                                                                                                                                                                                                                                                                                                  | An exactly-once downstream business effect or independent confirmation of settlement; whether an observation counts as `CONFIRMED` is the authority's judgement, not this package's                                                                     |
| `UNKNOWN_AFTER_DISPATCH`, finalized `INDETERMINATE`       | Dispatch began and completion could not be proved                                                                                                                                                                                                                                                                                                                                                                                               | Permission to repeat the side effect: reconcile through provider idempotency and read-only lookup, never by a second dispatch                                                                                                                           |
| `DEFINITELY_NOT_EXECUTED`, finalized `FAILED`             | Dispatch began, the provider refused it deterministically, and nothing was effected                                                                                                                                                                                                                                                                                                                                                             | Permission to try again: the refusal was about this attempt, and another needs a fresh decision and a fresh grant                                                                                                                                       |
| Shadow observation (`ShadowPipeline`, `mode: "SHADOW"`)   | What Decionis would have decided about an action that already ran: a verdict and a dossier, no grant                                                                                                                                                                                                                                                                                                                                            | Enforcement, a grant, or a no-write test environment; the production write happened as before                                                                                                                                                           |
| Library boundary (this package)                           | Intent capture, the gate, verification, and claim-before-handler dispatch inside the trusted integration                                                                                                                                                                                                                                                                                                                                        | Host isolation, IAM, network egress, credential storage, or incident response                                                                                                                                                                           |
| Trusted executor (`createTrustedExecutor`)                | What one process verifies about itself and enforces at its own door: the host posture `HostPosture` can observe, caller principals with roles and their own credentials, egress sealed to the origins `EgressPolicy` was configured with, a durable attempt journal reconciled by `StartupReconciler`, the ceilings in `HardLimits`, BEAP-vocabulary effect evidence, `HaltSwitch`, and hash-chained evidence with an offline-verifiable export | Node or kernel isolation, a CNI actually enforcing the NetworkPolicies the kit declares, an HSM or KMS, the authority's policy, or a bank's core correctness                                                                                            |
| Executor evidence bundle (`agent-safe.evidence-bundle/1`) | What one executor process can say about an incident: both hash-chained streams as it still held them, the open attempts, the posture by check, the chain heads, a configuration digest, and every file's own digest                                                                                                                                                                                                                             | Origin, unless a signature over the manifest verifies against a key the reader brought; completeness, since it carries a bounded window and says how many lines it dropped; and it holds no parameter, no provider body, no secret and no digest of one |

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
npx -y @decionis/verify@0.3.0 \
  --file /absolute/path/to/live-decision-dossier.json \
  --jwks https://api.decionis.com/v1/.well-known/decision-dossier-jwks.json
```

See the [corpus README](./dossiers/README.md) for regeneration, provenance, expected failures, and
the trust boundary between synthetic conformance and production verification.

## Architecture

```text
Untrusted                              Trusted control plane

Agent proposal                         runtime identity/config
     |                                         |
     +--------------> IntentCapture <----------+
                            |
                    canonical intent hash
                            |
                       DecionisGate
                     /      |       \
                 ALLOW  ESCALATE   BLOCK
                   |        |         |
                   |     Presence     stop
                   |        |
                   |  verified receipt
                   |        |
                   +--- Decionis re-evaluation
                            |
                     single-use grant
                            |
                       SafeExecutor
                            |
                sealed trusted ActionRegistry
                            |
                    downstream credential
```

This repository ships the library `@decionis/agent-safe-pipeline` and, over it, the runtime
`@decionis/agentsafe`, one binary with two ingresses: `agentsafe proxy`, the HTTP-interception
gateway above, and `agentsafe serve`, the trusted executor for a bank boundary, with principals, a
downstream credential, a verified host posture, and the [deployment kit](./deploy/README.md). Both
run the same lifecycle objects; the [discovery report](./docs/architecture/distribution-discovery.md)
traces one action through them and [ADR 0001](./docs/architecture/decisions/0001-http-interception-ingress.md)
records why the gateway is a second ingress and not a second implementation. None of it is a
hosted authorization service, an identity provider or a KMS, and no process can make a cluster
enforce the network policies the kit and the chart declare; [who owns which control](./EVALUATION-PATH.md#who-owns-which-control)
assigns each one.

Canonical source: <https://github.com/decionis/agent-safe-pipeline>. Copies of this repository at other hosts — including sites that reverse-proxy github.com wholesale — are not maintained by Decionis, lag security fixes, and are not what the npm package, the Zenodo record, or decionis.com cite. Verify any copy against the signed release tags ([docs/release-tag-signing.md](./docs/release-tag-signing.md)).

### The library

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

### Optional: a signed Decision Dossier from Decionis

Everything above runs locally and always will. The fixture authority evaluates in process, with no
network call and no account, and that path stays supported: it is not a trial, not a reduced tier,
and nothing in this repository stops working if you never do this step.

What the local path cannot do is prove a decision to someone else. With one variable, every example
asks Decionis to evaluate the same intent beside the fixture and ends with the thing only the
authority can produce: a Decision Dossier, a signed record of what was proposed, what was decided
and why, whose Ed25519 signatures verify against the authority's published keys, offline, with no
account.

```bash
DECIONIS_HOSTED=1 pnpm --filter @decionis/agent-safe-example-basic demo
```

No key? The run mints one: a free provisional workspace from
`POST https://api.decionis.com/v1/public/agents/provision`, no signup, no email, no card, with an
allowance of 50 governed decisions a month, kept in `~/.config/agentsafe/credentials.json` so the
next run reuses it. The first run says so on standard error:

```text
decionis: provisioned a free workspace 7f0c3a5e-... (provisional, no account; 50 governed decisions a month)
decionis: key stored at /home/you/.config/agentsafe/credentials.json; the next run reuses this workspace
```

Then the run prints exactly what it printed before, and ends with:

```text
verdict: BLOCK
decionis: ALLOW (SHADOW, recorded beside the local verdict)
  - POLICY_AUTONOMOUS_LIMIT
dossier: 6b2e5c1e-4b3a-4f0e-9c6d-2a1f7e8d9b0c
verify it yourself, no account needed: pnpm decionis:verify 6b2e5c1e-4b3a-4f0e-9c6d-2a1f7e8d9b0c
signed dossier: 6b2e5c1e-4b3a-4f0e-9c6d-2a1f7e8d9b0c (14211 bytes, ALLOW)
  Ed25519 by key decionis-dossier-2026-09 at 2026-09-18T01:02:03.000Z, 3 signed artifact(s)
  issuer: provisional_anonymous (a workspace without an account; claim it to keep it)
```

When the authority attaches a verification page to the decision, one more line names it: a URL
anyone can open, with no account, to see the signatures checked. `pnpm decionis:verify <id>`
fetches the record with the stored key, resolves the public JWKS the record names, and checks
every signed artifact with [`@decionis/verify`](https://www.npmjs.com/package/@decionis/verify),
which uses only Node's built-in crypto; it prints each check, who minted the record, and `VERIFIED`
or `NOT VERIFIED`. Add `--out dossier.json` to keep the signed record; anyone holding that file can
repeat the check with the command under [Verify Decision Dossiers](#verify-decision-dossiers), with
no key at all.

A provisional key evaluates in `SHADOW` only: the fixture's verdict still governs execution, and the
hosted decision and its dossier are recorded beside it. Every dossier it mints carries a signed
`provisional_anonymous` issuer tier, so a verifier can always tell it from an owned organization's
record. Claiming the workspace (the response says how) attaches a person and keeps the key and the
ledger. An owned organization's key, from the Decionis console or `agentsafe login`, takes the mode
you ask for, `ENFORCEMENT` included.

Which examples do what: `basic-agent`, `shopify-refund-agent`, `github-deploy-agent`,
`mcp-tool-gate` and `procurement-agent` evaluate their one proposal beside the fixture;
`golden-adversarial-demo`, `whisper-boundary-demo`, `crm-outreach-demo` and `local-escalation` run
their adversarial attempts locally by design and end with the golden proposal evaluated by
Decionis; `trusted-executor` runs the executor process once more in shadow against Decionis; the
two Presence examples need an owned organization with an enrolled approver, and say so when given
a provisional workspace.

#### How it is wired

`createHostedGate` in [`packages/pipeline`](./packages/pipeline/README.md#one-variable-a-key-issued-in-the-run)
reads the environment and returns the authority and verifier the example runs:

| Variable              | Default                    | Effect                                                                                                                                                                                                                    |
| --------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DECIONIS_HOSTED`     | unset                      | `1`: with no key, the stored credential, else a free provisional workspace minted in the run and stored for the next; the hosted evaluation runs in `SHADOW`.                                                             |
| `DECIONIS_API_KEY`    | unset                      | Unset: the fixture pair, the same objects as before, and no client is built. Set: `DecionisGate` runs beside the fixture, whatever `DECIONIS_HOSTED` says.                                                                |
| `DECIONIS_TENANT_ID`  | required with the key      | The key's organization. Decionis binds every intent to it, so the examples capture under it instead of their synthetic tenant.                                                                                            |
| `DECIONIS_MODE`       | `SHADOW`                   | `SHADOW`: the fixture's verdict still governs execution; the hosted verdict and dossier are recorded. `ENFORCEMENT`: the hosted decision governs and its grant is claimed with Decionis; the fixture can only tighten it. |
| `DECIONIS_API_URL`    | `https://api.decionis.com` | HTTPS only, for staging or a loopback double with `DECIONIS_ALLOW_INSECURE_LOOPBACK=true`.                                                                                                                                |
| `DECIONIS_TIMEOUT_MS` | `4000`                     | Budget for the hosted call. A call past it is recorded as fail-closed.                                                                                                                                                    |

Hosted mode fails closed. A timeout, a network error, a non-2xx response, a body that is not the
contract's decision, a verdict the contract does not define, a decision about another intent, or an
intent that expired before evaluation is recorded as `BLOCK` from the hosted side, with no grant. In
`SHADOW` that is recorded and the fixture's verdict still governs, so setting a key cannot change what
a working fork does; in `ENFORCEMENT` it blocks, as the threat model requires. Neither mode is ever
less restrictive than the fixture alone; the matrix is asserted in
[`ShadowGate.test.ts`](./packages/pipeline/test/decision/ShadowGate.test.ts) and every failure mode in
[`FailClosed.test.ts`](./packages/pipeline/test/decision/FailClosed.test.ts).

Only the captured intent leaves your process: the action, target and parameters the agent proposed,
and the tenant, actor, downstream target, expiry and context the trusted configuration supplied. It
is the same `ExecutionIntentBinding` the intent hash covers, and nothing else; credentials live behind
the executor and are never part of an intent. The request body is pinned field by field in
[`FailClosed.test.ts`](./packages/pipeline/test/decision/FailClosed.test.ts).

Beside it, every hosted call carries a `User-Agent` naming this package and its version, and from
the examples the upstream repository slug and the example name, so Decionis can count which example
a key was first used from. That is the whole of it: the header is sent only when a key is set, it
is not decision input and does not enter the dossier, and an integration that passes no `source`
sends the package name and version alone.

To go back: delete the key. That is the whole rollback.

### From the fixture to Decionis

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

See the [package README](./packages/pipeline/README.md) for the complete enforcement example and [`docs/shadow-mode.md`](./docs/shadow-mode.md) for the shadow rollout path. To move an example between the stages with configuration alone, see [Optional: a signed Decision Dossier from Decionis](#optional-a-signed-decision-dossier-from-decionis).

To run the boundary as its own service rather than in-process, [`packages/agentsafe`](./packages/agentsafe) is the executor as a process: `@decionis/agentsafe`, a listener in front of the same components with a seam for your handlers. [`examples/trusted-executor`](./examples/trusted-executor) is its proof over real HTTP against the loopback doubles and the template an adopter starts from. [`deploy/`](./deploy) is its image, the Kubernetes manifests for the two zones with every credential referenced and never written, and the runbook from shadow to enforcement.

## Research and specifications

Decionis Research defines the Execution Authority architecture, this repository demonstrates it as runnable, tested code, and the Decionis platform operates it as a hosted authority. The provenance chain is research paper -> protocol contract -> reference implementation (this repository) -> production service.

Published research:

- Jejelowo, Festus. "The Execution Verifiability Gap: Why Model Governance Cannot Authorize Consequential Actions." Decionis Research, version 1.0, 21 August 2026. [Canonical article](https://decionis.com/research/execution-verifiability-gap) · [Archival PDF](https://decionis.com/research/execution-verifiability-gap-v1.0.pdf) · [Research index](https://decionis.com/research).

Profiles of the protocol: the [Banking Execution Authority Profile (BEAP)](https://banking.decionis.com) applies this architecture to a bank's disbursement, payment run, or limit increase — execution domains, the canonical banking instruction, batch binding, multi-party sign-offs, effect evidence — and its reference runtime builds on `@decionis/agent-safe-pipeline`. BEAP v1.0 was published on 2026-09-15: the profile Decionis publishes and implements, not a standard approved by any body; the 0.1 draft is frozen and mirrored under `profiles/beap/v0.1`. Half of its runtime is here and half is not: the profile's section 24.5 names `@decionis/agentsafe` as the reference Trusted Executor, the executor-side subset it implements is listed in [docs/beap-conformance.md](./docs/beap-conformance.md), and the authority-side half — policy, grants, dossiers, the L1 and L2 requirements — is not in this repository and is not claimed by it. Being named a reference is not a conformance claim, and none is made: the executor implements the 1.0 identifiers, moved together with the profile's other runtimes.

Proof-of-human infrastructure: the [proof-of-human infrastructure page](https://decionis.com/proof-of-human-infrastructure) on the platform site says what the human-authority layer is — a verified, present person on their own device, bound to one exact action, sealed in a signed Presence Record the authority re-checks before commit — and the [Presence property](https://presence.decionis.com) is where it runs; this repository's `PresenceApprovalCoordinator` and the `examples/local-escalation`, `examples/presence-live-approval` and `examples/presence-managed-approval` examples are the reference for resolving an ESCALATE with it. Production enforcement is sales-assisted; the loopback double simulates the ceremony and proves nothing about a real one.

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

## Repository map

- [`packages/pipeline`](./packages/pipeline) — `IntentCapture`, `DecionisGate`, Presence coordination, and `SafeExecutor`.
- [`packages/agentsafe`](./packages/agentsafe) — `@decionis/agentsafe`, the trusted executor as one deployable process: the HTTP listener, the configuration, escalation resolution, and the handler seam in front of `packages/pipeline`, with its own image.
- [`packages/commerce-mcp`](./packages/commerce-mcp) — `@decionis/commerce`, the CommerceGate MCP server: lets an AI agent check a price change, stock change, order, fulfillment step, promotion, refund or return against the merchant's policy before acting, and read the signed record afterwards. A client adapter over the published Decionis contract; it holds no policy and contains no marketplace client.
- [`packages/commerce-mcp-claude-extension`](./packages/commerce-mcp-claude-extension) — the dedicated MIT-licensed Claude Desktop wrapper and packaging checks. Its MCPB vendors the unchanged Apache-2.0 CommerceGate runtime with that runtime's license and notice.
- [`examples/golden-adversarial-demo`](./examples/golden-adversarial-demo) — the self-checking proof: one golden path, eight attacks, zero unauthorized executions.
- [`examples/whisper-boundary-demo`](./examples/whisper-boundary-demo) — the same proof for a shopping agent: merchant-text steering, a cross-session credential lookup, a cart changed after signing, constraints lost in context compaction, and principal loss across a delegation hop — six attacks, zero unauthorized effects.
- [`examples/crm-outreach-demo`](./examples/crm-outreach-demo) — the same proof for a sales-development agent: who can approve a CRM update or an outbound message, a recipient changed after approval, an off-template message, an opted-out contact, an expired approval, and a provider response lost after dispatch that is reconciled once and never re-sent — six attacks, zero unauthorized effects.
- [`examples/basic-agent`](./examples/basic-agent) — the smallest BLOCK flow.
- [`examples/shopify-refund-agent`](./examples/shopify-refund-agent) — amount-based ALLOW / ESCALATE / BLOCK.
- [`examples/github-deploy-agent`](./examples/github-deploy-agent) — environment and force-push controls.
- [`examples/procurement-agent`](./examples/procurement-agent) — an in-budget software request held when existing tools still have user capacity.
- [`examples/mcp-tool-gate`](./examples/mcp-tool-gate) — a real stdio MCP server with a governed tool.
- [`examples/presence-live-approval`](./examples/presence-live-approval) — a Presence-bound enforcement against the real services with a FIDO2 or FIDO2-plus-liveness ceremony; needs real credentials.
- [`examples/presence-managed-approval`](./examples/presence-managed-approval) — Decionis-managed Presence orchestration with Decionis-only polling and no Presence credential in the executor.
- [`examples/local-escalation`](./examples/local-escalation) — both Presence integration modes against loopback Decionis and Presence doubles, no credentials, ceremony simulated.
- [`examples/trusted-executor`](./examples/trusted-executor) — the proof of `@decionis/agentsafe` over real HTTP against the loopback doubles, and the template an adopter starts from: the handler seam and a process of a few lines.
- [`deploy/`](./deploy) — the deployment kit: the executor image, conformance-tested Kubernetes manifests for the agent zone and the executor zone with Secrets referenced and never written, and the runbook from shadow to enforcement.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) and [`THREAT-MODEL.md`](./THREAT-MODEL.md) — trust boundary and abuse analysis.
- [`OPEN-CORE.md`](./OPEN-CORE.md) — what is Apache-2.0 here, what Decionis operates, and the seam between them.
- [`docs/`](./docs) — concepts, execution intent, outcomes, human approval, [Presence Evidence semantics](./docs/presence-evidence.md), the [remote CRO sequence](./docs/remote-cro-authorization.md), shadow mode, Decision Dossiers, trust boundary, the [executor's chained evidence](./docs/executor-evidence.md), [what the executor implements of the BEAP v0.1 banking profile](./docs/beap-conformance.md), [incident response for the executor](./docs/incident-response.md), [where a bypass of the executor is actually stopped](./docs/bypass-resistance.md), and assurance notes.
- [`conformance/agent-safe-intent-v1.json`](./conformance/agent-safe-intent-v1.json) — portable canonical-hash test vector.
- [`conformance/vectors/`](./conformance/vectors/) — edge-case canonical-hash vectors (Unicode/astral, NFC vs NFD, negative zero, fractional/exponent numbers, nested arrays, UTF-16 key sort order), auto-discovered by the conformance test.
- [`dossiers/`](./dossiers/) — reproducible synthetic Decision Dossier corpus with canonical bytes, SHA-256 digests, Ed25519 signatures, and a deliberately published corpus key.
- [`tests/integration/contract/`](./tests/integration/contract/) — loopback Decionis and Presence stubs that exercise the packed package's complete wire contract over real HTTP.
- [`FIXTURE-PROVENANCE.md`](./FIXTURE-PROVENANCE.md) — origin and permitted use of every fixture family.
- [`profiles/beap/v1.0`](./profiles/beap/v1.0) and [`profiles/beap/v0.1`](./profiles/beap/v0.1) — the Banking Execution Authority Profile, mirrored byte for byte from its own repository by that repository's sync script: 1.0, the version this executor implements, and the frozen 0.1 draft, staged here for archival under this repository's concept DOI.
- [`DEPENDENCY-LICENSES.md`](./DEPENDENCY-LICENSES.md) — generated inventory method and platform-conditional dependency notes.
- [`SECURITY-EVIDENCE.md`](./SECURITY-EVIDENCE.md) — control-to-artifact evidence map and published gaps.
- [`PUBLICATION-SIGNOFFS.md`](./PUBLICATION-SIGNOFFS.md) — human decisions that automation cannot make.

## Installing the Decionis CLI

This repository is also the public distribution home of the `decionis` command-line tool: its
[GitHub releases](https://github.com/decionis/agent-safe-pipeline/releases) carry every release's
npm tarball, Debian and RPM packages, Windows archive and registry manifests, and the two
manifests below are what package managers read. The CLI itself is not part of this repository's
Apache-2.0 source; `formula/` and `apps/` hold metadata only.

- **npm**: `npm install -g decionis`
- **Homebrew**: `brew tap decionis/agent-safe https://github.com/decionis/agent-safe-pipeline`
  then `brew install decionis` ([`Formula/decionis.rb`](./Formula/decionis.rb) fetches the npm
  tarball and pins its SHA-256)
- **Decionis app install**: `app install decionis` reads [`apps/decionis.json`](./apps/decionis.json)
- **Windows**: the WinGet manifest `Decionis.CLI` points at each release's
  `decionis-windows-x64-<version>.zip` here; until the manifest is accepted into winget-pkgs,
  download the archive from the release and add `decionis\bin` to `PATH`

## Open core

The architecture, intent contract, execution boundary, client adapters, audit contract, shadow mode, conformance vectors, examples, and `@decionis/commerce` runtime are Apache-2.0. The narrowly scoped Claude Desktop wrapper in [`packages/commerce-mcp-claude-extension`](./packages/commerce-mcp-claude-extension) is MIT-licensed to satisfy that directory's extension requirement; its bundle preserves the CommerceGate runtime as a separate Apache-2.0 artifact with license and notice. Decionis operates the policy control plane behind `DecionisGate`: policy evaluation, grant issuance and atomic consumption, Decision Dossier signing and retention, and Presence. The seam is two exported interfaces, `DecisionAuthority` and `AuthorizationVerifier`, plus a published OpenAPI contract; the library checks no plan, key, or entitlement. [`OPEN-CORE.md`](./OPEN-CORE.md) states the boundary and the commitments that keep it stable.

## Public-repository policy

This is intended to be the public, canonical reference implementation. It should not be mirrored: mirrors create contract and security-fix drift. Public content belongs here—architecture, package source, synthetic policies, and runnable examples. Production policy bundles, customer data, credentials, internal infrastructure, and private incident material do not.

Decionis remains the authoritative decision service, Presence remains the human-verification service, and their server internals can evolve independently behind versioned contracts.

## Start here

[ONBOARDING.md](./ONBOARDING.md) is the adopter's journey — install, capture, verdict, approval,
grant, execute once, outcome, evidence — walked for five families: AI agent, commerce, banking, proof of human,
and autonomous workflows, each pointing at the example that runs it and the property that owns it.

## Evaluating this repository

[EVALUATION-PATH.md](./EVALUATION-PATH.md) is the reviewer's route: which artefact you are looking
at, who owns which control, what each piece of evidence establishes and what it does not, and what
to run in what order.

## Status

The package is published as [`@decionis/agent-safe-pipeline`](https://www.npmjs.com/package/@decionis/agent-safe-pipeline). Install the latest stable release with `npm install @decionis/agent-safe-pipeline`; prereleases publish under the `next` dist-tag and require an explicit request such as `npm install @decionis/agent-safe-pipeline@next`.

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

## Contributing, support and license

[`CONTRIBUTING.md`](./CONTRIBUTING.md) is how a change lands: `pnpm verify` before a pull request,
the coding, security and discovery rules beside it, and the bot that opens pull requests for
branches. Questions and bug reports are [GitHub issues](https://github.com/decionis/agent-safe-pipeline/issues);
the runtime's first governed action, not a star, is the number this repository is measured by, and
[docs/reference/telemetry.md](./docs/reference/telemetry.md) says exactly what the runtime records
about that and what it never sends.

Apache-2.0 licensed except for the explicitly scoped MIT Claude Desktop wrapper in [`packages/commerce-mcp-claude-extension`](./packages/commerce-mcp-claude-extension). See [`LICENSE`](./LICENSE), [`OPEN-CORE.md`](./OPEN-CORE.md), [`TRADEMARKS.md`](./TRADEMARKS.md), [`SECURITY.md`](./SECURITY.md), and [`CONTRIBUTING.md`](./CONTRIBUTING.md). Report suspected vulnerabilities through [GitHub's private advisory form](https://github.com/decionis/agent-safe-pipeline/security/advisories/new), not a public issue.
