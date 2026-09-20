# Distribution discovery

What this repository already is, before it is packaged for installation. This report was produced
on 2026-09-17 by reading the code, not the documentation, and it is the baseline the distribution
work under [`decisions/0001-http-interception-ingress.md`](./decisions/0001-http-interception-ingress.md)
preserves. Paths and symbols below are the ones in the tree; nothing here is a plan.

## Existing architecture

One TypeScript workspace, pnpm 9, Node 22.14 or later, ESM throughout. Two publishable packages
and the surfaces around them:

| Piece           | Where                                                                                       | What it is                                                                                                                                                                                                      |
| --------------- | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Library         | `packages/pipeline` (`@decionis/agent-safe-pipeline`, npm `0.1.4`)                          | Intent capture, canonical hashing, the Decionis client, grant claim and finalization, the executor, shadow                                                                                                      |
| Runtime         | `packages/agentsafe` (`@decionis/agentsafe`, `0.1.0`, **not yet on npm**)                   | The trusted executor as one process with a `bin` named `agentsafe`; the image and the deployment kit run it                                                                                                     |
| Image           | `packages/agentsafe/Dockerfile`, published as `ghcr.io/decionis/agentsafe`                  | Distroless, non-root (65532), Node permission model, `NODE_ENV=production`, no configuration baked in                                                                                                           |
| Kubernetes      | `deploy/kubernetes/` (kustomize), `deploy/Runbook.md`, `deploy/alerts/`                     | StatefulSet, two namespaces, default deny, egress by CIDR or Cilium FQDN, operator RBAC, conformance-tested                                                                                                     |
| Homebrew        | `Formula/decionis.rb`                                                                       | This repository is already a tap (`brew tap decionis/agent-safe https://github.com/decionis/agent-safe-pipeline`) for the separate `decionis` CLI; the formula installs an npm tarball with a `node` dependency |
| Release         | `.github/workflows/deploy.yml` (`release` job)                                              | Version-driven on push to `master`: signed tag, npm trusted publishing of the library, SBOM, provenance, checksums, GHCR image with attestation, GitHub release                                                 |
| Local authority | `packages/pipeline/src/testing/LocalAuthority.ts` (`@decionis/agent-safe-pipeline/testing`) | A loopback double of the Decionis routes the package consumes, validating every request against the contract; synthetic policy, synthetic grants                                                                |

The runtime today is a **proposal executor**, not a reverse proxy. A caller authenticates as a
principal and posts a proposal envelope; the executor attaches the trusted context, asks the
authority, and on `ALLOW` claims the grant and runs one registered handler, the reference one
being a `POST` of the verified parameters to a single configured `DOWNSTREAM_URL`.

```text
caller (principal)                          Decionis
  │ POST /v1/actions {proposal, idempotency_key}   ▲ │
  ▼                                                │ │
ExecutorHttpServer ──► TrustedExecutorService.propose
  │                       │ IntentCapture (agent-safe.intent/1)
  │                       ▼
  │                    EscalationResolver.evaluate ──► DecionisGate ── enforce-and-bind ──┘
  │                       │ ALLOW / ESCALATE / BLOCK (fail-closed BLOCK on any doubt)
  │                       ▼
  │                    SafeExecutor.run ──► DecionisGrantVerifier ── claim-token
  │                       │ ActionRegistry.executeTracked → forward_request handler
  │                       │   GuardedFetch → DOWNSTREAM_URL (one POST, inside dispatch.run)
  │                       ▼
  │                    finalize-token (COMMITTED | FAILED | INDETERMINATE)
  ▼                       ▼
ActionResponse         AuditRecorder → HashChainedAuditSink → stdout (chained), ChainJournal
```

## Capability matrix

| Capability                          | Status  | Existing implementation                                                                                                       | Decision                                                                                                                              |
| ----------------------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| CLI (`agentsafe`)                   | PARTIAL | `packages/agentsafe/src/Cli.ts`: `serve`, `verify-chain`, `verify-bundle`, `probe-containment`                                | Extend with `init`, `proxy`, `run`, `status`, `doctor`, `config`, `version`, `verify`, `login`, `logout`; keep every existing command |
| HTTP interception (reverse proxy)   | MISSING | The listener accepts a proposal envelope only (`src/http/ExecutorHttpServer.ts`, `src/service/Requests.ts`)                   | Add a second ingress over the same lifecycle (ADR 0001); the envelope ingress stays                                                   |
| Ingress implementation              | EXISTS  | `src/http/ExecutorHttpServer.ts` (bounded body, protective headers, principals)                                               | Reuse its shape and constants (`RESPONSE_HEADERS`) for the gateway listener; do not replace it                                        |
| Action extraction / normalization   | PARTIAL | `TrustedExecutorService.captureIntent` builds the trusted context; BEAP binder for banking                                    | Add route matching (path pattern → action name) and request normalization for the HTTP ingress                                        |
| ExecutionBinding                    | EXISTS  | `packages/pipeline/src/intent/ExecutionIntent.ts` (`AuthorityIntentBinding`), `CanonicalIntentHasher.ts`                      | Reuse unchanged                                                                                                                       |
| Decionis client (authority)         | EXISTS  | `packages/pipeline/src/decision/DecionisGate.ts` (enforce-and-bind, managed escalation status)                                | Reuse unchanged                                                                                                                       |
| ALLOW / BLOCK / ESCALATE handling   | EXISTS  | `SafeExecutor.run`, `TrustedExecutorService.enforce`, `EscalationResolver`                                                    | Reuse; the gateway maps outcomes to HTTP statuses and terminal lines                                                                  |
| Claim / finalize                    | EXISTS  | `packages/pipeline/src/execution/AuthorizationVerifier.ts` (`DecionisGrantVerifier`: claim-token, finalize-token)             | Reuse unchanged                                                                                                                       |
| Shadow mode                         | EXISTS  | `packages/pipeline/src/shadow/ShadowPipeline.ts`, `ShadowGate.ts`; `EXECUTOR_MODE=SHADOW` in the executor                     | Reuse `ShadowPipeline.observe` around the unchanged forward                                                                           |
| Presence integration                | EXISTS  | `PresenceApprovalCoordinator.ts` (DIRECT), managed escalation in `DecionisGate`, both behind `EscalationResolver`             | Reuse `EscalationResolver` with the same `EscalationConfig`                                                                           |
| Decision Dossier / evidence         | EXISTS  | `AuditRecorder.ts`, `HashChainedAuditSink.ts`, `ChainJournal.ts`, `EvidenceExport.ts`, `scripts/VerifyDossier.mjs`            | Reuse the recorder and chained sink; the dossier id is what the authority returned                                                    |
| Fail-closed / AUTHORITY_UNAVAILABLE | EXISTS  | `FailClosedDecision` in `DecionisGate.ts` with `failClosed: true` and reason codes such as `AUTHORITY_UNAVAILABLE`            | Reuse; surface as its own state (HTTP 503), never as a policy BLOCK                                                                   |
| Configuration loading               | PARTIAL | `src/config/ExecutorConfig.ts`: environment only, production-strict, no file                                                  | Add a gateway configuration (file + environment + flags) beside it; the executor's loader is unchanged                                |
| Secrets                             | EXISTS  | `src/secrets/CompositeSecretStore.ts` (`<NAME>` or `<NAME>_FILE`, file-only in production)                                    | Reuse for `DECIONIS_API_KEY`                                                                                                          |
| Egress sealing                      | EXISTS  | `src/egress/EgressPolicy.ts`, `GuardedFetch.ts` (HTTPS or explicit loopback, pins, no redirects, bounded bodies)              | Reuse for the authority and Presence; the upstream is a proxied origin, see ADR 0001                                                  |
| Logging / redaction                 | EXISTS  | `src/logging/LineEmitter.ts`, `src/secrets/Redactor.ts`, `src/incident/SecurityEvents.ts`                                     | Reuse                                                                                                                                 |
| Metrics                             | EXISTS  | `src/incident/Metrics.ts` (OpenMetrics text at `/metrics`)                                                                    | Extend with the gateway families                                                                                                      |
| Health / readiness                  | EXISTS  | `/health`, `/ready` in `src/http/Routes.ts`; `TrustedExecutorService.readiness`                                               | Keep; the gateway adds `/healthz` and `/readyz` under its reserved prefix                                                             |
| Graceful shutdown, SIGTERM          | EXISTS  | `Serve.ts` (`SIGTERM`, `SIGINT`, `SIGHUP`)                                                                                    | Reuse the pattern                                                                                                                     |
| Docker                              | EXISTS  | `packages/agentsafe/Dockerfile`; CI job `image` reproduces the manifest's posture                                             | Harden: multi-arch, `agentsafe` as the entrypoint command                                                                             |
| Docker registry                     | EXISTS  | `ghcr.io/decionis/agentsafe`, tags `<version>` and `latest`                                                                   | Keep GHCR (existing convention); add `<major>.<minor>` and `<major>` tags                                                             |
| Kubernetes                          | EXISTS  | `deploy/kubernetes/*.yaml` for the executor; `test/automation/DeployManifests.test.mjs` pins the file list                    | Keep the kit; add a Helm chart for the gateway under `charts/agentsafe`                                                               |
| Helm                                | MISSING | —                                                                                                                             | Add                                                                                                                                   |
| Homebrew                            | PARTIAL | `Formula/decionis.rb` for another product, in this tap                                                                        | Add `Formula/agentsafe.rb` in the same tap and style                                                                                  |
| Linux packages / installer          | MISSING | Only the `decionis` CLI's `.deb`/`.rpm` (built elsewhere) are attached to releases                                            | Add `.deb`, `.rpm`, `tar.gz` and a checksum-verifying `install.sh` for the runtime                                                    |
| GitHub Releases                     | EXISTS  | `deploy.yml` `release` job, tied to `packages/pipeline`'s version                                                             | Extend: publish `@decionis/agentsafe`, attach the runtime artifacts                                                                   |
| SBOM / signing                      | EXISTS  | CycloneDX SBOM, Sigstore provenance, `actions/attest` for tarball and image, `SHA256SUMS`                                     | Extend to the new artifacts                                                                                                           |
| Golden adversarial demo             | EXISTS  | `examples/golden-adversarial-demo`                                                                                            | Unchanged                                                                                                                             |
| Tests                               | EXISTS  | vitest per package (coverage gates), Stryker at 100% on the trust-boundary files, `test/automation` for scripts and workflows | Extend                                                                                                                                |
| Activation telemetry                | MISSING | Only the `User-Agent` on hosted calls (`src/http/ClientIdentification.ts`)                                                    | Add local, documented, payload-free events; nothing new leaves the process                                                            |
| OpenTelemetry                       | PARTIAL | OpenMetrics exposition only                                                                                                   | Keep the exposition (scrapable by a collector); no SDK dependency                                                                     |
| Hosted operation                    | MISSING | Nothing in this repository is hosted                                                                                          | Configuration boundaries only (multi-tenant by deployment, not by process)                                                            |

`DO NOT USE`: `FixtureDecisionAuthority` as the local authority of the gateway. It signs its own
grants in process and is not the Decionis protocol; the `LocalAuthority` double speaks the real
routes and is what the gateway's demo mode uses, through the unchanged `DecionisGate`.

## One consequential action, traced

The baseline execution path, `pnpm --filter @decionis/agent-safe-example-trusted-executor demo`
in enforcement with `forward_request`:

| Step              | Package                         | File                                                                      | Symbol                                                                                                                       |
| ----------------- | ------------------------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| entrypoint        | `@decionis/agentsafe`           | `src/Cli.ts` → `src/Serve.ts` → `src/TrustedExecutor.ts`                  | `serve()`, `createTrustedExecutor()`                                                                                         |
| parsing           | `@decionis/agentsafe`           | `src/http/ExecutorHttpServer.ts`                                          | `handle` → `readJson` (100 KiB), `dispatch("/v1/actions")`                                                                   |
| authentication    | `@decionis/agentsafe`           | `src/identity/Authenticator.ts`                                           | `Authenticator.authenticate` (principal, role `PROPOSER`)                                                                    |
| proposal schema   | `@decionis/agentsafe`           | `src/service/Requests.ts`                                                 | `ProposalRequestSchema` (strict: action, target, parameters, idempotency key)                                                |
| normalization     | `@decionis/agentsafe`           | `src/service/TrustedExecutorService.ts`                                   | `captureIntent` → `IntentCapture.capture` (`packages/pipeline/src/intent/IntentCapture.ts`)                                  |
| ExecutionBinding  | `@decionis/agent-safe-pipeline` | `src/intent/CanonicalIntentHasher.ts`                                     | `CanonicalIntentHasher.capture`: `AuthorityIntentBinding`, RFC 8785 canonical form, `sha256:` intent hash                    |
| authority request | `@decionis/agent-safe-pipeline` | `src/decision/DecionisGate.ts`                                            | `DecionisGate.evaluate` → `POST /v1/authority/enforce-and-bind`, `Idempotency-Key: intent_id`                                |
| decision handling | `@decionis/agentsafe`           | `src/service/TrustedExecutorService.ts`                                   | `enforce`: `ALLOW` opens an attempt; every verdict goes through the executor                                                 |
| claim             | `@decionis/agent-safe-pipeline` | `src/execution/SafeExecutor.ts`, `src/execution/AuthorizationVerifier.ts` | `SafeExecutor.run` → `DecionisGrantVerifier.verifyAndConsume` → `POST /v1/execution/claim-token`                             |
| forwarding        | `@decionis/agentsafe`           | `src/handlers/ForwardRequestHandler.ts`                                   | `execute` inside `dispatch.run`, through `GuardedFetch` to `DOWNSTREAM_URL`                                                  |
| effect capture    | `@decionis/agentsafe`           | `ForwardRequestHandler.ts`; `src/adapters/*` for families                 | `DownstreamResult {status, accepted}`; `EffectEvidenceRegister` where an adapter observes an effect                          |
| finalize          | `@decionis/agent-safe-pipeline` | `src/execution/SafeExecutor.ts`                                           | `finalize` → `DecionisGrantVerifier.finalize` → `POST /v1/execution/finalize-token` (`COMMITTED`, `FAILED`, `INDETERMINATE`) |
| evidence          | `@decionis/agentsafe`           | `src/audit/HashChainedAuditSink.ts`, `src/audit/ChainJournal.ts`          | `AuditRecorder.record` per lifecycle event, chained, heads persisted; `/metrics`                                             |

Distribution work preserves this path. The HTTP-interception ingress added by ADR 0001 enters it
at "normalization" with a captured intent and leaves it after "evidence"; every step between is
the same code.

## What is not consistent, and what is

- There is one authority implementation (`DecionisGate`) and one claim/finalize implementation
  (`DecionisGrantVerifier`). `FixtureDecisionAuthority` is a development fixture that refuses to
  construct in production and is not on any executor path.
- `SafeExecutor` re-checks intent conformance immediately before the handler runs, so a payload
  cannot change between authorization and execution inside the process; the new ingress keeps the
  forwarded bytes bound to the intent by digest (ADR 0001).
- Presence verification is never local: `DIRECT` sends the receipt back to Decionis for a fresh
  decision, `MANAGED` polls Decionis only.
- The Kubernetes kit deploys the same image and process; it adds no protocol semantics.
- None of the stop-and-ask conditions in the brief was met. The one architectural decision, a
  second ingress, is recorded in ADR 0001 rather than guessed through.

## Facts that shape the plan

- `@decionis/agentsafe` is not on npm and the release job publishes only the library. Homebrew
  in this tap installs npm tarballs, so the runtime has to be published for the formula to exist.
- The release job keys everything on `packages/pipeline`'s version and requires it to equal the
  workspace version. The runtime's version is separate (`0.1.0`).
- `test/automation/DeployManifests.test.mjs` pins the exact file list under `deploy/` and parses
  every YAML there, so a Helm chart (whose templates are not YAML) lives under `charts/`.
- `test/automation/NpmPublishWorkflow.test.mjs` executes the npm publish step's script out of
  `deploy.yml` and pins the signing steps' order; changes to the workflow keep those markers.
- ESLint forbids `node:http` and `node:net` outside `packages/agentsafe/src/http` and `src/egress`;
  a listener is written under `src/http`, everything else takes a `fetch`.
- The executor package's coverage gate is 90% lines and functions, 85% branches, over `src/**`
  except `Index.ts` and `Cli.ts`. New modules are tested to that bar.
- `scripts/CheckFixtureProvenance.mjs` requires every test file under `packages/*/test/**` to be
  listed in `fixtures/manifest.json` and to name only loopback or reserved example hosts.
- `scripts/CheckDiscovery.mjs` holds `README.md`, `packages/pipeline/README.md`, `llms.txt`,
  `llms-full.txt`, `ONBOARDING.md` and `EVALUATION-PATH.md` to the workspace.

## Implementation plan

REUSE

- `IntentCapture`, `CanonicalIntentHasher`, `AuthorityIntentBinding`
- `DecionisGate`, `DecionisGrantVerifier`, `SafeExecutor`, `ActionRegistry`, `ShadowPipeline`
- `EscalationResolver` and `EscalationConfig` (NONE, DIRECT, MANAGED)
- `AuditRecorder`, `HashChainedAuditSink`, `HashChain`, `ChainJournal`
- `CompositeSecretStore`, `Redactor`, `LineEmitter`, `SecurityEvents`, `Metrics`
- `EgressPolicy`, `GuardedFetch` for the authority and Presence
- `LocalAuthority` as the demo authority, behind the unchanged `DecionisGate`
- The executor (`serve`), its configuration, image and Kubernetes kit, unchanged
- The release job's signing, SBOM, provenance, checksum and image steps

EXTEND

- `Cli.ts` with the install-friendly commands; existing commands and their exit codes unchanged
- `Metrics` with the gateway families
- `Dockerfile` and the `image` CI job: multi-arch, the `agentsafe` command as the entrypoint
- `deploy.yml`: publish `@decionis/agentsafe`, build the runtime artifacts, attach them, update the
  formula, run install smoke tests
- `README.md`, `llms.txt`, `llms-full.txt`, `EVALUATION-PATH.md`, package README

ADD

- `packages/agentsafe/src/gateway/`: configuration (file, environment, flags), route table,
  request normalization, the exact-forward handler, the gateway assembly, terminal reporting
- `packages/agentsafe/src/http/GatewayHttpServer.ts`: the interception listener
- `packages/agentsafe/src/cli/`: `init`, `proxy`/`run`, `status`, `doctor`, `config`, `version`,
  `login`, `logout`, `verify`
- `Formula/agentsafe.rb`, `packaging/` (nfpm for `.deb`/`.rpm`, `install.sh`), `charts/agentsafe`
- `docs/quickstart`, `docs/install`, `docs/gateway`, `docs/authority`, `docs/deployment`,
  `docs/reference`, and this `docs/architecture`
- Distribution smoke tests

DEPRECATE

- Nothing. `verify-chain` and `verify-bundle` gain a `verify chain|bundle` spelling and keep the
  old one.

## Decisions taken while packaging (Phase 2)

Routine packaging choices, recorded here rather than as ADRs:

- **The executable is a Node single executable application** built by
  `scripts/BuildExecutable.mjs` from the official Node release `packaging/sea/node.json` pins,
  verified by SHA-256 before use, never from the Node that runs the build (a shared-library
  build such as Homebrew's cannot carry an application). One bundle, one blob, three targets;
  x64 macOS, where Node does not support single executables, gets the same bundle beside the
  same pinned Node with a shell launcher, and the installer and the formula treat every target
  as a directory with `agentsafe` in it.
- **The image's default command is now the gateway.** `ENTRYPOINT` is the `agentsafe` command
  under the same permission model; `CMD ["proxy"]`. A deployment of the trusted executor names
  `serve` (the kit's StatefulSet now does; the CI's container runs do). An adopter of the image
  who passed no argument gets the gateway's `REFUSED_TO_START` until they add `args: ["serve"]`;
  that is the whole migration.
- **The registry stays `ghcr.io/decionis/agentsafe`**, the existing convention, with `<version>`,
  `<major>.<minor>`, `<major>` and `latest` tags and a two-architecture manifest. Docker Hub was
  added on 2026-09-20 as a second name for the same manifest, `docker.io/decionis/agentsafe`,
  because that is where developers look first: the `Docker Hub image` workflow copies the
  release's manifest by digest after the release job, refuses a differing digest, attests the
  Docker Hub name and publishes the overview from `packaging/dockerhub/README.md`; the credential
  is the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets
  for the `decionis` namespace, and the `DOCKERHUB_PUBLISH_ENABLED` variable is the switch. The
  same workflow, dispatched with a version, publishes a release that predates the switch.
- **The tap stays this repository.** `Formula/agentsafe.rb` is rendered by the release workflow
  from the release's `SHA256SUMS` and pushed to a `homebrew/agentsafe-<version>` branch for the
  pull request bot to open; nothing is pushed to `master` by a workflow. A `decionis/homebrew-tap`
  short form would be a copy of the same file in another repository.
- **Versions stay separate.** A release is still keyed to `packages/pipeline`'s version, as the
  workflow always was; the runtime artifacts, the image tags and the chart's `appVersion` carry
  `packages/agentsafe`'s own version, and the release job refuses a chart whose `appVersion` is
  not the runtime's. The first runtime release therefore rides on the next pipeline version bump.
- **The chart is an OCI artifact** at `oci://ghcr.io/decionis/charts/agentsafe`, pushed beside the
  image with the same token, and attached to the release; `https://charts.decionis.com` would be
  an index pointing at it, which this repository cannot host.
- **`@decionis/agentsafe` on npm** is published by the release workflow only once
  `NPM_PUBLISH_RUNTIME_ENABLED` is set, because a package's first publication cannot use trusted
  publishing until the publisher is configured on npm.
- **Runner labels** for the four targets (`ubuntu-latest`, `ubuntu-24.04-arm`, `macos-15`,
  `macos-15-intel`) are GitHub's current hosted labels and are the one thing here the repository
  cannot test before the workflow runs.

## Hosted readiness (Phase 4)

One seam, additive: `GatewayHttpServer` takes either a `Gateway` or a `GatewaySelector`, a
function from the request's host name to the gateway that answers it (`421` for a host it does
not serve). With it a hosted instance fronts every governed endpoint from one listener, each
endpoint one `Gateway` with its own configuration object, secret store, sinks and transports,
which `Gateway.create` and `GatewayConfigLoader.load` already accepted. Nothing about authority,
binding, claim or finalization is different in that shape, and nothing is forked; the page is
[`docs/install/hosted.md`](../install/hosted.md).
