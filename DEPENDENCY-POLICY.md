# Dependency and Interface Currency Policy

This policy covers production packages, development and release tooling, GitHub Actions, and the
external interfaces consumed by Agent-Safe Pipeline.

## Inventory and monitoring

`package.json` files declare direct npm dependencies, `pnpm-lock.yaml` is the resolved transitive
inventory for every package in `pnpm-workspace.yaml`, and the release workflow publishes separate
production-package and complete-workspace license inventories. GitHub Actions are dependencies too:
every `uses:` reference is pinned to a full commit SHA. The Go modules under `verifiers/envoy` and
`verifiers/kong` declare their dependencies in `go.mod`, pin them in `go.sum`, and have their own
weekly Dependabot entry; the Maven module under `verifiers/spring` pins its dependencies in `pom.xml` and has one
too; the Rust crate under `verifiers/rust` is a library that names its dependencies in
`Cargo.toml`, every one MIT, Apache-2.0 or BSD, and leaves the lockfile to its consumers, as
library crates do; the .NET solution under `verifiers/dotnet` pins its packages in its project
files. Its one non-permissive dependency, `jakarta.servlet:jakarta.servlet-api`, is a compile-time
API in `provided` scope that the application's container supplies and nothing distributes; the
dependency-review passes name it as a package-scoped exception for that reason. The Kong
plugin's `google.golang.org/protobuf`, indirect through Kong's plugin development kit, is
BSD-3-Clause with Google's Go patent grant, the PATENTS file Go itself ships under; the passes
name it too, because the review reads the grant as an unknown licence.

The project monitors this inventory through:

- GitHub Dependabot security alerts and security updates;
- weekly Dependabot version updates for the root pnpm workspace and GitHub Actions;
- pull-request dependency review at low severity for runtime dependencies and moderate severity for
  development dependencies;
- weekly and per-change `pnpm audit` gates for production and complete-toolchain dependencies; and
- the checked-in license policy and generated release inventories.

`pnpm dependabot:check` fails unless `.github/dependabot.yml` contains one weekly root entry for the
npm ecosystem and one for GitHub Actions, every package manifest belongs to the declared pnpm
workspace, and the repository contains workflow files covered by the Actions entry. The root npm
entry is authoritative because this monorepo has one root workspace and lockfile.

## Review cadence and ownership

Dependabot runs each Monday. Maintainers review new alerts and failed audit jobs during the next
business-day triage window. `security@decionis.com` owns vulnerability severity and disclosure
decisions; repository maintainers own compatible upgrades, regression tests, and release delivery.
Dependency exceptions require the project-lead approval defined in `GOVERNANCE.md` and must record
scope, rationale, compensating controls, and an expiry or removal condition.

The response clock begins when an alert or report is received:

| Dependency class            | Initial assessment | Remediation target                            |
| --------------------------- | ------------------ | --------------------------------------------- |
| Production, critical        | 2 business days    | 14 calendar days                              |
| Production, high            | 5 business days    | 30 calendar days                              |
| Production, moderate or low | 5 business days    | 90 calendar days or the next planned release  |
| Toolchain, critical or high | 5 business days    | 30 calendar days                              |
| Toolchain, moderate         | 10 business days   | 90 calendar days or the next toolchain update |
| Toolchain, low              | Next weekly review | Next compatible scheduled update              |

Active exploitation, credential exposure, or a compromised build dependency overrides these
targets and uses the coordinated process in `SECURITY.md`. A blocked upgrade must be tracked in an
issue or private advisory, depending on disclosure risk, with a bounded follow-up date.

## Recorded exceptions

| Advisory                                                                                                                             | Scope                                                                                                                                                                                 | Rationale                                                                                                                                                                                                                                                                                                                                  | Compensating controls                                                                                                           | Approved                 | Removal condition                                                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| [GHSA-86w9-cpqp-85rv](https://github.com/advisories/GHSA-86w9-cpqp-85rv) (`node-forge` RSA PKCS#1 v1.5 signature verification, high) | `node-forge@1.4.0`, reached only through the development dependency `@anthropic-ai/mcpb@2.1.2` of `packages/commerce-mcp-claude-extension`; ignored by `pnpm.auditConfig.ignoreGhsas` | No patched release exists (every version is affected) and `mcpb` 2.1.2 is the latest. The repository uses `mcpb` only to pack a deterministic bundle; it never verifies an untrusted RSA signature, so the vulnerable path is not exercised. Nothing in a published package or image depends on it (`security:production` does not see it) | The production audit still gates at low; the exception names this one advisory only, not the package; Dependabot alerts stay on | Project lead, 2026-10-02 | Remove when `node-forge` publishes a fix or `mcpb` drops it; re-review by 2026-11-01 (the 30-day toolchain-high target) |

## Compatibility and interface currency

Routine patch and minor upgrades must pass formatting, linting, audits, type checking, unit and
negative tests, mutation assurance, packaged-consumer tests, discovery checks, and the release dry
run when packaging changes. Major upgrades are not automated and require an explicit compatibility
plan.

External interfaces include the Decionis decision and grant-consumption endpoints,
`@decionis/presence-node`, GitHub APIs used by repository automation, the npm trusted-publishing
contract, and pinned GitHub Actions. Before an interface upgrade, maintainers compare the upstream
contract and release notes, run the relevant contract and fail-closed tests, and verify both success
and malformed or unavailable responses. Cross-repository Decionis contract changes update the
OpenAPI description, SDK types, contract tests, and discovery inventory in the same release train,
as required by `CONTRIBUTING.md`.

A dependency is removed when it is unmaintained, cannot be updated within these targets, violates
the license policy, or requires weakening the execution boundary. Replacement decisions record the
security and migration tradeoff in the reviewing pull request.
