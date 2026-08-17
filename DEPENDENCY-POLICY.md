# Dependency and Interface Currency Policy

This policy covers production packages, development and release tooling, GitHub Actions, and the
external interfaces consumed by Agent-Safe Pipeline.

## Inventory and monitoring

`package.json` files declare direct npm dependencies, `pnpm-lock.yaml` is the resolved transitive
inventory for every package in `pnpm-workspace.yaml`, and the release workflow publishes separate
production-package and complete-workspace license inventories. GitHub Actions are dependencies too:
every `uses:` reference is pinned to a full commit SHA.

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
