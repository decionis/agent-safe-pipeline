# Decionis Policy — DevOps and CI

<!--
  A policy for pipelines: what may ship, change or be destroyed from CI, and
  who decides when it may not be decided alone. Govern carries this file's
  hash in every intent, so each Decision Dossier names the revision that was
  in force; the rules Decionis enforces are configured in the workspace and
  versioned there.
-->

## Scope

Deploys, releases, infrastructure changes and data migrations run from
GitHub Actions, GitLab CI or Jenkins in this repository.

## Rules

### Releases and production deploys

- **Escalate** every production deploy and every tagged release to the release
  manager; the pipeline holds while Decionis orchestrates the approval.
- **Block** deploys during a declared change freeze.
- **Allow** deploys to non-production environments from the default branch.

### Infrastructure

- **Escalate** an infrastructure change that destroys resources or touches IAM,
  networking or secrets.
- **Allow** changes that only add or update resources within the plan's stated
  blast radius.

### Data

- **Escalate** a migration that drops a column or a table, or rewrites more
  than a stated share of a table.
- **Allow** additive, reversible migrations.

### Agent-authored changes

- **Escalate** any change an AI agent authored on deploy, infrastructure or
  migration paths; **allow** documentation and test-only changes.

## Thresholds

- Treat a change with an estimated blast radius over **$10,000** as high-risk
  and escalate.
- Require review for anything that modifies secrets or their rotation.
