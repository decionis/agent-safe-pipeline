# Decionis Policy

<!--
  DECIONIS_POLICY.md — the repository's governance policy, in plain Markdown.

  Place this file at the root of the repository. Govern reads it, hashes it,
  and carries its path and SHA-256 in every intent it sends, so the signed
  Decision Dossier records exactly which revision of this file the repository
  held when the action was decided. Change the file and the next decision
  records the new hash. Set `policy-file: ""` to leave it out.

  Nothing in this file is evaluated by Govern itself: the rules Decionis
  enforces are the workspace's, configured and versioned there, and every
  verdict names the policy version that applied. This file is the human
  statement those rules encode, kept where the code lives and reviewed with it.
-->

## Scope

Applies to deploys, infrastructure changes, database migrations, and
agent-authored pull requests in this repository.

## Rules

### Production deploys

- **Block** production deploys during a change freeze.
- **Escalate** any production deploy outside business hours: a named approver
  decides before it runs.
- **Allow** production deploys that have a green CI run and an approved PR.

### Infrastructure (`terraform apply`, Pulumi, CDK)

- **Escalate** changes that touch IAM, security groups, or networking.
- **Block** destructive actions (resource deletion, forced replacement) without
  an explicit approval label on the PR.

### Database migrations

- **Escalate** any migration that drops a column or table.
- **Allow** additive, reversible migrations.

### Agent-authored changes

- **Escalate** any change authored by an AI agent that touches deploy,
  infrastructure, or migration paths.
- **Allow** agent-authored documentation and test-only changes.

## Thresholds

- Treat any action with an estimated blast radius over **$10,000** as
  high-risk and escalate.
- Require two approvers for anything that modifies secrets or their rotation.

<!--
  Start in shadow (`mode: shadow`) to see what these rules would do to real
  runs without failing a build, then enforce.
-->
