# Decionis Policy

<!--
  DECIONIS_POLICY.md — your repo's governance policy, in plain Markdown.

  Place this file at the root of your repository. The Decionis Action reads it,
  content-hashes it, and injects it into every gated decision — so the gate
  governs against YOUR rules and the signed Decision Dossier records exactly
  which policy (by sha256) applied. Change the file → new hash → new recorded
  revision. Set `policy-file: ""` on the action to disable.

  Write rules however your team thinks. Headings/bullets keep it readable for
  humans; Decionis encodes the intent. Keep it specific and testable.
-->

## Scope

Applies to deploys, infrastructure changes, database migrations, and
AI-generated pull requests in this repository.

## Rules

### Production deploys

- **Block** production deploys during a change freeze.
- **Escalate** any production deploy outside business hours (require a human
  approver) before it runs.
- **Allow** production deploys that have a green CI run and an approved PR.

### Infrastructure (`terraform apply`, Pulumi, CDK)

- **Escalate** changes that touch IAM, security groups, or networking.
- **Block** destructive actions (resource deletion, force-replace) without an
  explicit approval label on the PR.

### Database migrations

- **Escalate** any migration that drops a column or table.
- **Allow** additive, reversible migrations.

### AI-generated changes

- **Restrain** (require human review) any change authored by an AI agent that
  touches deploy, infra, or migration paths.
- **Allow** AI-authored docs/test-only changes.

## Thresholds

- Treat any action with an estimated blast radius over **$10,000** as high-risk
  and escalate.
- Require two approvers for anything that modifies secrets or rotation.

<!--
  Notes:
  - Verdicts map to the action's `decision` output: allow / block / restrain /
    escalate.
  - Start in shadow mode (`mode: shadow`) to see what these rules would do
    without failing builds, then enforce.
-->

## Enforced rules

The prose above is documentation. The block below is what actually **enforces**
when the action runs with `policy-enforce: true` — it compiles 1:1 into an
active policy bundle (idempotent by content hash; change the block, it
republishes) — and what the action's **local policy engine** evaluates
in-process on every run. JSON only; each rule has exactly one of `all` / `any`,
and an `action` of allow / block / restrain / escalate. Give every rule an
explicit `priority` (higher evaluates first) and keep `"domain": "*"` so the
rule applies to every decision this repo gates.

```decionis
{
  "version": 1,
  "rules": [
    {
      "name": "Block production deploys during a change freeze",
      "priority": 100,
      "domain": "*",
      "all": [
        { "field": "decision_type", "op": "eq", "value": "production-deploy" },
        { "field": "context.change_freeze", "op": "eq", "value": true }
      ],
      "action": "block"
    },
    {
      "name": "Escalate IAM / security-group changes",
      "priority": 90,
      "domain": "*",
      "any": [
        { "field": "context.touches_iam", "op": "eq", "value": true },
        { "field": "context.touches_network", "op": "eq", "value": true }
      ],
      "action": "escalate"
    },
    {
      "name": "Restrain AI-authored deploy/infra/migration changes",
      "priority": 80,
      "domain": "*",
      "all": [
        { "field": "context.agent_generated", "op": "eq", "value": true }
      ],
      "action": "restrain"
    }
  ]
}
```
