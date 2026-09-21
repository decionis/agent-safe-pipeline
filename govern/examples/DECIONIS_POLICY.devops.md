# Decionis Policy — DevOps & CI (example)

<!--
  DECIONIS_POLICY.devops.md — a DevOps/CI governance policy for the Decionis
  Action. Copy it to your repo root as DECIONIS_POLICY.md (or merge these rules
  into yours) to gate infrastructure changes, deploys, and releases.

  The Action reads the file, content-hashes it, and injects it into every gated
  decision. The ```decionis block below compiles 1:1 into an enforced policy
  bundle (idempotent by content hash — change the block, it republishes).
  Verdicts: allow / block / restrain / escalate. Start in `mode: shadow`, watch
  what it would do, then enforce.
-->

## Scope

Applies to infrastructure changes (`terraform apply` / `destroy`, Pulumi, CDK),
production and on-chain / release deploys, and any AI-authored change that
touches those paths.

## Rules

### Infrastructure

- **Escalate** infrastructure **destroys** (`terraform destroy`, force-replace,
  resource deletion) — these must never run unattended; require an authorized
  operator.
- **Restrain** (require human review) production infrastructure **applies**.
- **Escalate** any change that touches **IAM, networking, or secrets**.

### Deploys & releases

- **Restrain** on-chain / release deploys — review the release authority and
  build inputs before anything ships.
- **Block** production deploys during a **change freeze**.

### AI-authored changes

- **Restrain** any change authored by an **AI agent** that touches infra,
  deploy, or release paths.
- **Allow** AI-authored docs / test-only changes.

## Thresholds

- Treat any change with an estimated **blast radius over $10,000** as high-risk
  and escalate.
- Require review for anything that modifies **secrets** or their rotation.

## Enforced rules

The prose above is documentation. The block below is what **enforces** when the
action runs with `policy-enforce: true` — and what the action's local policy
engine evaluates in-process on every run. JSON only; each rule has exactly one
of `all` / `any`, and an `action` of allow / block / restrain / escalate.
Fields are matched against the decision `payload` — `decision_type`,
`workflow_key`, and your own `context.*` keys. Give every rule an explicit
`priority` (higher evaluates first) and keep `"domain": "*"` so the rule
applies to every decision this repo gates.

```decionis
{
  "version": 1,
  "rules": [
    {
      "name": "Escalate infrastructure destroy",
      "priority": 100,
      "domain": "*",
      "any": [
        { "field": "decision_type", "op": "eq", "value": "infra-destroy" },
        { "field": "workflow_key", "op": "eq", "value": "infra-destroy" },
        { "field": "context.destroys_resources", "op": "eq", "value": true }
      ],
      "action": "escalate"
    },
    {
      "name": "Escalate infra changes touching IAM / networking / secrets",
      "priority": 90,
      "domain": "*",
      "any": [
        { "field": "context.touches_iam", "op": "eq", "value": true },
        { "field": "context.touches_network", "op": "eq", "value": true },
        { "field": "context.touches_secrets", "op": "eq", "value": true }
      ],
      "action": "escalate"
    },
    {
      "name": "Block deploys during a change freeze",
      "priority": 80,
      "domain": "*",
      "all": [{ "field": "context.change_freeze", "op": "eq", "value": true }],
      "action": "block"
    },
    {
      "name": "Restrain production infrastructure apply",
      "priority": 70,
      "domain": "*",
      "any": [
        { "field": "decision_type", "op": "eq", "value": "infra-apply" },
        { "field": "workflow_key", "op": "eq", "value": "infra-apply" }
      ],
      "action": "restrain"
    },
    {
      "name": "Restrain on-chain / release deploys",
      "priority": 60,
      "domain": "*",
      "any": [
        { "field": "decision_type", "op": "eq", "value": "release-deploy" },
        { "field": "workflow_key", "op": "eq", "value": "release" },
        { "field": "workflow_key", "op": "eq", "value": "escrow-deploy" }
      ],
      "action": "restrain"
    },
    {
      "name": "Restrain AI-authored infra / deploy changes",
      "priority": 50,
      "domain": "*",
      "all": [{ "field": "context.agent_generated", "op": "eq", "value": true }],
      "action": "restrain"
    }
  ]
}
```

<!--
  Pair with examples/gate-terraform.yml (blast radius on the plan),
  examples/gate-deploy.yml (block a deploy on a `block` verdict), and
  examples/gate-release.yml (verdict before a tagged release). Populate the
  context.* fields from your plan/PR (e.g. `terraform show -json` + `jq`) and
  pass them via the action's `payload` input.
-->
