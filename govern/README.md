# 🛡️ Decionis Action Gate

**Stop unauthorized deploys, migrations, and infra changes before they reach production — whether a teammate or an AI agent triggered them.**

[![Marketplace](https://img.shields.io/github/v/release/decionis/govern?label=marketplace&logo=githubactions&logoColor=white&color=6D28D9)](https://github.com/marketplace/actions/decionis-action-gate)
[![Governed by Decionis](https://img.shields.io/badge/Governed%20by-Decionis-6D28D9?logo=shield&logoColor=white)](https://github.com/decionis/govern)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)

> **Where this lives.** Since 2026-09-21 the gate's source is this directory of
> [`decionis/agent-safe-pipeline`](https://github.com/decionis/agent-safe-pipeline), the reference
> implementation of the Decionis execution contract; [`decionis/govern`](https://github.com/decionis/govern)
> remains the address workflows use (`uses: decionis/govern@v1`) and the Marketplace listing. What is
> here is the action as it shipped at v1.9.0. Its next major rewrites it in Go as one binary for any
> workflow runner (GitHub Actions, GitLab CI, Jenkins and others), speaking the same execution contract
> as the AgentSafe runtime: intent, decision, grant, execution, Decision Dossier.

Add **one step** to your workflow, and every deploy, migration, infra change, or AI-generated PR is checked against **your** policy — then **allowed, blocked, or escalated before it runs**, with a signed, verifiable record of every decision.

**Try it in 30 seconds, risk-free.** Start in shadow mode: it records what _would_ be governed without ever failing a build — so you see the value before you enforce anything.

---

## The question every pipeline now faces

AI coding agents — **Claude Code, Copilot, Cursor, Codex, OpenHands** — now open PRs, edit workflows, write migrations, and trigger deploys. The hard question is no longer _"who wrote this code?"_ It's:

> **Should this action be allowed to execute?**

That's the Action Gate.

## Why Decionis

- **One verdict per governed action** — `allow` / `block` / `restrain` / `escalate`, evaluated against _your_ policy before anything runs.
- **Deterministic policy you own** — versioned rules, committed as `DECIONIS_POLICY.md` or connected from where policy already lives; every verdict cites the version that applied.
- **Microsecond verdicts** — the committed rules block is evaluated **in-process** by a local engine that mirrors the server, so deterministic verdicts act in ~1ms while the API notarizes off the critical path. Shadow mode is **speculative**: your command starts immediately, adding ~zero latency.
- **Cryptographic proof** — each decision is a signed, public-verifiable Decision Dossier: audit-ready evidence of what was authorized and why, pinned to the exact policy revision (`sha256`).
- **Zero-friction adoption** — start in shadow mode in 30 seconds; it never fails a build until you choose to enforce.

## Set it up in one step

Pick whichever is fastest — both drop a **shadow-mode** gate in, so nothing fails your build on day one:

- **New repo:** [**Use this template →**](https://github.com/decionis/agent-safe-pipeline/generate) a ready-wired pipeline + `DECIONIS_POLICY.md`.
- **Existing repo, one command:**

  ```bash
  curl -fsSL https://decionis.com/govern/install.sh | sh
  ```

  Writes a shadow-mode workflow + a starter `DECIONIS_POLICY.md` (no secrets touched, idempotent). The installer ships in this repo ([`install.sh`](./install.sh)) and takes flags after `sh -s --`:

  | Flag             | Effect                                                                                                                                                                 |
  | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | `--pr`           | Branch (`feature/add-decionis-governance`), commit, push, and open the onboarding PR (`gh` CLI, or prints the compare URL).                                            |
  | `--inject`       | Also insert an **observe-only** shadow step as the first step of every job in your existing workflows — insert-only, `continue-on-error: true`, skips anything unsafe. |
  | `--dry-run`      | Show every file and diff it would write; write nothing.                                                                                                                |
  | `--mode`         | `shadow` (default) or `enforce` for the generated workflow.                                                                                                            |
  | `--org-id`       | Inline a literal org id instead of `${{ secrets.DECIONIS_ORG_ID }}`.                                                                                                   |
  | `--workflow-key` | Workflow key for the generated/injected steps.                                                                                                                         |

  ```bash
  # The full viral onboarding: gate every workflow, open the PR
  curl -fsSL https://decionis.com/govern/install.sh | sh -s -- --pr --inject
  ```

Then add your `DECIONIS_API_KEY` / `DECIONIS_ORG_ID` secrets — [free keys here](https://decionis.com/quickstart?source=github_action).

## 30-second quickstart

**Wrap the command you want to govern.** Decionis runs it _through_ the gate, so it can't execute without an authorizing verdict:

```yaml
- uses: decionis/govern@v1
  with:
    api-key: ${{ secrets.DECIONIS_API_KEY }}
    org-id: ${{ secrets.DECIONIS_ORG_ID }}
    workflow-key: github_deploy_approval
    action: production-deploy
    run: ./deploy.sh # ← Decionis runs this ONLY if it authorizes the action
```

On `allow` the command runs. On `block`/`escalate` it **never runs** and the step fails. Try it risk-free with `mode: shadow` — the command still runs, but Decionis only records the verdict (never fails the build):

```yaml
- uses: decionis/govern@v1
  with:
    api-key: ${{ secrets.DECIONIS_API_KEY }}
    org-id: ${{ secrets.DECIONIS_ORG_ID }}
    workflow-key: github_deploy_approval
    action: production-deploy
    run: ./deploy.sh
    mode: shadow # observe-only; command starts instantly, verdict records in the background
    comment-pr: "true" # posts the verdict + verify link on the PR
```

Need keys? Create them free at **[decionis.com/quickstart?source=github_action](https://decionis.com/quickstart?source=github_action)** — no card, no call.

### Cryptographic proof, verified at the target

Set `request-grant: true` and every authorized run carries a short-lived, single-use, signed **Execution Grant** — `DECIONIS_EXECUTION_GRANT` in the command's environment. Your deploy target verifies it against Decionis's public keys before it acts, so authorization is proven where the action actually happens.

```yaml
- uses: decionis/govern@v1
  with:
    workflow-key: github_deploy_approval
    action: production-deploy
    request-grant: true
    grant-audience: prod-us-east
    run: ./deploy.sh # presents $DECIONIS_EXECUTION_GRANT to the target
```

### Zero standing credentials

Take secrets out of CI entirely. Register a target's credential with Decionis once, and it's released only in exchange for an authorized run — your pipeline holds nothing to leak. See [`examples/gate-deploy-broker.yml`](./examples/gate-deploy-broker.yml), or federate **GCP Workload Identity Federation** / **Azure** so the cloud issues credentials only for a Decionis-authorized deploy.

---

## What you get

### 1. 🚦 A verdict before anything runs

One verdict before execution — **`allow`**, **`block`**, or **`escalate`**. Composable into any later step via `steps.<id>.outputs.decision`.

### 2. 🟣 A zero-risk, zero-latency way to start

`mode: shadow` shows exactly what would be governed, without ever failing a build — and it's **speculative**: your `run` command starts immediately while the verdict resolves in the background, so the gate adds ~zero wall-clock time. The step's exit code is exactly your command's; evaluation problems (API down, secrets not configured yet) surface as notices, never failures. Enforce when you're ready — one line.

### ⚡ Local policy engine

The ` ```decionis ` rules block in your `DECIONIS_POLICY.md` is evaluated **in-process** by a local engine that faithfully mirrors the platform evaluator (same operators, same coercions, same first-match ordering). A deterministic `allow`/`block` from an explicitly matched committed rule acts in **microseconds**; the API call becomes an async notarization off the critical path, so the signed dossier, verify URL, and badge still arrive. The log shows the speedup:

```text
⚡ Decionis local verdict 'block' via rule "Block deploys during a change freeze" in 0.41ms — API roundtrip moved off the critical path.
```

Control it with `local-eval`:

- **`auto`** (default) — local verdicts act instantly; the API notarizes in the background. If the API disagrees (org-level policy can add rules), you get a `::warning::` and `verdict-mismatch=true`.
- **`strict`** — deterministic local verdicts skip the network entirely (offline-capable; those runs mint no dossier).
- **`off`** — v1.8 behavior: every verdict comes from the blocking API call.

The engine **never guesses**: matched `escalate`/`restrain`, no matching rule, unknown operators, malformed/YAML policies, and rules that depend on server-side state always fall back to the API. `request-grant: true` always uses the blocking path (the signed grant must exist before your command's environment is built).

### 3. 🧾 Proof you can hand an auditor

Every verdict produces a signed, public-verifiable [Decision Dossier](https://decionis.com/dossier-example?source=github_action): **why** it happened, **who** approved it, **which policy** applied, and the **risk**. The verify link unfurls as an OG card in Slack / Teams / LinkedIn — paste it in an incident, a change ticket, or an audit and it holds up.

---

## Your policy — what the gate evaluates against

Every gated action is evaluated against **your organization's policy**: the rules that decide whether an action is **allowed, blocked, restrained, or escalated**. You own those rules.

- **Zero config to start.** Out of the box, Decionis applies a built-in **default policy pack** for your workflow's vertical (core, finance, hospitality, and more), so the 30-second quickstart governs immediately — no policy authoring required.
- **Make it yours, and it's versioned.** Add or update rules at any time; Decionis **versions every change**, and each verdict's Decision Dossier records exactly **which policy version applied** — so an audit can trace any decision back to the rule that made it.
- **Bring policy from where it already lives.** Build rules dynamically, **upload or paste** a policy file, or **connect the source of truth** and Decionis keeps the encoded policy in sync — **Google Drive, GitHub, Jira, Confluence, Notion, or SAP.**

The result: the gate isn't a generic check — it enforces _your_ rules, kept current with how your organization actually documents them.

### Policy as a file: `DECIONIS_POLICY.md`

Keep policy where developers already work — in the repo, in Markdown, reviewed by PR. Drop a **`DECIONIS_POLICY.md`** at your repo root and the action reads it, **content-hashes it, and injects it into every decision** — so the gate governs against your repo's policy and the signed Decision Dossier records exactly which policy (by `sha256`) applied. Change the file, get a new recorded revision. No dashboard step.

```yaml
- uses: decionis/govern@v1
  with:
    workflow-key: github_deploy_approval
    action: production-deploy
    # policy-file: DECIONIS_POLICY.md   # default; set "" to disable
    run: ./deploy.sh
```

Outputs `policy-sha256` + `policy-path`. A missing/unreadable file never fails the gate. See the annotated [example policy](./examples/DECIONIS_POLICY.md) to copy — or the [DevOps/CI example](./examples/DECIONIS_POLICY.devops.md) (escalate infra destroys, restrain applies + release deploys, block during change freeze). For an **org-wide** policy, point a Git source connector at your `.github` repo's `DECIONIS_POLICY.md`.

---

## Govern AI-generated changes

When an AI agent opens a PR or triggers a deploy, gate it **before** it merges or ships:

```yaml
- uses: decionis/govern@v1
  id: gate
  with:
    api-key: ${{ secrets.DECIONIS_API_KEY }}
    org-id: ${{ secrets.DECIONIS_ORG_ID }}
    workflow-key: ai_change_gate
    action: ai-generated-pr
    comment-pr: "true"
    payload: |
      { "author": "${{ github.actor }}", "agent_generated": true }
```

See [`examples/gate-ai-agent-pr.yml`](./examples/gate-ai-agent-pr.yml) for the full recipe (auto-detects agent authorship and requires a human verdict on risky changes).

## Also governs

- **Deployments** — production releases, blue/green cutovers
- **Infrastructure** — `terraform apply`, Pulumi, CDK
- **Data** — database migrations, destructive jobs
- **Privileged workflows** — release pipelines, secrets rotation, IAM changes

## What reviewers see on the PR

A single, **self-updating** comment — it stays current on every run:

![Example Decionis PR comment — Blocked verdict with a signed verify link](./assets/pr-comment.svg)

## 📌 Add the badge

Show your pipeline is governed — and let other devs discover the gate. Also emitted as the `badge-markdown` output, pointing at the live verify URL **pinned to your policy revision** (`…&policy=sha256:<hash>`), so the badge cryptographically binds the decision to the exact committed policy state:

```markdown
[![Governed by Decionis](https://img.shields.io/badge/Governed%20by-Decionis-6D28D9?logo=shield&logoColor=white)](https://github.com/decionis/govern)
```

[![Governed by Decionis](https://img.shields.io/badge/Governed%20by-Decionis-6D28D9?logo=shield&logoColor=white)](https://github.com/decionis/govern)

---

## Recipes

Copy-paste workflows in [`examples/`](./examples/):

| Recipe                                                              | What it gates                                                                    |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| [`gate-ai-agent-pr.yml`](./examples/gate-ai-agent-pr.yml)           | AI-generated PRs (Claude Code, Copilot, Cursor…) before merge.                   |
| [`gate-deploy.yml`](./examples/gate-deploy.yml)                     | A production deploy on a `block` verdict (enforce).                              |
| [`gate-terraform.yml`](./examples/gate-terraform.yml)               | `terraform apply` on the plan's blast radius.                                    |
| [`gate-release.yml`](./examples/gate-release.yml)                   | A verdict before a tagged release ships.                                         |
| [`auto-merge-dependabot.yml`](./examples/auto-merge-dependabot.yml) | Auto-merge a dependency PR only when the verdict is `allow`.                     |
| [`gate-pr-comment.yml`](./examples/gate-pr-comment.yml)             | Shadow-mode evaluator that comments without failing the build.                   |
| [`gate-deploy-broker.yml`](./examples/gate-deploy-broker.yml)       | Release deploy credentials only for an authorized run — no standing secrets.     |
| [`gate-deploy-gcp-wif.yml`](./examples/gate-deploy-gcp-wif.yml)     | GCP Workload Identity Federation — the cloud issues credentials only on `allow`. |
| [`gate-deploy-azure.yml`](./examples/gate-deploy-azure.yml)         | Azure federated credentials — the cloud issues credentials only on `allow`.      |

## Inputs

| Input                | Required | Default                       | Description                                                                                               |
| -------------------- | -------- | ----------------------------- | --------------------------------------------------------------------------------------------------------- |
| `api-key`            | yes      | —                             | Decionis API key with `protocol:evaluate` scope. Pass as a secret.                                        |
| `org-id`             | yes      | —                             | Decionis org id (UUID).                                                                                   |
| `workflow-key`       | yes      | —                             | Workflow key registered in Decionis policy.                                                               |
| `action`             | no       | —                             | Short label for what's being gated (e.g. `production-deploy`).                                            |
| `run`                | no       | —                             | Command Decionis runs **only if authorized** (the enforcing path).                                        |
| `shell`              | no       | `bash`                        | Shell for `run` — `bash` or `sh`.                                                                         |
| `request-grant`      | no       | `false`                       | Issue a signed Execution Grant on an authorizing verdict.                                                 |
| `grant-audience`     | no       | —                             | Bind the grant to a target/env id (e.g. `prod-us-east`).                                                  |
| `payload`            | no       | _built from workflow context_ | JSON object describing the action being gated.                                                            |
| `fail-on`            | no       | `block`                       | `block` / `escalate` / `block_or_escalate` / `never`.                                                     |
| `mode`               | no       | `enforce`                     | `enforce` or `shadow`. Shadow never fails the step and starts `run` commands immediately (speculative).   |
| `local-eval`         | no       | `auto`                        | Local policy engine: `auto` (act locally, notarize async), `strict` (offline), `off` (v1.8 blocking API). |
| `comment-pr`         | no       | `false`                       | Post (and update in place) the verdict as a PR comment.                                                   |
| `show-attribution`   | no       | `true`                        | Include the "Governed by Decionis" footer on the PR comment.                                              |
| `api-base-url`       | no       | `https://api.decionis.com`    | Override for staging / self-host.                                                                         |
| `site-base-url`      | no       | `https://decionis.com`        | Override for staging / self-host.                                                                         |
| `request-timeout-ms` | no       | `20000`                       | Timeout for the evaluate-decision call.                                                                   |

## Outputs

| Output             | Description                                                                                                   |
| ------------------ | ------------------------------------------------------------------------------------------------------------- |
| `decision`         | `allow` / `block` / `escalate` / `restrain` / `review` (API outcomes are normalized, e.g. `APPROVE`→`allow`). |
| `decision-source`  | `local` (deterministic committed-rule verdict) or `api`.                                                      |
| `verdict-mismatch` | `true` when a local verdict acted but the notarizing API verdict differed.                                    |
| `dossier-id`       | Signed Decision Dossier id for this evaluation.                                                               |
| `verify-url`       | Public verify URL (`?sig=` for OG unfurls, `&policy=sha256:…` pinning the policy revision).                   |
| `policy-version`   | Policy version (string) that produced the verdict.                                                            |
| `reason-code`      | Stable reason code (string), if returned.                                                                     |
| `badge-markdown`   | Ready-to-paste "Governed by Decionis" badge linking to the live verify URL.                                   |
| `executed`         | `true` if a `run` command was authorized and executed, `false` if blocked.                                    |
| `execution-grant`  | Signed Execution Grant (EdDSA JWT) when `request-grant: true` and authorized.                                 |
| `grant-expires-at` | ISO timestamp when the Execution Grant expires.                                                               |

## Permissions

Default (`contents: read`) is enough. To enable `comment-pr: 'true'`:

```yaml
permissions:
  contents: read
  pull-requests: write
```

## How it works

1. The repo's `DECIONIS_POLICY.md` is read, sha256-hashed, and its ` ```decionis ` rules block is evaluated **in-process** (microseconds) by a local engine that mirrors the platform evaluator.
2. A deterministic local `allow`/`block` acts immediately; `POST /v1/protocol/evaluate-decision` runs as an async notarization that mints the signed dossier and cross-checks the verdict. Everything the engine can't decide falls back to the blocking API call, exactly like v1.8.
3. In `mode: shadow` with a `run` command, the command starts **first** and the entire evaluation runs in the background; after the command exits, the step waits a bounded grace window (≤10s) for the verdict, then finishes with the command's exit code.
4. Inputs are echoed into the dossier so you can audit exactly what produced it. In `enforce` mode a non-200 from the API (with no local verdict) fails the step with the status — no silent green builds.

Every run logs a timing line so the speedups are visible, e.g. `Decionis timing — command started +3ms · API verdict 'allow' in 1840ms +1846ms · command exited code 0 +61.2s`.

### Changed in v1.9.0

- **Shadow mode never fails the step, period.** Previously an API error failed the step even in shadow; now all gate/evaluation failures in shadow are `::notice::` lines and the exit code is your command's (or 0). Shadow also no longer requires credentials — unconfigured gates are inert.
- **`local-eval: auto` is on by default.** Repos with a ` ```decionis ` rules block get local verdicts + async notarization; repos without one see no change in decision flow. Set `local-eval: off` for strict v1.8 behavior.
- **API outcomes are normalized** (`APPROVE`→`allow`, `REJECT`→`block`, `REQUIRE_REVIEW`/`REVIEW`→`review`) so `run` gating and `fail-on` work against the current Decionis API vocabulary.

---

Built by [Decionis](https://decionis.com?source=github_action_readme) · [Quickstart](https://decionis.com/quickstart?source=github_action) · [Dossier example](https://decionis.com/dossier-example?source=github_action) · Apache-2.0 licensed
