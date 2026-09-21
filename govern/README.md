# Govern

**One verdict before a workflow step runs — a deploy, a migration, an infrastructure change, an
agent's action — with a signed Decision Dossier of it.**

[![Governed by Decionis](https://img.shields.io/badge/Governed%20by-Decionis-6D28D9?logo=shield&logoColor=white)](https://github.com/decionis/agent-safe-pipeline/tree/master/govern)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)

Govern is one binary for any workflow runner — GitHub Actions, GitLab CI, Jenkins, or anything that
can run a command — that speaks the Decionis execution contract the [AgentSafe runtime](../packages/agentsafe/README.md)
speaks: it captures the step as an [execution intent](../docs/execution-intent.md), asks Decionis
for a decision on exactly that intent, runs the command only on an `ALLOW` whose single-use grant it
claimed first, and finalizes what happened so the outcome joins the signed Decision Dossier. Nothing
is decided locally: a Decionis that cannot be reached, or an answer outside the contract, is a
refusal, and the command does not run.

> **Where this lives.** Govern's source is this directory of
> [`decionis/agent-safe-pipeline`](https://github.com/decionis/agent-safe-pipeline).
> [`decionis/govern`](https://github.com/decionis/govern) is the address GitHub workflows use
> (`uses: decionis/govern@v2`; `v1` is the earlier node20 action, which spoke the evaluate-decision
> API) and the Marketplace listing. The version here is `2.1.0` ([`VERSION`](./VERSION)).

## What one governed step is

```text
capture   the step as agent-safe.intent/1: who runs it, what it does, on what, where, until when
decide    POST /v1/authority/enforce-and-bind → ALLOW | ESCALATE | BLOCK, a Decision Dossier, and on ALLOW a grant
claim     POST /v1/execution/claim-token, once, immediately before the command: the authority consumes the grant
run       the command, with the decision's identifiers and the claim attestation in its environment
finalize  POST /v1/execution/finalize-token: COMMITTED, FAILED or INDETERMINATE, from the exit code
```

`ESCALATE` can hold the step: with `escalation: managed`, Decionis orchestrates the approval and the
step waits for it, at most until the intent expires (five minutes, the contract's ceiling). `BLOCK`
ends the step with the command never started. In **shadow** the command starts at once and the
verdict is recorded beside it; shadow never fails a build for the gate's sake.

The intent carries what the runner knows about the run (repository, ref, commit, actor, run id and
URL, workflow, job) and, when the repository has one, its policy file's path and SHA-256, so the
dossier names the exact policy revision the repository held. Nothing the command prints, no
credential, and nothing a person typed reaches Decionis.

## GitHub Actions

```yaml
- uses: decionis/govern@v2
  with:
    api-key: ${{ secrets.DECIONIS_API_KEY }}
    tenant-id: ${{ vars.DECIONIS_TENANT_ID }}
    action: production-deploy
    environment: production
    payload: '{ "service": "api" }'
    run: ./scripts/deploy.sh # runs only on an ALLOW whose grant this step claimed
```

Start without enforcing anything:

```yaml
- uses: decionis/govern@v2
  with:
    api-key: ${{ secrets.DECIONIS_API_KEY }}
    tenant-id: ${{ vars.DECIONIS_TENANT_ID }}
    mode: shadow # the command starts at once; the verdict is recorded beside it
    action: production-deploy
    run: ./scripts/deploy.sh
    comment: "true" # the verdict on the pull request, updated in place
```

Without `run`, the step is advisory: `steps.<id>.outputs.decision` is `ALLOW`, `ESCALATE` or
`BLOCK`, and `fail-on` says which of them fails the step. The recipes in [`examples/`](./examples)
cover a deploy, `terraform apply` on the plan's blast radius, a release held for the release
manager, a shadow comment on every pull request, agent-authored pull requests, and Dependabot
auto-merge.

The action runs the bytes its commit names: [`release.json`](./release.json) beside it pins each
platform archive's SHA-256, the first step downloads the archive for the runner and verifies it
before extracting (a second or so), and only a version the manifest does not name yet, or a runner
without an archive, is built from the commit with the pinned Go toolchain (`actions/setup-go`,
about twenty seconds, cached) — the same bytes, which the release's double build holds the
archive to. The release workflow renders the manifest from the release's `SHA256SUMS` and opens it
with the Homebrew formula as one pull request.

## GitLab CI, Jenkins, and any other runner

The same binary, the same flags, the runner detected from its own variables:

```sh
govern run --action production-deploy --environment production \
  --payload '{"service":"api"}' -- ./scripts/deploy.sh
```

The arguments after `--` are quoted for the shell in use, so the command runs as typed: bash or
`sh` by default, Windows PowerShell on a Windows agent unless another shell is named, and `--run`
takes a line already written for that shell.

```powershell
govern run --shell pwsh --action production-deploy -- ./scripts/deploy.ps1 -Environment production
```

| Runner         | Detected by                      | Facts                              | Outputs                                                   | Comment                                                        |
| -------------- | -------------------------------- | ---------------------------------- | --------------------------------------------------------- | -------------------------------------------------------------- |
| GitHub Actions | `GITHUB_ACTIONS`                 | `GITHUB_*`                         | `GITHUB_OUTPUT`, the step summary                         | the pull request, with `GITHUB_TOKEN` (`pull-requests: write`) |
| GitLab CI      | `GITLAB_CI`                      | `CI_*`                             | a dotenv report (`govern.env`, or `GOVERN_OUTPUT_FILE`)   | the merge request, with `GOVERN_GITLAB_TOKEN` (`api` scope)    |
| Jenkins        | `JENKINS_URL` and `BUILD_NUMBER` | `JOB_NAME`, `BUILD_URL`, `GIT_*`   | a properties file (`govern.env`, or `GOVERN_OUTPUT_FILE`) | —                                                              |
| anything else  | —                                | `GOVERN_REPOSITORY`, `GOVERN_SHA`… | `GOVERN_OUTPUT_FILE`, when set                            | —                                                              |

Outputs in a dotenv or properties file are `GOVERN_DECISION`, `GOVERN_DOSSIER_ID`,
`GOVERN_OUTCOME` and the rest, one per line. [`examples/gitlab-ci.yml`](./examples/gitlab-ci.yml)
and [`examples/Jenkinsfile`](./examples/Jenkinsfile) show a job each.

## Install

Govern ships with the repository's [releases](https://github.com/decionis/agent-safe-pipeline/releases)
as one static binary per platform: `govern-<version>-<os>-<arch>.tar.gz` for macOS and Linux on
Apple silicon, ARM and x86-64, and `govern-<version>-windows-x64.zip` for Windows, each built
twice on its own platform and shipped only when the two builds are the same bytes. Every archive
is listed in the release's `SHA256SUMS` and attested by the release workflow, and
`govern-<version>.cdx.json` is the release's CycloneDX SBOM, read from the shipped executables'
own build information (the modules linked in, the toolchain, the build settings, each archive's
checksum) and attested beside them. A `GOVERN_VERSION` such as `2.1.0` pins a version, and the
installer otherwise takes the newest release that carries one.

| How            | Command                                                                                                                            |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Installer      | `curl -fsSL https://raw.githubusercontent.com/decionis/agent-safe-pipeline/master/govern/install.sh \| sh`                         |
| Homebrew       | `brew tap decionis/agent-safe https://github.com/decionis/agent-safe-pipeline && brew install govern`                              |
| Go             | `go install github.com/decionis/agent-safe-pipeline/govern/v2/cmd/govern@v2.1.0`                                                   |
| By hand        | download the archive and `SHA256SUMS` from the release, `shasum -a 256 -c SHA256SUMS`, extract, put `govern` on the path           |
| Windows        | download `govern-<version>-windows-x64.zip` and `SHA256SUMS`, check the zip against the list, unpack, put `govern.exe` on the path |
| GitHub Actions | `uses: decionis/govern@v2` (the action builds or fetches the binary itself, on Windows runners too)                                |

[`install.sh`](./install.sh) does one thing: it detects the platform, downloads the archive and the
release's `SHA256SUMS`, refuses to continue unless the archive's SHA-256 is the one the release
lists, places the directory under `<prefix>/lib/govern/<version>` and links `<prefix>/bin/govern`
to it (`/usr/local` when writable, `~/.local` otherwise, or `GOVERN_INSTALL_PREFIX`). It touches
no shell profile, no workflow file and no configuration; `GOVERN_RELEASE_BASE` and
`GOVERN_RELEASE_CA` point it at a mirror. The Homebrew formula (`Formula/govern.rb` in this
repository, the tap) pins each platform's archive to the checksum the release listed; it is
rendered by the release workflow from `SHA256SUMS` and opened as a pull request, never typed by
hand. The Go module is `github.com/decionis/agent-safe-pipeline/govern/v2`; its tag,
`govern/v<version>`, is signed by the release workflow's identity like the release tag, and
`go.mod` pins the toolchain so a `go install` builds the same bytes the release shipped.

A release is verified the way the runtime's is: `shasum -a 256 -c SHA256SUMS`, and
`gh attestation verify govern-<version>-<os>-<arch>.tar.gz --repo decionis/agent-safe-pipeline`
(or the zip); the same command with `--predicate-type https://cyclonedx.org/bom` checks the SBOM
attestation, and the SBOM itself names each archive it describes with its SHA-256.

## Settings

Every setting is a flag or a variable; flags win. `govern run --help` lists them.

| Flag                            | Variable                                     | Meaning                                                                                                      |
| ------------------------------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| —                               | `DECIONIS_API_KEY` / `DECIONIS_API_KEY_FILE` | The workspace's key; never a flag, so no process listing shows it; pasted quotes and whitespace are stripped |
| `--tenant`                      | `DECIONIS_TENANT_ID`                         | The workspace (organization) the key belongs to, a UUID; required beside the key                             |
| `--api-url`                     | `DECIONIS_API_URL`                           | `https://api.decionis.com` unless self-hosted                                                                |
| `--mode`                        | `GOVERN_MODE`                                | `enforce` (default) or `shadow`                                                                              |
| `--action`                      | `GOVERN_ACTION`                              | The action's type as the record names it (`[a-z][a-z0-9._:-]*`); default `workflow.step`                     |
| `--resource`                    | `GOVERN_RESOURCE`                            | What it acts on; default: the command                                                                        |
| `--payload`                     | `GOVERN_PAYLOAD`                             | A JSON object (or `@file`): the action's parameters                                                          |
| `--environment`                 | `GOVERN_ENVIRONMENT`                         | The deployment environment; GitLab's `CI_ENVIRONMENT_NAME` otherwise                                         |
| `--run` or `-- <command>`       | `GOVERN_RUN`                                 | The gated command                                                                                            |
| `--shell`                       | `GOVERN_SHELL`                               | `bash` (default; `powershell` on Windows), `sh`, `pwsh`, `powershell`, `cmd`; `--` is quoted for the shell   |
| `--fail-on`                     | `GOVERN_FAIL_ON`                             | For a step without a command: `block` (default), `escalate`, `block_or_escalate`, `never`                    |
| `--escalation`                  | `GOVERN_ESCALATION`                          | `managed`: hold an `ESCALATE` for Decionis' approval flow                                                    |
| `--approver`, `--approver-role` | `GOVERN_APPROVER`, `GOVERN_APPROVER_ROLE`    | Who approves a managed escalation; either implies `managed`                                                  |
| `--policy-file`                 | `GOVERN_POLICY_FILE`                         | Default `DECIONIS_POLICY.md` (`.yaml`/`.yml` tried); `""` disables                                           |
| `--workspace`                   | `GOVERN_WORKSPACE`                           | The checkout; the runner's own variable otherwise                                                            |
| `--comment`                     | `GOVERN_COMMENT`                             | Post the verdict on the change request                                                                       |
| `--no-attribution`              | `GOVERN_ATTRIBUTION=false`                   | Drop the footer from the comment                                                                             |
| `--report`                      | `GOVERN_REPORT`                              | Write the JSON record (`agent-safe.govern-report/1`); `-` for stdout                                         |
| `--timeout`                     | `GOVERN_TIMEOUT`                             | Per authority call; default `20s`                                                                            |
| `--intent-ttl`                  | `GOVERN_INTENT_TTL`                          | How long the intent stays decidable; at most `5m`                                                            |
| `--actor-id`, `--actor-type`    | `GOVERN_ACTOR_ID`, `GOVERN_ACTOR_TYPE`       | Who proposes the action; default the workflow's identity, type `WORKFLOW`                                    |
| `--host`                        | `GOVERN_HOST`                                | `github`, `gitlab`, `jenkins`, `generic`; detected otherwise                                                 |

The command's environment carries `DECIONIS_INTENT_ID`, `DECIONIS_INTENT_HASH`,
`DECIONIS_DECISION_ID`, `DECIONIS_DOSSIER_ID`, `DECIONIS_GRANT_ID`, `GOVERN_MODE` and, in
enforcement, `DECIONIS_CLAIM_ATTESTATION`: the authority's own signed statement that this claim was
made, which a system of record verifies before it acts ([Verifying Provider Profile](../docs/authority/verifying-provider.md)).
The grant itself never leaves the gate.

## Outputs

| Output                                     | Meaning                                                                                           |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| `decision`                                 | `ALLOW`, `ESCALATE` or `BLOCK`; empty when the authority was not asked                            |
| `decision-id`, `dossier-id`, `dossier-url` | The decision, its Decision Dossier, and the dossier's authenticated path                          |
| `verify-url`                               | A page anyone can open to verify the decision, when the authority attached one                    |
| `intent-id`, `intent-hash`                 | The intent and its canonical SHA-256, what every record names                                     |
| `reason-codes`                             | The authority's reason codes, comma separated                                                     |
| `policy-version`                           | The policy version the decision was made under                                                    |
| `policy-sha256`, `policy-path`             | The repository policy file the intent carried                                                     |
| `mode`                                     | `SHADOW` or `ENFORCEMENT`                                                                         |
| `fail-closed`                              | `true` when no authoritative decision was reached and the gate refused                            |
| `executed`, `claimed`, `exit-code`         | Whether the command ran, whether a grant was claimed for it, and how it exited                    |
| `outcome`, `finalization`                  | `COMMITTED`, `FAILED` or `INDETERMINATE`, and whether Decionis `RECORDED` it or left it `PENDING` |
| `badge-markdown`                           | A “Governed by Decionis” badge linking to the proof                                               |

## Exit codes

The command's own exit code when it ran; `1` when it did not because the verdict, a refusal or a
missing configuration said so; `0` for an advisory step that `fail-on` lets pass; `2` for a flag
the command could not read.

## Fail closed, and what that means here

- In enforcement, the command runs only after `claim-token` consumed the grant for exactly this
  intent hash, decision and dossier: an `ALLOW` without a claim runs nothing.
- An authority that is unreachable, answers outside the contract (`additionalProperties: false`),
  answers about another intent, or issues a grant that outlives the intent is a refusal with a
  reason code (`AUTHORITY_UNAVAILABLE`, `AUTHORITY_RESPONSE_INVALID`, `AUTHORITY_BINDING_MISMATCH`,
  `AUTHORITY_GRANT_MISSING`, …).
- Enforcement without `DECIONIS_API_KEY` and `DECIONIS_TENANT_ID` runs nothing. Shadow without them
  runs the command and records nothing, so a gate a repository has not configured yet is inert.
- A finalization Decionis did not record is reported `PENDING`; it never changes the outcome.

## Repository policy file

Drop a `DECIONIS_POLICY.md` at the repository root and every intent carries its path and SHA-256
(and its text, up to 16 KiB), so the dossier records the revision the repository held. Govern does
not evaluate the file — the rules Decionis enforces are the workspace's, versioned there, and every
verdict names the policy version that applied. [`examples/DECIONIS_POLICY.md`](./examples/DECIONIS_POLICY.md)
is a starting point.

## Building and testing

```sh
cd govern
go build ./cmd/govern
go test ./...                          # unit tests, and the contract against a Go double
pnpm --filter @decionis/agent-safe-pipeline build
node --test test/*.test.mjs            # the binary against the pipeline's own loopback Decionis
```

The Go tests include the repository's [conformance vectors](../conformance/vectors/README.md): the
canonical bytes and digests the reference implementation pins, reproduced byte for byte. The Node
test runs the built binary against `LocalAuthority` from `@decionis/agent-safe-pipeline/testing`,
which re-hashes every binding with its own canonicalizer and validates every request against the
contract's strict shapes: what passes is a client another implementation of the contract accepts.

## Starting a repository: `govern init`

```sh
govern init --action production-deploy
```

It writes a repository's starter files and nothing else: a shadow-mode workflow for the runner the
tree is set up for (`.github/workflows/decionis-govern.yml` when `.github/workflows` exists,
`.gitlab/ci/decionis-govern.yml` to include from `.gitlab-ci.yml` when that file exists,
`jenkins/decionis-govern.groovy` to paste into a Jenkinsfile when one exists; `--host` says
otherwise) and `DECIONIS_POLICY.md` at the root, then prints what is left to a person: the key and
the tenant, the commit. A file that exists is kept unless `--force` says otherwise; `--dry-run`
writes nothing; `--mode`, `--action` and `--branch` shape the starter; `--no-policy` skips the
policy file; git is never touched.

Built by [Decionis](https://decionis.com?source=govern_readme) · Apache-2.0
