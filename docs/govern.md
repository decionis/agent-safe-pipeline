# Govern: the workflow gate

A deploy, a migration, an infrastructure change, a release, a merge an agent asked for: the step
that does it runs in a workflow runner, with credentials the runner holds, on a trigger that a
commit, a comment or an agent produced. Govern puts one Decionis verdict in front of that step.
The step becomes an execution intent, Decionis decides on exactly that intent, the command runs
only on an `ALLOW` whose single-use grant the gate claimed first, and what happened is finalized
into a signed Decision Dossier. It is the same execution contract the [runtime](../packages/agentsafe/README.md)
speaks in front of an HTTP service, at a different place in the path: before a command in a
pipeline, on GitHub Actions, GitLab CI, Jenkins or any runner that can run a binary.

Nothing is decided locally. There is no policy engine in the binary, no cached verdict and no
"allow when unsure": a Decionis that cannot be reached, or an answer outside the contract, is a
refusal, and the command does not run. Shadow is the exception by design, and it decides nothing
either: it starts the command at once and records what Decionis would have said beside it.

## What one governed step is

```text
capture   the step as agent-safe.intent/1: who runs it, what it does, on what, where, until when
decide    POST /v1/authority/enforce-and-bind → ALLOW | ESCALATE | BLOCK, a Decision Dossier, on ALLOW a grant
claim     POST /v1/execution/claim-token, once, immediately before the command
run       the command, with the decision's identifiers and the claim attestation in its environment
finalize  POST /v1/execution/finalize-token: COMMITTED, FAILED or INDETERMINATE, from the exit code
```

The intent is the [Agent-Safe Intent v1](../spec/intent/v1/README.md) binding: the action's type and
resource, its parameters (the step's `payload`), the actor (the workflow's identity, type
`WORKFLOW`), the downstream target (the runner as the system, the action as the operation, the
deployment environment, the run's URL as the endpoint), and a context that carries what the runner
knows about the run (repository, ref, commit, actor, run id and URL, workflow, job) and the
repository's policy file by path and SHA-256. The hash of its canonical form is what every later
record names; the [conformance vectors](../conformance/vectors/README.md) hold the Go binary to the
reference implementation byte for byte.

| Verdict    | Enforcement                                                                                              | Shadow                                   |
| ---------- | -------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `ALLOW`    | the grant is claimed, the command runs, the outcome is finalized                                         | recorded; the command already ran        |
| `ESCALATE` | the step fails with the command never started, or holds while Decionis orchestrates the approval (below) | recorded                                 |
| `BLOCK`    | the step fails with the command never started                                                            | recorded                                 |
| refusal    | `AUTHORITY_UNAVAILABLE`, `AUTHORITY_RESPONSE_INVALID`, … — the step fails with the command never started | a notice; the exit code is the command's |

A step that wraps no command is advisory: its `decision` output feeds a later step's `if:`, and
`fail-on` says which verdicts fail it. Wrapping the command is the enforcing shape: there is no
`if:` to delete.

## Holding a step for a person

With `escalation: managed` (or an `approver` or `approver-role`), an `ESCALATE` does not end the
step. Decionis opens a managed escalation, Presence verifies the approver, and the step polls
`/v1/authority/escalations/{id}` until the escalation ends: `GRANT_READY` carries the grant and the
command runs; a rejection, a cancellation or an expiry is a `BLOCK`. The wait is bounded by the
intent's lifetime, five minutes at most, and a step that runs out of time runs nothing. [Human
approval](./human-approval.md) and [Presence evidence](./presence-evidence.md) say what the
approver's evidence is and why the gate never sees it.

## What the record shows

Every run writes the same facts to every surface the runner has: outputs a later step reads
(`decision`, `decision-id`, `dossier-id`, `intent-hash`, `outcome`, `finalization`, …), a run
summary, a pull-request or merge-request comment updated in place, and, when asked, a JSON record
(`agent-safe.govern-report/1`). The Decision Dossier is read back with the run's own key after the
decision, and its signature material is reported; `verify-url` carries the public page when
Decionis attaches one. The command itself receives `DECIONIS_DECISION_ID`,
`DECIONIS_DOSSIER_ID`, `DECIONIS_INTENT_HASH` and `DECIONIS_CLAIM_ATTESTATION`, the authority's own
signed statement that this claim was made, which a system of record can verify before it acts
([Verifying Provider Profile](./authority/verifying-provider.md)). The grant never leaves the gate.

## Where to start

`govern init` writes a repository's starter files and nothing else: a shadow-mode workflow for the
runner the tree is set up for (`.github/workflows/decionis-govern.yml`,
`.gitlab/ci/decionis-govern.yml` to include, or `jenkins/decionis-govern.groovy` to paste) and a
`DECIONIS_POLICY.md` at the root; it keeps any file that exists and never touches git. Shadow
first: until the key and tenant exist the step is inert, then it records; the verdicts show on
pull requests; then `mode: enforce` and the command to gate. [Shadow mode](./shadow-mode.md) is
the same idea for the runtime.

The binary ships with the repository's releases, built twice per platform and shipped only when
identical, listed in `SHA256SUMS`, attested, and pinned by a signed `govern/v<version>` module
tag; the GitHub action downloads the archive its commit names and verifies it before running, or
builds the same bytes from that commit when no archive exists yet. Govern's
[README](../govern/README.md) has the install paths, every setting and output, the exit codes, and
the runners' surfaces.

## What it does not do

Govern does not read the command's output as decision input, does not send a credential or a
person's text to Decionis, does not decide when Decionis cannot, and does not stop a step that
runs outside it: a workflow with the gate on one step and the deploy on another has governed the
first. The [trust boundary](./trust-boundary.md) is the same as the runtime's; the runner is where
the gate runs, not what it trusts.
