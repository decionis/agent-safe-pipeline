# Incident response for the trusted executor

What to do when something has gone wrong with the execution boundary itself. This is runtime
incident response for an adopter running `@decionis/agentsafe`; it is not
[vulnerability response](./vulnerability-response.md), which is how a reported flaw in this
repository is triaged and fixed.

Six playbooks. Each says what you would see, what to do first, what to preserve, who decides, and
what never to do. They are written to be adopted rather than followed as-is: the decider column
names a role this repository cannot fill for you, and the thresholds are your institution's.

Before any of them: the executor is designed so that stopping is cheap and resuming is not. Reach
for the stop early. Nothing in flight is abandoned by a halt, so halting costs you the proposals
that have not started, and nothing else.

```bash
kubectl -n agent-safe-executor create configmap agent-safe-executor-halt \
  --from-literal=halted="describe the incident here"
```

That works whether or not the control route answers, which is why it is first in every playbook
below. `POST /v1/control/halt` with a reason is the same stop through the front door.

## What you have to work with

| Signal                               | Where                                                              |
| ------------------------------------ | ------------------------------------------------------------------ |
| The security stream                  | Standard error, `agent-safe.security/1`, hash-chained              |
| The evidence stream                  | Standard output, `agent-safe.executor-evidence/1`, hash-chained    |
| Metrics                              | `GET /metrics`, an operator holding `metrics`                      |
| What this process knows about itself | `GET /v1/control/status`                                           |
| Attempts whose outcome nobody knows  | `GET /v1/control/open-attempts`                                    |
| A bundle of all of the above         | `POST /v1/control/evidence-export`, an operator holding `evidence` |
| Every decision, and who allowed it   | The authority's own record, which this process cannot alter        |
| Parameters and amounts               | The attempt journal on the volume, which is **not** in any export  |

The journal is deliberately excluded from an export: it holds request parameters, so it is as
sensitive as the traffic. Take it from the volume, under the same handling as the traffic, and
only when a playbook says you need it.

### Taking a bundle

```bash
curl -sS --cert ops.crt --key ops.key \
  -X POST https://agent-safe-executor.agent-safe-executor.svc.cluster.example:8443/v1/control/evidence-export \
  -H 'content-type: application/json' \
  -d '{"reason":"payment rail incident, on-call took a bundle"}'
```

The answer names the directory on the journal volume and carries the manifest. Copy the directory
out, then verify it where you are going to read it:

```bash
agentsafe verify-bundle ./2026-03-02T10-00-00-000Z
```

The verifier recomputes every file's digest against the manifest, walks both chains, and checks
that each stream's last line is the head the manifest claims. It needs no key, no network and no
cooperation from the executor to do that, which is the point.

It reports one of two things, and the difference matters:

- `INTERNAL_CONSISTENCY` — the bundle is the bundle that was made, and nothing establishes **who**
  made it.
- `ORIGIN_AND_CONSISTENCY` — a signature over the manifest verified against a public key **you**
  supplied in `AGENTSAFE_EVIDENCE_PUBLIC_KEY`. A signature the bundle verified with a key the
  bundle carried would prove nothing, so the verifier will not do that.

Set `EXECUTOR_EVIDENCE_SIGNING_KEY_FILE` before an incident if you want the second one. Afterwards
is too late.

## Proposer compromise

The workflow that proposes is behaving like an attacker: proposals you did not expect, refused
credentials in volume, or an action outside what the principal may ask for.

|                   |                                                                                                                                                                                                                                                    |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **You would see** | `AUTH_FAILED` in volume, `PRINCIPAL_LOCKED`, `ACTION_NOT_PERMITTED_FOR_PRINCIPAL`, `SEPARATION_OF_DUTIES_VIOLATED`, a rising `agentsafe_auth_failures_total`, or a halt with trigger `AUTH_FAILURE_SPIKE`                                          |
| **Contain**       | Halt. Then remove the principal from the principals file and apply it, or revoke the workload identity in the cluster so the token stops being signed. A bearer principal is removed by deleting its entry; there is no revocation list, by design |
| **Eradicate**     | Find how the proposer was reached. The agent zone has no route off the cluster, so a compromise came in with the workload's own image, its supply chain, or its prompt                                                                             |
| **Recover**       | Reconcile every open attempt first. Then a new principal with a new credential, and resume with a reason                                                                                                                                           |
| **Preserve**      | A bundle, the authority's decision record for the window, and the agent runtime's own logs, which this repository knows nothing about                                                                                                              |
| **Decider**       | The OPERATOR on call halts. The tenant admin in the authority decides whether the policy that allowed those proposals was right                                                                                                                    |
| **Never**         | Never widen `allowed_actions` to make an alert stop. Never resume before the open attempts are resolved: a compromised proposer's in-flight attempt is exactly the one you need to know the outcome of                                             |

## Executor host compromise

The process is running somewhere it should not be, or something on the host has changed underneath
it.

|                   |                                                                                                                                                                                                                                        |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **You would see** | `POSTURE_DRIFT` with a check name, a halt with trigger `POSTURE_DRIFT`, `EGRESS_REFUSED` for an origin no handler should reach, `LEAK_SUSPECTED`, or a pod that will not start with `REFUSED_TO_START` and a posture code              |
| **Contain**       | Halt through the ConfigMap, not the control route: if the host is compromised, the route is answering from the thing you distrust. Then cordon the node and delete the pod. The StatefulSet brings the replica back to its own journal |
| **Eradicate**     | The posture code says which check failed and nothing about the value. Compare the running pod's spec against `deploy/kubernetes/TrustedExecutor.yaml`; a drift is usually a mutating admission webhook or a manual edit                |
| **Recover**       | Rotate every credential the process held: they were readable by it. Then a fresh pod on a clean node, posture green, open attempts resolved, resume with a reason                                                                      |
| **Preserve**      | A bundle if the process still answers, the pod spec as admitted, the node's own audit log, and the journal volume before it is reused                                                                                                  |
| **Decider**       | The platform team owns the node. The OPERATOR owns the halt. Rotating the authority credential is the tenant admin's                                                                                                                   |
| **Never**         | Never set `EXECUTOR_POSTURE=DEVELOPMENT` to get a pod running during an incident. That waives the checks that are telling you what is wrong, and production refuses it anyway                                                          |

## Credential leak

A credential the executor holds has been exposed, or may have been.

Each one has a different blast radius, and they are not interchangeable:

| Credential                       | What an attacker can do with it                                                                         | Rotate by                                                            |
| -------------------------------- | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| A caller's bearer token          | Propose as that principal, within its `allowed_actions`. It cannot execute: a grant is still required   | Changing the digest in the principals file                           |
| A caller's client certificate    | The same, until the certificate is revoked by your PKI                                                  | Your PKI, plus the SAN URI or the fingerprint pin in the file        |
| `DECIONIS_API_KEY`               | Ask the authority for decisions as your tenant, and claim grants. This is the serious one               | The authority's own console; the executor follows the file           |
| `DOWNSTREAM_CREDENTIAL` or a key | Act on the provider **without** the executor, which is the boundary gone                                | The provider, then the mounted file                                  |
| `PRESENCE_API_KEY`               | Open approval requests. A receipt still has to come from the named person's own ceremony                | The Presence console                                                 |
| `EXECUTOR_TLS_KEY`               | Impersonate the listener to a caller                                                                    | Your certificate authority; the listener swaps context live          |
| `EXECUTOR_EVIDENCE_SIGNING_KEY`  | Sign a bundle that is not the executor's. No past bundle becomes false; future ones stop meaning origin | A new key pair, and tell whoever verifies bundles the new public key |

|                   |                                                                                                                                                                                                                                                         |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **You would see** | `LEAK_SUSPECTED` (the redactor changed a line on its way out), `SECRET_RELOAD_REFUSED`, a credential in a place it should not be, or a report from someone else                                                                                         |
| **Contain**       | For the downstream credential or the authority key: halt first, because both let something act without the boundary. For a caller credential: remove the principal; the executor keeps taking other work                                                |
| **Eradicate**     | Replace the file. The executor follows a changed file within seconds without a restart, and emits `SECRET_ROTATED` with the name. `POST /v1/control/secrets/reload` makes it immediate                                                                  |
| **Recover**       | Confirm the old value no longer authenticates, from the caller's side and not from the logs. Then resume                                                                                                                                                |
| **Preserve**      | A bundle: its manifest names every secret with a rotation count, which is how you show the rotation happened inside the window. It carries no value and no digest of one, deliberately, because a low-entropy credential's digest is a guessable oracle |
| **Decider**       | Whoever owns the credential's source. The executor only ever reads the file                                                                                                                                                                             |
| **Never**         | Never put a credential in the ConfigMap "temporarily". Production refuses a secret given as a plain variable, and the posture check refuses a secret file the process is not alone in being able to read                                                |

## Authority compromise or unavailability

The authority is answering wrongly, or not answering at all.

|                   |                                                                                                                                                                                                                                                                                               |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **You would see** | Decisions that do not match your policy, `fail_closed: true` answers, `DECISION_NOT_AUTHORITATIVE`, a rise in `agentsafe_proposals_total{verdict="NONE"}`, or timeouts                                                                                                                        |
| **Contain**       | Unavailability needs no action: the boundary fails closed, nothing executes, and the workflow gets a refusal. A _compromised_ authority is different and needs the halt, because its answers are the thing granting execution                                                                 |
| **Eradicate**     | The authority's, not yours. What is yours is confirming the address and the credential your process is using: the configuration digest in a bundle manifest tells you whether two replicas were configured the same way                                                                       |
| **Recover**       | Fresh grants only. Every grant issued during the window is suspect, and a grant is single-use and short-lived precisely so that waiting resolves this                                                                                                                                         |
| **Preserve**      | A bundle, and the authority's record for the window from the authority's side. Your evidence stream holds what it told you; only the authority holds what it decided                                                                                                                          |
| **Decider**       | The tenant admin, with the authority's operator. Not on-call alone                                                                                                                                                                                                                            |
| **Never**         | Never point `DECIONIS_API_URL` at the fixture authority to keep working. It is a development double that allows what you ask it to, and `DECIONIS_ALLOW_INSECURE_LOOPBACK` is refused in production. Never resume against a different authority URL without a two-person configuration change |

## Duplicate dispatch or effect mismatch

Something may have happened twice, or something happened that is not what was authorised.

|                   |                                                                                                                                                                                                                                                                                                                                                       |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **You would see** | `EFFECT_MISMATCH` with the differing field names and a halt with trigger `EFFECT_MISMATCH`; or `agentsafe_open_attempts{state="UNKNOWN"}` above zero; or `EFFECT_PENDING_CONFIRMATION` on every commit, which means nothing is being read back at all                                                                                                 |
| **Contain**       | Already halted, if `EXECUTOR_ON_EFFECT_MISMATCH` is `HALT` — the default, because the next proposal would otherwise be made against a state nobody has reconciled. With `ALERT`, halt now                                                                                                                                                             |
| **Eradicate**     | Read `GET /v1/control/open-attempts`. For each, ask the provider what it did with that idempotency key, using the provider's own records rather than the executor. The response's `effect` block holds both digests and the fields that differed; the mismatch is about the projection the profile names, so the differing field is the fact to chase |
| **Recover**       | Reconcile **every** open attempt before resuming. A reversal is a new action with its own dossier and its own approval, never a retry: the boundary has no notion of undoing, and a retry of a dispatch whose outcome is unknown is how one payment becomes two                                                                                       |
| **Preserve**      | A bundle, the provider's own record for the key, and the journal from the volume, which is the only place the parameters are                                                                                                                                                                                                                          |
| **Decider**       | The business owner of the action decides whether to reverse. On-call decides when to resume                                                                                                                                                                                                                                                           |
| **Never**         | Never re-send a dispatch whose outcome is unknown. Never treat the absence of a provider error as success: only a read-back whose projection matches is a confirmation                                                                                                                                                                                |

## Audit chain break

The evidence does not verify.

|                   |                                                                                                                                                                                                                                                                                                                                                                               |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **You would see** | `agentsafe verify-chain` reporting `CHAIN_HASH_MISMATCH`, `CHAIN_SEQ_GAP` or `CHAIN_PREV_MISMATCH`, or `verify-bundle` reporting `BUNDLE_CHAIN_BROKEN` or `BUNDLE_CHAIN_HEAD_MISMATCH`                                                                                                                                                                                        |
| **Contain**       | Halt. A chain that does not verify means you cannot say what this process did, and continuing adds lines to a record you already cannot trust                                                                                                                                                                                                                                 |
| **Eradicate**     | Distinguish three things the codes tell apart. A **gap** in sequence is usually the log pipeline dropping lines, not tampering. A **fresh start from genesis** mid-stream is a restart that lost its chain journal, which is the volume's problem. A **hash that does not match its own fields** is a line that was altered after it was written, and that is the serious one |
| **Recover**       | A break is not repairable and must not be made to look repaired. Note the range, keep the broken lines, and start a fresh chain by restarting with a clean chain journal. The authority's record is independent of yours and covers the same window                                                                                                                           |
| **Preserve**      | The lines themselves, unedited, before anything rotates them. A bundle records the heads as this process saw them, which is how you show where the divergence starts                                                                                                                                                                                                          |
| **Decider**       | Whoever owns the audit record: usually internal audit or compliance, not on-call                                                                                                                                                                                                                                                                                              |
| **Never**         | Never regenerate or backfill lines to make a chain verify. A chain establishes continuity and integrity, not origin; a regenerated chain establishes nothing at all                                                                                                                                                                                                           |

## The resume checklist

Every playbook ends here. `POST /v1/control/resume` is refused with `HALT_CAUSE_PERSISTS` while
the halt file is present or a posture drift still stands, which is the executor telling you it can
see the cause. The rest is yours to check:

1. **Zero unknown attempts.** `GET /v1/control/open-attempts` is empty, or every remaining entry
   has been resolved against the provider's own records.
2. **Posture green.** `GET /v1/control/status` reports `posture.degraded: false`.
3. **The cause is gone**, not merely quiet: the credential rotated, the node replaced, the clock
   corrected, the halt ConfigMap deleted.
4. **A reason recorded.** The reason you give lands on the security stream beside the halt it
   answers. Write the one a colleague will need in six months.
5. **Fresh grants only.** Nothing that was authorised before the incident may execute after it.
   Grants are single-use and short-lived so that this takes care of itself; do not defeat it by
   replaying a stored response.
6. **A bundle taken and verified**, before the evidence rotates out of the window this process
   still holds.

A halt that returns immediately after a resume is a cause you have not actually removed. Do not
resume a third time; go back to the playbook.
