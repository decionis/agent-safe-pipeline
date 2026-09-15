# From shadow to enforcement

One workflow, one action, one team. Start with the action whose evidence someone will ask for
first.

## Before shadow

- A Decionis tenant and its server-side API key, mounted as `DECIONIS_API_KEY_FILE`, or your own
  authority behind the same two interfaces.
- A principals file, mounted as `EXECUTOR_PRINCIPALS_FILE`, naming every caller: the workflows that
  may propose, what each may propose, and the operators who may read the status and the metrics. A
  first deployment without one runs on a single caller token, mounted as
  `EXECUTOR_CALLER_TOKEN_FILE`, held by the workflow that proposes and by
  nothing else.
- The handler for the action, in `src/Handlers.ts`, with its parameter schema; the image built from
  it; the ConfigMap naming the downstream and the actor.
- Three questions answered in writing, because they decide where the executor sits:
  1. Where, in the path from the agent's proposal to the provider's effect, is the last point at
     which the action can be refused before anything changes? That is where the executor goes, and
     the NetworkPolicy is drawn around it.
  2. What does the workflow already know at that point that policy will need: the actor, the
     target, the amount, the environment? That is the trusted context and the parameters.
  3. When the provider's call succeeds and the response is lost, what does the workflow use today to
     find out what happened? That is what `reconcile` reads, and `DOWNSTREAM_LOOKUP_URL` names it.
- `EXECUTOR_MODE=SHADOW`.

## Shadow

Post every proposal to the executor as well as running it as before, before it runs. Capture it
exactly as enforcement will: the same trusted context, the same parameter schema, the same
idempotency key derivation. Record the executor's answer beside the workflow's outcome.

Compare, over the period you decide on:

- Proposals the authority would have blocked that the workflow ran. Each is a conversation about
  where the fact lives, not yet a defect.
- Proposals the authority would have escalated: who would have been asked, and was that the person
  the workflow would name?
- Observations that came back `UNAVAILABLE` or `TIMED_OUT`. That is the availability cost
  fail-closed enforcement would impose, and it is measured here rather than discovered later.
- `grant_discarded` in the audit stream. It should never be true; if it is, the gate is not in
  shadow mode.

Write the stopping criteria in your own words, as sentences someone can check, and do not borrow a
figure from anywhere. Keep the `SHADOW` label on every log and dashboard: the only way a shadow
result gains authority is a person reading it as one.

## Controlled enforcement

The workflow requires the executor's answer before it acts, and acts only through the executor, for
this action only. `EXECUTOR_MODE=ENFORCEMENT`. Capture fresh intents; a shadow-observed intent is
never reused for enforcement.

An `ESCALATE` comes back with no grant and, when `EXECUTOR_ESCALATION` is `DIRECT` or `MANAGED`,
with what the workflow presents back once the person has answered. Choose the shape before this
step: `DIRECT` puts the Presence credential in the executor and has it open the request; `MANAGED`
keeps every Presence credential with the authority and has the executor poll the authority only.
Either way the authority decides again with the receipt as evidence, and an approval cannot revive an
intent past its lifetime, so set `EXECUTOR_INTENT_TTL_SECONDS` to the longest a ceremony may take,
at most five minutes.

An attempt whose answer never came back is `UNKNOWN_AFTER_DISPATCH`. The workflow presents the
recovery object to `/v1/reconciliations`; the executor reads what the provider did and never sends
the request again. A new side effect needs a new decision.

## Enforcement

The action is reachable only through the executor: the agent runtime has no path to the provider,
and the provider credential exists only behind the executor. Then the next action.

## Stopping, and starting again

The executor stops taking new work in four ways, and one of them is yours to reach for:

1. **An operator asks it to.** `POST /v1/control/halt` with `{"reason":"..."}` from a principal
   holding the `halt` scope. The reason is written to the security stream verbatim, so write the
   one a colleague will need at 3 a.m.
2. **The halt file appears.** Create the ConfigMap the manifest mounts and every replica halts
   within seconds, whether or not anyone can reach its control route. This is the one that works
   when the control plane is the thing you distrust.
3. **The executor halts itself**: a posture drift, a spike of refused credentials at the door, a
   spike of refused outbound requests, or a clock too far from the authority's.
4. **It starts halted**, if the halt file is there when the process starts.

While halted, a proposal is refused with `503`, `reason_codes: ["EXECUTOR_HALTED"]` and a
`Retry-After`; nothing is asked of the authority; `/ready` answers `503` so the load balancer
takes the replica out; `/health` stays `200` so nothing restarts it. Work already in flight
finishes and is journaled, because abandoning a dispatch is how an outcome becomes unknown.

To start again:

1. Read `GET /v1/control/status` and `GET /v1/control/open-attempts`. Every attempt whose outcome
   is `STILL_UNKNOWN` is a provider you have not yet asked; resolve those first, with the
   provider's own records, before anything else executes.
2. Remove the cause. Delete the halt ConfigMap, fix the posture drift, rotate the credential that
   was flooding the door, correct the clock. `POST /v1/control/resume` is refused with
   `409 HALT_CAUSE_PERSISTS` while the halt file is present or a drift still stands, which is the
   check telling you the cause is still there.
3. `POST /v1/control/resume` with `{"reason":"..."}` from a principal holding the `resume` scope.
   The reason lands on the security stream beside the halt it answers.
4. Watch `agentsafe_open_attempts` and the `HALTED` events. A halt that returns immediately is a
   cause you have not actually removed.

Never resume by restarting the process with the halt file deleted and the journal discarded: the
open attempts are the only record of what may already have happened.

## What to keep

The audit lines and the Decision Dossier identifiers returned with each attempt. Together with the
authority's record they say who allowed this exact action, that it ran once, and what the provider
reported afterwards.
