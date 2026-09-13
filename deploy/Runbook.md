# From shadow to enforcement

One workflow, one action, one team. Start with the action whose evidence someone will ask for
first.

## Before shadow

- A Decionis tenant and its server-side API key, mounted as `DECIONIS_API_KEY_FILE`, or your own
  authority behind the same two interfaces.
- A caller token, mounted as `EXECUTOR_CALLER_TOKEN_FILE`, held by the workflow that proposes and by
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

## What to keep

The audit lines and the Decision Dossier identifiers returned with each attempt. Together with the
authority's record they say who allowed this exact action, that it ran once, and what the provider
reported afterwards.
