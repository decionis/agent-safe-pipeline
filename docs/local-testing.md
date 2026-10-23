# Testing escalations locally

Developers can exercise the complete escalation path on one machine, with no Decionis or Presence
credentials, through `@decionis/agent-safe-pipeline/testing`. The entry ships two loopback doubles
and the development fixture primitives:

| Export                                                                                                          | Stands in for                                                                                 |
| --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `LocalPresence`                                                                                                 | The Presence verification-request surface the `@decionis/presence-node` gate uses             |
| `LocalAuthority`                                                                                                | The Decionis execution-authority routes: enforce-and-bind, escalation status, claim, finalize |
| `createFixtureAuthorityPair`, `FixtureDecisionAuthority`, `FixtureAuthorizationVerifier`, `InMemoryReplayStore` | In-process development authority and verifier (also at the package root until 1.0)            |

The production clients are used unchanged against the doubles: `DecionisGate`,
`DecionisGrantVerifier`, and the real Presence SDK. Both doubles bind to `127.0.0.1` on an
ephemeral port and refuse to construct under `NODE_ENV=production`.

## Direct mode

The trusted executor coordinates Presence and returns the receipt to the authority.

```ts
import { HumanApprovalGate, PresenceClient } from "@decionis/presence-node";
import {
  DecionisGate,
  DecionisGrantVerifier,
  PresenceApprovalCoordinator,
  SafeExecutor,
} from "@decionis/agent-safe-pipeline";
import {
  LocalAuthority,
  LocalPresence,
  LOCAL_AUTHORITY_API_KEY,
  LOCAL_PRESENCE_API_KEY,
} from "@decionis/agent-safe-pipeline/testing";

const presence = new LocalPresence({ autoComplete: "MANUAL", roles: { "synthetic-cro": "CRO" } });
const authority = new LocalAuthority({ presence });
await presence.start();
await authority.start();

const gate = new DecionisGate({
  baseUrl: authority.baseUrl,
  apiKey: LOCAL_AUTHORITY_API_KEY,
  allowInsecureLoopback: true,
});
const coordinator = new PresenceApprovalCoordinator(
  new HumanApprovalGate(
    new PresenceClient({ baseUrl: presence.baseUrl, apiKey: LOCAL_PRESENCE_API_KEY }),
  ),
  gate,
  "Local bank",
  "synthetic-cro",
  {
    requirements: {
      level: "HIGH_CONFIDENCE",
      methods: ["WEBAUTHN", "ACTIVE_LIVENESS"],
      hardware_pki_required: false,
      disallow_virtual_cameras: true,
    },
  },
);

const handoff = await coordinator.request(captured); // HUMAN_REQUIRED
presence.approve(handoff.request_id!); // the person's ceremony
const decision = await coordinator.resolveAndReauthorize(captured, handoff); // ALLOW with a grant
const result = await new SafeExecutor(
  registry,
  new DecionisGrantVerifier({
    baseUrl: authority.baseUrl,
    apiKey: LOCAL_AUTHORITY_API_KEY,
    allowInsecureLoopback: true,
  }),
).run(captured, decision);
```

`presence.deny(requestId)`, `presence.expire(requestId)`, and `presence.cancel(requestId)` produce
the other terminal states. The same completions are reachable over HTTP at
`POST /local/verification-requests/:id/complete` with `{ "response": "APPROVE" | "DENY" }`, which is
how a separate process or a manual test drives the ceremony.

## Managed mode

The authority orchestrates Presence; the executor polls the authority only.

```ts
const pending = await gate.evaluate(captured, undefined, {
  escalation: {
    mode: "MANAGED",
    approver: { principal_id: "synthetic-cro", role_id: "CRO" },
    verification_requirements: {
      level: "HIGH_CONFIDENCE",
      methods: ["WEBAUTHN", "ACTIVE_LIVENESS"],
    },
  },
});
const presenceRequestId = authority.escalations.get(
  pending.managedEscalation!.escalationId,
)!.presenceRequestId!;
presence.approve(presenceRequestId);
const authorized = await gate.waitForAuthorization(captured, pending); // ALLOW with a grant
```

The local authority creates the Presence request the way Decionis does: bound structurally through
`action_context.intent_hash`, addressed to the approver principal, carrying the requested ceremony.
Its status lookups walk the managed lifecycle from `AWAITING_APPROVER` through verification and
re-evaluation to `GRANT_READY`, or to `REJECTED`, `EXPIRED`, `CANCELLED`, or `FAILED`.

## What the doubles verify

| Property                | Behavior                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Structural binding      | `action_context.intent_hash` is sealed as the binding when present; the `Intent hash` display field is the fallback; a conflict between them is rejected with `intent_binding_mismatch`                                                                                                                                                                                                                                                                                                                                                                          |
| Receipt verification    | Terminal `ALLOWED` with result `ALLOW`, the receipt the request produced, action type and target, the intent hash, an approver with a role, an optional required role, and expiry; failures carry Decionis-style reason codes                                                                                                                                                                                                                                                                                                                                    |
| Request contract        | Strict `ExecutionAuthorityRequest` schema, `Idempotency-Key` equal to `intent_id`, an independent canonicalizer that recomputes the hash, the five-minute intent lifetime                                                                                                                                                                                                                                                                                                                                                                                        |
| Grants                  | Single-use claims, replay refused with `NONCE_REPLAY_DETECTED`, direct grants re-verify evidence at claim, managed grants carry no client evidence                                                                                                                                                                                                                                                                                                                                                                                                               |
| Finalization            | `finalize-token` records `COMMITTED`, `FAILED`, or `INDETERMINATE` once per claim; the record is on `authority.grants`                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Expected effect         | `expected_effect_digest` is accepted on the binding, re-hashed by the independent canonicalizer, stored on the grant, echoed in the claim's grant claims, and re-checked at claim time                                                                                                                                                                                                                                                                                                                                                                           |
| Effect evidence         | `effect_evidence` on finalize is validated against the Protocol 1.1 schema and refused in the hosted order before the commit transition, a malformed record answered with 409 `EFFECT_EVIDENCE_INVALID` rather than a 400                                                                                                                                                                                                                                                                                                                                        |
| Finalize 200 body       | Key for key the hosted success body: `finalized`, `outcome`, `evidence_durably_queued`, `decision_chain_evidence_recorded`, `evidence_recorded`, `effect_evidence_recorded`, `effect_confirmation`, `COMMIT_EVIDENCE_PENDING`                                                                                                                                                                                                                                                                                                                                    |
| Fixture ledger          | `FixtureAuthorizationVerifier.finalize` records the outcome in an inspectable ledger, so `RECORDED` from the fixture means the entry exists in `ledger()`                                                                                                                                                                                                                                                                                                                                                                                                        |
| Fault injection         | `scriptOnce(route, override)` delays, truncates, replaces, or destroys the next response on a route; `scriptNextManagedLifecycle` scripts client-visible states                                                                                                                                                                                                                                                                                                                                                                                                  |
| Signed signals          | `evidence.signals` tokens are verified as the hosted authority verifies them, against keys registered with `purpose: "signed_signal"`, and their facts reach the `policy` hook as `signed_signals` by name; a refusal is a 409 with its `SIGNED_SIGNAL_*` code                                                                                                                                                                                                                                                                                                   |
| Commit-time state       | A claim re-derives authority before it consumes the grant, in the hosted order: `POLICY_VERSION_STALE` after `releasePolicy()`, `SIGNAL_VERSION_STALE` after `publishSignal()` of a signal the `materialSignals` option names for the request, `POLICY_STATE_CHANGED` in a scope an assumption breach holds, then `NONCE_REPLAY_DETECTED`, then `CURRENT_STATE_UNRESOLVED` behind an `INDETERMINATE` claim and `AUTHORIZATION_SCOPE_BUSY` behind an open one on the same signal scope; the signals' current values reach the `policy` hook as `material_signals` |
| Organisation-bound keys | `tenantKeys` binds further API keys to one organisation each, as hosted keys are: a request naming another tenant is refused at enforce-and-bind (403 `AUTHORITY_TENANT_MISMATCH`) and at claim (403 `TENANT_MISMATCH`); the `apiKey` itself stays unbound                                                                                                                                                                                                                                                                                                       |
| Policy lifecycle        | Every `/v1/policies` route answers 401 `ACCOUNT_SESSION_REQUIRED` to any key, as the hosted lifecycle takes an account session only; `releasePolicy()` is the governance authority's own act                                                                                                                                                                                                                                                                                                                                                                     |
| Addressable grants      | `addressableGrants: true` mints tokens in the hosted shape (an unsigned JWT whose `jti` is the grant's UUID), so clients use the grant resources, including reconciliations, which have no legacy alias                                                                                                                                                                                                                                                                                                                                                          |
| Assumption breaches     | A finalization whose verified receipt or observation contradicts its grant opens one breach for that action at that target (`authority.assumptionBreaches`), reported as `assumption_breach`; while it is open an autonomous `ALLOW` there becomes `ESCALATE` (`ASSUMPTION_BREACH_OPEN`) and a grant issued autonomously before it fails at claim with `POLICY_STATE_CHANGED`; `assumptionBreaches.clear(citations)` is the governed release that cites it, refused unless every evidence id is named                                                            |

## What they do not reproduce

- No FIDO2 ceremony, liveness check, or device binding runs. Completion is a method call or the
  control route, and the receipt's authenticator evidence is whatever the double was configured with.
- Receipts and dossiers are not signed; `GET /v1/dossiers/:id/verify` answers valid for any receipt
  the double sealed and invalid otherwise.
- The Presence Authority envelope protocol between Decionis and Presence is not simulated. The
  local authority orchestrates the local Presence in process; what is faithful is the client-visible
  contract on both sides.
- Nothing is delivered. The invitation link uses a reserved `.invalid` host.
- Commit-time revalidation is modelled for policy releases, material signals and their concurrency
  scopes only. The double does not re-run the policy at the claim (`POLICY_STATE_CHANGED`) beyond an
  assumption breach's hold, does not
  move an expired claim lease to an unresolved one, and holds no scope for a grant that binds no
  material signal, where the hosted claim store holds the execution target (system, environment,
  operation, resource, endpoint): two open claims on one resource with no material signal are
  refused hosted and not here. Without the `allowanceDraws` option it reserves nothing: two grants
  on the last unit of an allowance are then refused only through the signal, so when the allowance
  is published after the commit rather than with it, a claim inside that window reads the old value
  and both commit, here and hosted. A [held allowance](#held-allowances) closes that window.
- Assumption breaches are modelled from finalizations only. The hosted authority also opens them from a
  reconciliation that names another effect, from a claim left `INDETERMINATE` past its deadline, and,
  when switched on, from an action's monitoring rates. Hosted, the hold is a policy rule (the starter
  policy's); the double applies that rule's effect itself, so a person's approval passes a held scope
  here as it would under a policy whose approval rule sits above the hold.
- The effect-evidence path is modelled only as far as claim-lease-free state allows. The double does
  not model `authority_protocol_version: "1.1"` or `eligibility_validated_at`, and it models none of
  the observation causality window: the hosted authority refuses any non-null `observed_at` that
  precedes the claim (`EFFECT_OBSERVATION_PRECEDES_CLAIM`), precedes the authority's own eligibility
  confirmation (`EFFECT_OBSERVATION_PRECEDES_AUTHORITY_CONFIRMATION`), or follows the start of the
  finalization (`EFFECT_OBSERVATION_AFTER_FINALIZATION`), each against its own database clock. An
  `observed_at` taken from a downstream system's response can hit the first two, so a timestamp the
  double accepts can still be refused in production — and then the evidence-free retry records the
  commit without the observation. The earlier finalize-body divergence `effect_status` was in no
  contract and has been removed.

## Trusted effect observers

`new LocalAuthority({ trustedEffectObserverIds: ["synthetic-observer"] })` mirrors the hosted
`DECIONIS_TRUSTED_EFFECT_OBSERVER_API_KEY_IDS` allowlist. It is **empty by default**, exactly as the
hosted authority is, so `CONFIRMED` effect evidence is refused with
`EFFECT_OBSERVER_PROVENANCE_UNAVAILABLE` unless a test opts in. As in the hosted route, the allowlist
is intersected with the caller's own authenticated identity: the double has exactly one credential, so
opting in means listing its `apiKey` (`LOCAL_AUTHORITY_API_KEY` by default) and naming that same value
as `observer.id`. Any other observer id is refused with `EFFECT_OBSERVER_PROVENANCE_MISMATCH`, which is
what the hosted route does with an observation that does not name the key that presented it. An absent allowlist does not fail
closed to `UNCONFIRMED`: it refuses the whole finalization, which is why `DecionisGrantVerifier`
retries once without the observation. Local tests should exercise both the allowlisted path and the
default refusal.

## Held allowances

`new LocalAuthority({ allowanceDraws })` models the counters hosted Decionis holds itself
(`/v1/authority/allowances`). `allowanceDraws(request)` stands for the approving rule's
`then.allowance`: the allowance key and the amount, or a null amount when the parameters give none.
`setAllowance(key, limit)` stands for the policy writer's `PUT`, which no decision key can make, and
raising a limit is a top-up. `allowanceUsage(key)` reports what an allowance has reserved, held,
consumed and left.

What the double does is what hosted does:

- An ALLOW is granted only once every draw fits what its allowance has left.
- A draw that does not fit gets no grant. The decision is `BLOCK`, never `ESCALATE`, with
  `ALLOWANCE_EXHAUSTED`, `ALLOWANCE_UNDEFINED` or `ALLOWANCE_AMOUNT_INVALID` after the policy's own
  reason code.
- A managed escalation whose reauthorization cannot draw ends `BLOCKED` with `REAUTHORIZATION_BLOCKED`.
- A draw counts from the grant to the outcome. An unclaimed grant holds it until the grant expires,
  a commit keeps it, a failure releases it, and an `INDETERMINATE` holds it until reconciled.
- It is never a concurrency scope.

What it leaves out: an allowance here has no window, and every tenant the double serves shares it,
where hosted allowances are per organisation. It does not model the hosted claim's own check that
the grant's reservation is live, because here a reservation cannot expire before its grant.
`packages/pipeline/test/testing/LocalAllowances.test.ts` runs the race for a shared limit against
it: two rollouts, each fitting the last unit, are proposed before either commits. One commits, the
other is refused, and the other completes after a top-up. The twelfth case of
[the Changed Conditions Test](./changed-conditions-test.md#a-shared-limit-and-its-window) uses it to
close the window between a commit and a late publication of the limit.

The [wire-contract harness](../tests/integration/contract/README.md) runs these doubles against the
packed npm tarball in CI, and the [local escalation example](../examples/local-escalation) shows both
modes end to end.
