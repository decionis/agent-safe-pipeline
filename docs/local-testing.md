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

| Property             | Behavior                                                                                                                                                                                                                      |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Structural binding   | `action_context.intent_hash` is sealed as the binding when present; the `Intent hash` display field is the fallback; a conflict between them is rejected with `intent_binding_mismatch`                                       |
| Receipt verification | Terminal `ALLOWED` with result `ALLOW`, the receipt the request produced, action type and target, the intent hash, an approver with a role, an optional required role, and expiry; failures carry Decionis-style reason codes |
| Request contract     | Strict `ExecutionAuthorityRequest` schema, `Idempotency-Key` equal to `intent_id`, an independent canonicalizer that recomputes the hash, the five-minute intent lifetime                                                     |
| Grants               | Single-use claims, replay refused with `NONCE_REPLAY_DETECTED`, direct grants re-verify evidence at claim, managed grants carry no client evidence                                                                            |
| Finalization         | `finalize-token` records `COMMITTED`, `FAILED`, or `INDETERMINATE` once per claim; the record is on `authority.grants`                                                                                                        |
| Expected effect      | `expected_effect_digest` is accepted on the binding, re-hashed by the independent canonicalizer, stored on the grant, echoed in the claim's grant claims, and re-checked at claim time                                        |
| Effect evidence      | `effect_evidence` on finalize is validated against the Protocol 1.1 schema and refused in the hosted order before the commit transition, a malformed record answered with 409 `EFFECT_EVIDENCE_INVALID` rather than a 400     |
| Finalize 200 body    | Key for key the hosted success body: `finalized`, `outcome`, `evidence_durably_queued`, `decision_chain_evidence_recorded`, `evidence_recorded`, `effect_evidence_recorded`, `effect_confirmation`, `COMMIT_EVIDENCE_PENDING` |
| Fixture ledger       | `FixtureAuthorizationVerifier.finalize` records the outcome in an inspectable ledger, so `RECORDED` from the fixture means the entry exists in `ledger()`                                                                     |
| Fault injection      | `scriptOnce(route, override)` delays, truncates, replaces, or destroys the next response on a route; `scriptNextManagedLifecycle` scripts client-visible states                                                               |

## What they do not reproduce

- No FIDO2 ceremony, liveness check, or device binding runs. Completion is a method call or the
  control route, and the receipt's authenticator evidence is whatever the double was configured with.
- Receipts and dossiers are not signed; `GET /v1/dossiers/:id/verify` answers valid for any receipt
  the double sealed and invalid otherwise.
- The Presence Authority envelope protocol between Decionis and Presence is not simulated. The
  local authority orchestrates the local Presence in process; what is faithful is the client-visible
  contract on both sides.
- Nothing is delivered. The invitation link uses a reserved `.invalid` host.
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

The [wire-contract harness](../tests/integration/contract/README.md) runs these doubles against the
packed npm tarball in CI, and the [local escalation example](../examples/local-escalation) shows both
modes end to end.
