# ADR 0009: an acceptance run touches only what the operator's plan names

Status: accepted, 2026-10-31. Amends [ADR 0002](./0002-boundary-test-on-a-synthetic-target.md)
for one new command, `agentsafe accept`; `agentsafe test` is unchanged. It builds on three
decisions the user took on 2026-10-31. D-1 replaces the earlier D6: a run touches only targets
the operator names, in a plan the operator writes. D-2: a dedicated key signs the report. D-3:
drift and a stale report are reported, never enforced. The user accepted the choices this ADR makes
beyond those three, as written, on the same day. Each rejected alternative is recorded under
"Options considered".

## Problem

Every proof in this repository runs against loopback doubles. A buyer accepting a deployment asks
four questions of the boundary that was actually installed:

- Which consequential paths does it govern?
- What evidence shows that?
- Under what conditions does that evidence hold?
- Where does the claim stop?

The questions come from a reader's comment on _The Commit Boundary_, Edition 30 (30 October 2026).
The [evaluation path](../../../EVALUATION-PATH.md#four-questions-and-where-each-answer-stops)
answers them for one decision and for this repository. For one deployment, the answer is the
manual checklist in [gateway strategies](../../deployment/gateway-strategies.md#verify-the-boundary-before-promotion):
it is run by hand, and it is unsigned.

ADR 0002 forbids the one thing that would answer them: sending a request at a real target. Two
facts can be shown in no other way:

- that a refused write left its target unchanged, read at the target;
- that the agent's zone cannot reach the system of record by another route, from the agent's own
  network position.

Any fix has two constraints. The run must not become the incident it tests for. And it must not
let the side under test vouch for itself.

## Existing implementation

- `agentsafe test` (ADR 0002): the real gateway against a synthetic target. Its only contact with
  anything real is a TCP dial.
- `containment/ContainmentProbe.ts` (`agentsafe probe-containment`): a TCP dial. `REACHABLE` proves
  a hole. `CONTAINED` never proves containment.
- The gateway's reads of the target (#400). For a write whose API profile operation names a read,
  the gateway reads at three moments:
  - before the authority is asked, binding the precondition;
  - after an `ALLOW` the upstream answered `2xx`, recording `EFFECT_OBSERVED` as `CONFIRMED`,
    `UNKNOWN` or `PENDING`;
  - `interception.refusalWindowMs` after a refusal, recording `REFUSAL_OBSERVATION`. This is on by
    default.
- The deployment fingerprint (#401): `agent-safe.deployment-fingerprint/1` in `/_agentsafe/status`.
  It covers the route table, with each route's mode and failure policy, and the declared
  containment targets.
- `edge/UsageReport.ts`: the only report the runtime signs today. It uses an Ed25519 PKCS#8 key,
  takes its RFC 7638 thumbprint as `kid`, and signs as a compact JWS. The evidence chains are
  hash-chained but unkeyed ([executor evidence](../../executor-evidence.md)).
- A shadow route forwards: the gateway decides, then sends the request on (`PASSTHROUGH`). "Shadow
  first" through the deployed gateway would therefore perform the write.
- The gateway has no operator role. Its callers are agents. Under `/_agentsafe` it serves health,
  readiness, status, subject sessions and escalation resume, plus metrics, which can sit behind a
  bearer of their own (`AGENTSAFE_METRICS_TOKEN`).

## Options considered

**Who signs.**

1. **Keep ADR 0002: synthetic targets only.** This leaves deployment scope (G1) and route probes
   (G4) open. D-1 rejects it.
2. **A tool in the agent's zone runs the cases and signs with a key it holds.** Rejected. The zone
   is the side under test, and a key there signs whatever a compromised caller reports. The
   signature would add nothing to the zone's own word.
3. **The tool runs the cases from the agent's zone; the gateway signs.** The gateway holds the
   acceptance key. It signs what it observed itself: its decisions, what it forwarded, and what it
   read at the target. What only the zone can see (direct routes, credentials in its environment)
   goes in the same report, marked as reported by the zone. **Chosen.**

**How a prohibited write is "decided in shadow first" (D-1).**

1. **Give the tool the authority credential, for a shadow call.** Rejected. An authority key in the
   agent's zone can obtain enforcement grants, which is the hole the run looks for.
2. **Send it through a shadow route.** Rejected, because a shadow route forwards.
3. **The gateway decides the request in shadow on an operator endpoint, and neither reads nor
   forwards.** **Chosen.**

**How "authority unreachable" is shown.**

1. **Make the real authority unreachable.** Rejected: that is a production outage.
2. **The tool builds a gateway from the deployment's configuration in its own process.** Rejected.
   It needs the deployment's secrets in the agent's zone, and it tests the tool's runtime rather
   than the deployed one.
3. **The deployed process builds a second gateway from the configuration it already loaded.** It
   has no listener, and its authority transport and upstream are in-process doubles that fail and
   record. **Chosen.**

**The cases on a grant after issuance.** These are an amount changed after authorization, a
consumed grant presented again, and a grant carried to another boundary.

1. **Run them from the zone.** Not possible: the zone never holds a grant, so it has none to alter
   or replay.
2. **Run them inside the gateway, against the real authority.** Rejected. The gateway would have to
   obtain real grants for writes it never sends, and alter them, through a new path in production
   code that exists only to misbehave.
3. **State them as established by the build.** The report says that the zone's credential scan is
   what checks the zone holds no grant. **Chosen.**

## Decision

The gateway signs (option 3), decides prohibited writes in shadow (option 3), builds the second
gateway in the deployed process (option 3), and states the grant cases as established by the build
(option 3).

### The plan: `agent-safe.acceptance-plan/1`

The operator writes the plan as a YAML file. The tool sends nothing the plan does not name.

| Field        | Meaning                                                                           |
| ------------ | --------------------------------------------------------------------------------- |
| `gateway`    | The deployed gateway's URL                                                        |
| `expires_at` | Required: the date the report stops being current (see below)                     |
| `permitted`  | Writes to perform through the gateway: method, path, body                         |
| `prohibited` | Writes the operator expects the policy to refuse, each naming its canary resource |
| `origins`    | For each upstream origin, a read with no side effect                              |
| `providers`  | Verifying providers, each with one write at a canary resource                     |
| `mcp`        | MCP server URLs                                                                   |
| `metadata`   | Whether to probe the cloud metadata endpoint. Off unless the plan names it        |

`expires_at` is required because the fingerprint does not capture network policy, cloud IAM or
the upstream's own configuration. A report must stop being current on a date, even when nothing in
the fingerprint moved. A canary is the operator's statement, and the report records it as such.

The gateway checks the plan against its own route table when the run opens. It refuses the run if
any of these holds:

- a prohibited write maps to a route that is not in enforcement;
- a prohibited write's profile operation names no read;
- a write maps to no route.

### The cases

Each case says who observed it: the gateway, whose word the signature carries, or the zone, whose
word it stays.

- **Permitted write** (gateway). Sent once through the gateway. Reported: the decision,
  `FORWARDED`, and the effect read back (`CONFIRMED`, `UNKNOWN`, or `PENDING` with the reason).
- **Prohibited write** (gateway).
  - It is decided first, in shadow, on the operator endpoint.
  - It is sent through the gateway only when that decision was `BLOCK` or `ESCALATE`.
  - Reported: the refusal (`NOT_FORWARDED` or `HELD`), and the `REFUSAL_OBSERVATION` (`UNCHANGED`,
    `CHANGED` or `UNREADABLE`).
  - A shadow `ALLOW` is never sent, and the case fails: the policy permits what the plan calls
    prohibited.
- **Authority unreachable** (gateway). Each plan write on a fail-closed route goes through the
  second gateway. It passes with `503` `NOT_FORWARDED` and nothing reaching that gateway's
  recording upstream. A fail-open route is not run; it is reported as not governed while the
  authority is down.
- **Other routes** (zone).
  - Each origin's read is sent directly, with no credential and the proxy bypassed. The same read
    goes through the gateway as the control. The result is `CONTAINED` only when the direct read
    fails at the transport and the control succeeds. Any direct HTTP answer is `REACHABLE`.
    Anything else is `INCONCLUSIVE`.
  - Each provider's write is sent twice: unattested, then signed with a fresh key the provider
    cannot know. Each must be refused with a `4xx` and a reason code.
  - Reachable MCP servers are listed.
  - Credentials in the environment and at well-known file paths are reported by name and kind,
    never by value.
  - The metadata endpoint is probed with a `GET` only, and only when the plan names it.
- **Stated, not run** (nobody). Each is listed with its reason:
  - **Grants after issuance:** the zone never holds a grant, and the zone's credential scan is what
    checks it holds none. The authority's and provider's refusals are established by the build: the
    Changed Conditions Test, the Compromised Principal Test, and the provider conformance vectors.
  - **Lost outcome and restart:** the build's trusted-executor proof.
  - **Downstream consequences, executor host integrity, node and kernel isolation:** no record
    establishes them. They are the fixed list in the Decionis verifier's `assurance_scope`.

The verdict is `ACCEPTED` only when every case that ran passed. Otherwise it is `NOT_ACCEPTED`,
with the failing cases named. `INCONCLUSIVE` is not a pass, because the control probe that would
explain it also failed.

### The gateway's side

A new configuration section, `acceptance`, is off unless both of its keys are set:

- `acceptance.key: { file }`: an Ed25519 PKCS#8 key used for nothing but acceptance reports.
  `agentsafe identity` prints its `kid` (the RFC 7638 thumbprint unless one is configured) and its
  public JWK.
- `acceptance.operatorToken: { file }`: the bearer the tool presents on the acceptance endpoints.
  It is compared by digest. It is not an agent's credential and grants nothing on any other route.

When the section is absent, the endpoints under `/_agentsafe/v1/acceptance` answer `404`. When it
is present:

- `POST /runs` opens a run. It answers with the run id, the fingerprint, and the coverage: the
  governed paths, and the ungoverned ones by kind (reads, shadow routes, fail-open routes, writes
  whose profile names no read). Only one run is open at a time, and a run closes itself after 15
  minutes.
- `POST /runs/{id}/decisions` decides one request in shadow, captured exactly as its route
  captures it, with no read and no forward. The decision is recorded on the gateway's chain.
- Requests the tool sends through the ordinary listener carry `agentsafe-acceptance-run: <id>`.
  The gateway keeps their chain lines for the run, at most 64 per run. It removes the header
  before the authority or the upstream sees anything, and the header changes no decision.
- `POST /runs/{id}/outage` runs the authority-unreachable case.
- `POST /runs/{id}/close` takes the zone's findings and waits for any refusal observation still
  due. It then assembles and signs the report, records `ACCEPTANCE_SIGNED` with the report's digest
  on the chain, and returns the report.

### The report: `agent-safe.acceptance/1`

The report is a compact JWS: `alg` `EdDSA`, `typ` `agent-safe-acceptance+jwt`, and `kid`. It
holds:

- the fingerprint document and its digest, which is the report's validity condition, and the
  plan's `expires_at`;
- the coverage: the governed paths, and the ungoverned ones by kind;
- each case with its decision id, dossier id, chain line hashes, the target versions observed, and
  `observed_by` (`GATEWAY` or `ZONE`);
- the fixed list of what is never established;
- the statement that it does not carry over to other adapters, routes or environments.

### Verification

- `agentsafe verify acceptance <report> --key <jwk>` checks the signature and the schema offline.
- With `--current --gateway <url>`, it also compares the report's fingerprint digest with the one
  the running gateway serves. The answer is `CURRENT`, `STALE` with the fingerprint fields that
  differ, or `EXPIRED`.
- `agentsafe status --acceptance <report>` shows the same answer.
- None of these answers changes what the gateway does (D-3).
- Exit codes: `0` when the report is current and accepted; `1` when it is stale, expired or not
  accepted; `2` when it could not be checked.

The plan and the report belong to the buyer, who reruns them in CI or as a `helm test` hook on any
change.

### Proof in this repository

`examples/acceptance-demo` runs `accept` against the loopback stack, and `examples:prove` runs the
demo. That proves the tool. A customer's run proves that customer's deployment, and nothing else.

## Reason

- **The gateway, not the zone, attests what it did.** The gateway is the trusted side, and it is
  the side that already holds the reads of Phase B. Putting the key there means a signature
  carries the boundary's word, not the agent's.
- **The zone's findings stay the zone's word.** They are what the containment probe already says
  they are: `REACHABLE` is proof of a hole, and nothing else is proof of containment. Marking
  `observed_by` keeps the two kinds of finding apart in the one document a buyer reads.
- **Every write that reaches a real target is one the operator named.** A prohibited write gets
  there only after the authority refused it in shadow, only on an enforcement route, and only at a
  canary. The worst case of a wrong policy is a change to a canary the operator chose, and the
  report says it happened.

## Protocol impact

None on intents, decisions, grants, claims or finalizations. The shadow decision is an ordinary
shadow decision, and the tagged requests are ordinary requests. There are two new envelopes, the
plan and the report, and new operator endpoints on the gateway.

## Compatibility impact

- Nothing changes unless `acceptance` is configured.
- `agentsafe test` and ADR 0002 stand as they are.
- Configuring the section changes the fingerprint's configuration digest, as any setting does. Its
  secrets are redacted, like every other secret-derived value.

## Security impact

- **What a run sends.** It sends only what the plan names. The operator owns the plan, every
  target in it, and every canary statement.
- **New surface on the gateway.** The acceptance endpoints are new, and they are off by default.
  When on, they require a dedicated bearer, keep at most one run open, close it after 15 minutes,
  and keep at most 64 tagged requests per run.
- **The shadow endpoint is a policy oracle.** Whoever holds the operator token can learn the
  policy's answer without performing the write. That is why the token is never an agent's, why
  every decision made on the endpoint is on the chain, and why the token lives in the agent's zone
  only for the run.
- **The token during the run.** The zone's own credential scan reports the operator token by name,
  like any other credential. It grants runs and shadow decisions, nothing more, and the operator
  removes it afterwards.
- **The run tag cannot change a decision.** The header is stripped before the authority or the
  upstream sees the request.
- **The second gateway.** It has no listener. Its upstream and authority are in-process doubles,
  and it is built from the configuration object already loaded, without reading the file again.
- **What the report holds.** Credentials appear by name and kind, never by value. The report holds
  no header value and no body except what the plan wrote.
- **The acceptance key** signs nothing but acceptance reports.

## Migration impact

None.
