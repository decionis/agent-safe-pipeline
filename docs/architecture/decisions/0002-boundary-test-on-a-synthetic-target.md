# ADR 0002: the boundary test runs on a synthetic target, never on a real one

Status: accepted, 2026-09-18.

## Problem

The adoption path is discover, install, see what the gateway changes, run in shadow, enforce,
deploy. After `install`, nothing in the runtime showed a newcomer what the boundary does before
they put it in front of something of their own: the quickstart asks for an upstream and a request,
and the golden adversarial demo needs a clone and the examples. A command was wanted that
demonstrates, on the machine the runtime was just installed on, what can reach a target with no
boundary in the way and what enforcement prevents, and that says so in a form a person can read
and a pipeline can assert.

## Existing implementation

- `Gateway` and `GatewayHttpServer` (`src/gateway/`, `src/http/`): the interception lifecycle
  and its listener, the objects `agentsafe proxy` runs.
- `DemoAuthority.ts`: the synthetic policy on loopback, through the unchanged `DecionisGate`,
  refused under `NODE_ENV=production` by the pipeline's testing double itself.
- `verify/VerifyAuditChain.ts`: offline verification of the chained evidence lines.
- `containment/ContainmentProbe.ts` and `agentsafe probe-containment`: a TCP dial that reports
  whether a system of record answers the agent zone without the executor.
- `packaging/smoke/Smoke.sh`: the release smoke, which already governs one request per verdict.

## Options considered

1. **Fire adversarial requests at the operator's configured upstream.** Rejected. The requests
   that demonstrate a boundary are unsafe methods with consequential bodies; sending them at a
   real system is not a test, it is the incident the runtime exists to prevent. Under a real
   policy some would be allowed and forwarded, and a "dry-run" convention cannot be assumed of
   an arbitrary upstream.
2. **Simulate the lifecycle in-process with doubles of the gateway.** Rejected. A demonstration
   of a mock proves nothing about the runtime that was installed.
3. **Run the real gateway, in this process, against a synthetic target this process owns.** The
   target is a loopback service that records what reaches it; the authority is the local demo
   policy; the requests are fixed; every real thing (a configured upstream, a stored key, the
   environment) is left unread. Chosen.

## Decision

Option 3. `agentsafe test` (`src/cli/TestCommand.ts` over `src/gateway/BoundaryTest.ts`, with
the target in `src/http/RecordingTarget.ts`) sends a fixed set of eight requests three ways at
the recording target: directly, through a gateway in shadow, and through a gateway in
enforcement, each gateway a real `Gateway` behind a real `GatewayHttpServer` on a loopback port
of its own. An outage is demonstrated with gateways whose authority transport fails, under the
default fail-closed policy and, for contrast, under the explicit fail-open one. The report,
`agent-safe.boundary-test/1`, carries per case what reached the target each way, how many times,
with which state, verdict, execution and dossier; the exposure (how many adversarial cases
reached the target each way); whether routine work still went through exactly once; and whether
the evidence chains the enforcing gateways left verify. The verdict is `BOUNDARY_HOLDS` only when
nothing adversarial reached the target under enforcement, routine work did, once each, and the
evidence verifies; anything else is `BOUNDARY_BROKEN`, a defect in the runtime.

The configuration of each gateway under test is built by `GatewayConfigLoader.load` from flags
alone with an empty environment and no file, so the loader's precedence applies and nothing of
the operator's is read. The demo authority is started once for the run and stopped at the end.

A target named on the command line (`name=host:port`) is dialed with the existing containment
probe and reported beside the synthetic run. That is the only contact the command has with
anything real, and it is a TCP dial with no request on it.

The command exits `0` when the boundary holds and no named target answered, `1` when something
adversarial got through or a target answered, and `2` when it did not run: wrong arguments, or a
process marked production, where the synthetic authority refuses to start. It is not bypassed
there; the refusal is explained, and the image's documentation says to unset `NODE_ENV` for the
one run.

The release smoke test runs `agentsafe test --json` on every packaged binary and requires
`BOUNDARY_HOLDS`; the image job requires the refusal as shipped and the holding verdict with
`NODE_ENV` unset.

## Reason

The test demonstrates the runtime that was installed, not a description of it, and it can do so
on any machine in under a second with nothing configured, because it owns both ends of every
request it sends. The containment probe is reused rather than duplicated because "does the target
answer without the gateway" is the same question in both places.

## Protocol impact

None. The intents, decisions, grants, claims and finalizations in the run are the ordinary ones
between the gateway and the demo authority; the report is a new envelope beside them, not a
change to any.

## Compatibility impact

One new command and one new report envelope. Every existing command, flag, route and output is
unchanged. `agentsafe test` is a gateway command in `GATEWAY_COMMANDS`; the usage lists it.

## Security impact

- Nothing the operator configured is read: no upstream, no key, no stored login, no environment
  beyond what the command's own flags say. A real system cannot be the target of a probe.
- The recording target listens on loopback only, keeps header names but never a value, bounds the
  body it reads, and lives for the run.
- The synthetic authority's production refusal is honoured, not worked around.
- The forged-approval case shows a caller's `x-agent-safe-*` headers reaching a target directly
  and never through the gateway, which strips them; the case does not add a new stripping rule,
  it exercises the existing one.

## Migration impact

None.
