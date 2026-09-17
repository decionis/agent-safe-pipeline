# ADR 0001: an HTTP-interception ingress over the existing lifecycle

Status: accepted, 2026-09-17.

## Problem

AgentSafe is to be installed in front of an agent, an API or a service and to govern the
consequential HTTP actions that pass through it. The runtime in `packages/agentsafe` accepts a
proposal envelope from an authenticated principal at `POST /v1/actions` and forwards the verified
parameters to one configured URL. Nothing in the repository accepts a plain HTTP request, decides
whether it is consequential, and forwards it unchanged once it is authorized.

## Existing implementation

`TrustedExecutorService.propose` (`packages/agentsafe/src/service/TrustedExecutorService.ts`)
captures an intent from the envelope, asks the authority through `EscalationResolver` and
`DecionisGate`, and runs `SafeExecutor` over a sealed `ActionRegistry` whose reference handler,
`forward_request`, posts the parameters to `DOWNSTREAM_URL`. Its configuration
(`ExecutorConfigLoader`) is environment-only and production-strict: a tenant, an actor, a
downstream system, a credential kind, a TLS certificate or an explicit plaintext flag, and a
journal directory in enforcement. Its callers are principals with roles.

## Options considered

1. **Keep the envelope; teach clients to send it.** Every agent framework and every service would
   need an adapter. That is a library, not a gateway.
2. **Extend `TrustedExecutorService` and `ExecutorConfigLoader` to accept raw HTTP and a file.**
   The executor's contract is the bank security boundary: a principal per caller, a credential
   kind per downstream, a posture the host must hold. Relaxing any of it for a laptop path
   weakens what the deployment kit and its conformance tests assert; keeping all of it makes the
   five-minute path impossible.
3. **A second ingress, `gateway`, over the same lifecycle objects.** A listener that turns an
   intercepted request into a captured intent and then uses `DecionisGate`, `SafeExecutor`,
   `DecionisGrantVerifier`, `ShadowPipeline`, `EscalationResolver` and `AuditRecorder` exactly as
   the executor does, with its own configuration and its own forwarding handler.

## Decision

Option 3. The runtime gains one more command, `agentsafe proxy` (alias `gateway`; `run` is the
same command reading its configuration file), implemented under `packages/agentsafe/src/gateway/`
with its listener under `src/http/GatewayHttpServer.ts`. `agentsafe serve`, the envelope ingress,
is unchanged.

What the ingress does, in order:

1. **Match.** A route table maps method and path pattern to an action name. A request whose
   method is safe (`GET`, `HEAD`, `OPTIONS`) is not consequential and is proxied unchanged. An
   unsafe request that matches no route is governed under the derived action `http.<method>`
   unless the configuration says `interception.unmatched: passthrough`; the default is the
   fail-safe one.
2. **Normalize.** The intent's `action` is the route's; its `target` is `<METHOD> <path>`; its
   `parameters` are `method`, `path`, `query` and, for a JSON body within the embedding limit,
   `body`; its `context` carries `body_sha256` over the raw bytes, the byte count, the content
   type and whether the body was embedded. The idempotency key is the client's `Idempotency-Key`
   when it sent one and the intent id otherwise. Request headers are not part of the intent:
   an `Authorization` or `Cookie` header is the client's credential to the upstream and never
   travels to the authority or into evidence.
3. **Decide.** `IntentCapture`, then `EscalationResolver.evaluate` through `DecionisGate`. A
   fail-closed decision is reported as its own state (`AUTHORITY_UNAVAILABLE`, HTTP 503 with
   `Retry-After`), never as a policy `BLOCK` (HTTP 403).
4. **Execute exactly once.** On `ALLOW`, `SafeExecutor.run` claims the grant and calls the
   `http.forward` handler. The handler rebuilds the upstream request from the **verified**
   parameters only, and before dispatch recomputes the digest of the raw bytes it is about to
   send and compares it to `context.body_sha256`. The bytes forwarded are the bytes whose digest
   the authority bound; a mismatch fails before dispatch. The upstream's status decides the
   finalization: `2xx`/`3xx` is `COMMITTED`, `4xx` is `FAILED` (the provider refused,
   definitively), `5xx` and a transport failure are `INDETERMINATE`.
5. **Hold.** On `ESCALATE` nothing is forwarded (HTTP 202, `Execution HELD`). The captured intent
   and the raw request are held in memory until the intent expires; a resume through
   `/_agentsafe/v1/escalations/{intent_id}` goes back to the authority for a fresh decision, and
   only a fresh `ALLOW` with a grant executes, once.
6. **Shadow.** In `shadow` mode the request is forwarded unchanged inside
   `ShadowPipeline.observe` while the authority is asked what it would have decided; the
   observation is reported as `SHADOW` with `Actual execution PASSTHROUGH` and is never a grant.

The demo authority is `LocalAuthority` from `@decionis/agent-safe-pipeline/testing`, started on
loopback in the same process and reached through the unchanged `DecionisGate`. It is refused
under `NODE_ENV=production` and is named `local/demo` on every line it produces.

## Reason

The lifecycle is the protocol; the ingress is not. Two ingresses over one lifecycle keep one
authority client, one claim, one finalization, one evidence chain. The alternative would have put
the laptop path's ergonomics into the bank boundary's contract, or the bank boundary's contract
into every laptop.

## Protocol impact

None. `agent-safe.intent/1`, the `ExecutionAuthorityRequest`, `claim-token` and
`finalize-token` are used as they are. The intent's `parameters` shape for an HTTP action
(`method`, `path`, `query`, `body`) is new vocabulary inside the existing contract, not a change
to it.

## Compatibility impact

None to existing commands, configuration, environment variables, routes or the image. The new
command reads a new configuration surface (`agentsafe.yaml`, `AGENTSAFE_*`) and the existing
`DECIONIS_*` variables with their existing meanings.

## Security impact

- The forwarded payload is bound by digest to the authorized intent and re-checked before
  dispatch.
- The authority and Presence are reached through `GuardedFetch` under a sealed `EgressPolicy`:
  HTTPS or explicit loopback, no redirects, bounded bodies.
- The upstream is a proxied origin, fixed by configuration and never by the caller. A plain-HTTP
  upstream is refused unless it is loopback or `upstream.insecure: true` is set; inside a cluster
  that is an explicit statement that the network, not TLS, protects the hop.
- Fail-open exists only as an explicit `failurePolicy: failOpen` and is recorded on the evidence
  chain as `EXECUTION_UNGOVERNED` with the reason the authority was unavailable.
- Held escalations are bounded in number and expire with the intent.

## Migration impact

None. An adopter of the envelope ingress keeps it; an adopter of the deployment kit keeps it.
