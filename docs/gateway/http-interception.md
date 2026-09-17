# HTTP interception

`agentsafe proxy` is a reverse proxy with an authority boundary in it. The request that reaches the
upstream is the request that was authorized, byte for byte, or nothing reaches it at all. This page
says what the gateway looks at, what it binds, and what it forwards. The decision itself is the
authority's; the gateway asks, enforces and records ([ADR 0001](../architecture/decisions/0001-http-interception-ingress.md)).

## What is consequential

A request is consequential when its method is `POST`, `PUT`, `PATCH` or `DELETE`. `GET`, `HEAD`
and `OPTIONS` are never evaluated; they pass through with their query and headers, and are counted.

A consequential request is named by the [route table](./routes.md). One that no route names is
governed under a derived name, `http.post`, `http.put`, `http.patch` or `http.delete`, unless the
configuration says `interception.unmatched: passthrough`. Governing by default is the fail-safe
choice: narrowing what the boundary covers is something an operator writes down.

Paths under `/_agentsafe/` belong to the gateway ([CLI reference](../reference/cli.md#the-gateways-own-routes))
and are never forwarded.

## What the authority sees

The gateway reads the body in full, under `interception.maxBodyBytes` (1 MiB by default), and
captures an intent in the `agent-safe.intent/1` contract:

| Field                                   | Value                                                                                                         |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `action`                                | the route's action, or the derived name                                                                       |
| `target`                                | `<METHOD> <path>`                                                                                             |
| `parameters.method`, `parameters.path`  | as received                                                                                                   |
| `parameters.query`                      | the query as an object, keys sorted, a list where a key repeats                                               |
| `parameters.body`                       | the body, when it is JSON within `interception.maxEmbeddedBodyBytes` (64 KiB); absent otherwise               |
| `context.body_sha256`, `body_bytes`     | SHA-256 and length of the raw bytes, embedded or not                                                          |
| `context.content_type`                  | the request's                                                                                                 |
| `context.body_embedded`                 | whether policy can see the fields                                                                             |
| `context.claimed_principal`             | the value of `interception.principalHeader`, when configured; a claim the gateway carries and does not verify |
| `correlationId`                         | `X-Correlation-Id`, else `X-Request-Id`                                                                       |
| `idempotencyKey`                        | the client's `Idempotency-Key`, else a fresh one                                                              |
| `actor`, `tenantId`, `downstreamTarget` | from the configuration: the gateway's actor, the tenant, the upstream as system, the action as operation      |

Request headers are not part of the intent. An `Authorization` or `Cookie` header is the client's
credential to the upstream and never reaches the authority or the evidence chain.

The intent is canonicalized (RFC 8785) and hashed by `CanonicalIntentHasher`, and sent to the
authority as the `ExecutionAuthorityRequest` the [execution intent](../execution-intent.md) page
describes, with `Idempotency-Key: <intent id>`. A body too large or too deep to bind is refused
with `413` before anyone is asked.

## What is forwarded

On `ALLOW`, `SafeExecutor` claims the single-use grant and calls the forwarding handler with the
parameters the authority evaluated. Before the point of no return the handler recomputes the
digest of the bytes it holds and compares it, with the method and the path, to what the intent
bound; a mismatch fails before dispatch and nothing is sent. Then, exactly once:

- the method and path from the verified parameters, the query as received;
- the client's headers minus the hop-by-hop ones (`Connection` and what it names, `Keep-Alive`,
  `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, `Proxy-*`), minus `Host`, `Content-Length` and
  `Expect`, which the hop recomputes;
- `X-Forwarded-For` appended with the caller's address, `X-Forwarded-Proto`, `X-Forwarded-Host`;
- `Accept-Encoding: identity`, so the bytes relayed back are the bytes received;
- `x-agent-safe-intent-hash`, `x-agent-safe-decision-id`, `x-agent-safe-dossier-id`;
- the raw body bytes.

Redirects from the upstream are relayed, never followed. The response is read in full, under 16
MiB, and relayed with its status and headers, `Set-Cookie` included, plus `agentsafe-decision`,
`agentsafe-dossier-id`, `agentsafe-intent-hash` and `agentsafe-execution`.

## What each outcome means

| Upstream answered | Finalized with the authority | Execution header | Relayed                 |
| ----------------- | ---------------------------- | ---------------- | ----------------------- |
| `2xx`, `3xx`      | `COMMITTED`                  | `FORWARDED`      | the upstream's response |
| `4xx`             | `FAILED`                     | `FAILED`         | the upstream's response |
| `5xx`             | `INDETERMINATE`              | `INDETERMINATE`  | the upstream's response |
| nothing           | `INDETERMINATE`              | `INDETERMINATE`  | `502` from the gateway  |

A `4xx` is the provider's own refusal: the request reached it and nothing was effected. A `5xx`
or a lost connection is unknown, and is recorded as such rather than guessed either way. See
[execution outcomes](../execution-outcomes.md) for the vocabulary the executor uses for the same
distinctions.

## Responses the gateway makes itself

When nothing is forwarded, the caller gets JSON with `version: agent-safe.gateway/1`, the `state`,
the `verdict`, the `reason_codes`, the `execution`, and the intent, decision and dossier
identifiers, with the same `agentsafe-state` and `agentsafe-execution` headers:

| State                     | Status  | Execution       | When                                                         |
| ------------------------- | ------- | --------------- | ------------------------------------------------------------ |
| `BLOCK`                   | 403     | `NOT_FORWARDED` | the authority refused                                        |
| `ESCALATE`                | 202     | `HELD`          | a person must decide; `resume` names where to ask again      |
| `AUTHORITY_UNAVAILABLE`   | 503     | `NOT_FORWARDED` | the authority could not be asked; `Retry-After` is set       |
| `EXECUTION_FAILED`        | 502     | `NOT_FORWARDED` | the grant was claimed but the handler stopped before sending |
| `EXECUTION_INDETERMINATE` | 502     | `INDETERMINATE` | the request was sent and no answer came back                 |
| `ERROR`                   | 400–503 | `NOT_FORWARDED` | the intent could not be bound, or the grant not claimed      |

An `ESCALATE` is held in memory until the intent expires (`intentTtlSeconds`, 120 by default,
at most 300) or 1,000 holds are pending, whichever comes first. With Presence configured,
`POST /_agentsafe/v1/escalations/{intent_id}/resume` asks the authority again; only a fresh `ALLOW`
with a grant executes, once. Without Presence the hold is the answer and resume says so (`409`).

## Shadow

In `shadow` mode a consequential request is forwarded unchanged inside `ShadowPipeline.observe`
while the authority is asked what it would have decided. The response carries `agentsafe-mode:
SHADOW` and `agentsafe-execution: PASSTHROUGH`; the observation is reported when it settles and is
never a grant. Shadow measures policy impact; it protects nothing, and the output says so. See
[shadow mode](../shadow-mode.md).

## Not yet

HTTP/2 between the gateway and either side, streaming of governed bodies (they are read in full
under the bound), WebSocket upgrades, and a reconciliation route for an indeterminate outcome.
Each is a feature, not a protocol change, and none loosens what is above.
