# Hosted

Decionis runs this runtime as a hosted fleet, live in shadow: each tenant it onboards is served at
`{id}.decionisedge.com`, and a request within the gateway's bounds (below) reaches the tenant's API
while Decionis records what it would have decided. Decionis onboards each tenant and hands it a
tenant key; there is no self-serve sign-up. Bringing an endpoint, saying which of its actions are
consequential and watching the decisions without an operator in the loop is the evaluation path
the fleet is building toward, and that part is not live.

What this repository establishes is that the fleet runs the same runtime. The hosted gateway is not
a second implementation: it is `Gateway` from `@decionis/agentsafe`, configured per governed
endpoint, behind the same listener, asking the same Decionis authority through the same
`DecionisGate`, claiming the same single-use grants, leaving the same chained evidence. The
commercial boundary is what surrounds it (managed policies, organizational authority, Presence
coordination, retention, fleet visibility), never a weaker gateway for the self-hosted path.

## What a tenant of the fleet sees

The fleet is `agentsafe host` serving a [tenant registry](../gateway/configuration.md#many-tenants-in-one-process).
For a tenant, that means:

- **The base URL changes, and the key is added.** The agent sends the same method, path, query and
  body to `https://{id}.decionisedge.com` instead of its API's own host, with
  `AgentSafe-Tenant-Key: <key>` ([the tenant key](../gateway/configuration.md#the-tenant-key)). The
  gateway removes the key, adds `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host`, and
  `x-agent-safe-intent-hash` on an evaluated request, and forwards the rest unchanged.
- **Shadow only, and the routes are fixed.** `POST`, `PUT`, `PATCH` and `DELETE` are evaluated as
  they pass, each under its derived name (`http.post`, `http.put`, `http.patch`, `http.delete`),
  and nothing is held or blocked on a verdict; `GET`, `HEAD` and `OPTIONS` pass through
  unevaluated. A tenant of the fleet cannot configure routes or name its actions: onboarding sets
  none, so every tenant gets these defaults. What Decionis is shown of an evaluated request is in
  [what the authority sees](../gateway/http-interception.md#what-the-authority-sees).
- **Responses change.** A relayed response carries `agentsafe-execution` (`PASSTHROUGH`), and
  `agentsafe-mode: SHADOW` when the request was evaluated; any `agentsafe-*` header the API sent is
  dropped. Every relayed response gets `Content-Security-Policy: sandbox`, so a page or script
  served through the gateway does not run as one; every `Set-Cookie` loses its `Domain`, so a
  cookie is kept for the tenant's host alone; and the fleet terminates TLS itself, so every answer
  carries its `Strict-Transport-Security`, never the API's own.
- **Some answers are the gateway's, not the API's.** `401` with `TENANT_KEY_MISSING` or
  `TENANT_KEY_INVALID` and `WWW-Authenticate: AgentSafe-Tenant-Key`; `421 HOST_NOT_SERVED` for a
  host that is no tenant's; `429 RATE_LIMITED` with `Retry-After` above the rate (50 requests a
  second with a burst of 100 unless the operator set another, per replica); `413 BODY_TOO_LARGE`
  for an evaluated body over 1 MiB; `502` when the API does not answer (`UPSTREAM_TIMEOUT` after
  10 seconds unless the operator set another, which never claims the request was not sent once it
  may have been) or its TLS refused the gateway (`UPSTREAM_TLS_REJECTED`,
  `UPSTREAM_CLIENT_CERT_REFUSED`); and `503 UPSTREAM_UNVERIFIED` (below) ([responses the gateway makes itself](../gateway/http-interception.md#responses-the-gateway-makes-itself)).
  Each carries `agentsafe-execution`: `NOT_FORWARDED` when the request did not reach the API,
  `INDETERMINATE` once it may have. The API's own answer, relayed, carries `PASSTHROUGH` (above),
  so an answer without `agentsafe-execution` did not come through the gateway.
- **Bodies are read whole.** A response is read in full, up to 16 MiB, before it is relayed; there
  is no streaming and no WebSocket upgrade.
- **The API's origin is proved, and goes on being proved.** A tenant proves it controls its API's
  origin by serving a token bound to the tenant, its Decionis workspace and that origin, at
  `https://<host>/.well-known/agentsafe-upstream` or in a TXT record at
  `_agentsafe-challenge.<host>` ([the upstream's proof](../gateway/configuration.md#the-upstreams-proof)),
  and keeps it served. A host run with `--require-upstream-proof` forwards nothing for the tenant
  until it has seen the proof, and looks again every day: while it is not seen, an admitted request
  is `503 UPSTREAM_UNVERIFIED` with `fallback` naming the API to call directly, and when it goes
  missing, answers carry `agentsafe-upstream-proof: missing` for 72 hours before forwarding stops. An API the gateway cannot front (mutual TLS, a third-party
  host the tenant cannot serve a file on) is answered with its code, and the
  [in-process path](../shadow-mode.md#when-the-gateway-cannot-front-your-api-mutual-tls-third-party-saas)
  gives the same report without a relay.

## The boundaries the runtime keeps for a host

- **Configuration is an object.** `GatewayConfigLoader.load({ file, env, version })` resolves a
  configuration from a document with the same schema as `agentsafe.yaml`; a host passes the
  document it generated for a tenant and an `env` of its own choosing, and the loader reads
  nothing from the process. `NODE_ENV=production` in that `env` refuses the demo authority and a
  key in the environment, as it does everywhere.
- **The key is a handle.** `Gateway.create(config, { secrets })` takes a `SecretStore`; a host
  hands in one that reads the tenant's key from wherever it keeps it, and the gate reads it
  through the handle per request, so a rotation needs no restart.
- **Output is a sink.** `Gateway.create(config, { io })` takes the report and evidence sinks; a
  host routes each tenant's lines to that tenant's evidence store and dashboard instead of a
  process's standard output.
- **Egress is injectable.** `authorityFetch` and `upstreamFetch` are the transports the gateway
  uses; a host that fronts many tenants gives each an upstream transport it controls.
- **One listener, many hosts.** `new GatewayHttpServer((hostname) => gatewayFor(hostname))` routes
  by the `Host` header: each governed endpoint is a host name, each host name is one `Gateway`
  with its own upstream, key, tenant, mode and routes, and a host the selector does not know is
  `421`. A single-gateway listener is the same class with a gateway instead of a selector.
- **Nothing else is shared.** Metrics, held escalations, evidence chains and the request holder
  are per gateway; a tenant's counts and holds are never another's.
- **Many tenants, one process.** `agentsafe host` is that listener with a selector built from a
  registry the operator mounts: each tenant's gateway at `{id}.{domain}`, its tenant key required,
  its keys changed in place, its chains kept across reloads
  ([many tenants in one process](../gateway/configuration.md#many-tenants-in-one-process)).

## What a hosted gateway still is not

It does not decide: the verdict is Decionis's, per tenant, under that tenant's key. It does not
verify a person: an `ESCALATE` is held until Decionis, having run the ceremony, answers again. And
it does not run the demo authority: a hosted endpoint evaluates against Decionis, with a
provisional key when the visitor has no account, and every dossier such a key mints is signed as
`provisional_anonymous`.

## Self-hosting is not crippled

The same commands, the same chart, the same image, the same protocol. A hosted evaluation that
becomes a production deployment moves to a laptop, a container, a host or a cluster with its
configuration file and its key, and nothing about the authority semantics changes on the way.
