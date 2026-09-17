# Hosted

`agentsafe.decionis.com` is the zero-install evaluation path: bring an endpoint, say which of its
actions are consequential, receive a governed endpoint, send a request, watch the decision, inspect
the evidence. It is not live yet, and nothing in this repository links to it as if it were.

What this repository establishes is that it will run the same runtime. The hosted gateway is not
a second implementation: it is `Gateway` from `@decionis/agentsafe`, configured per governed
endpoint, behind the same listener, asking the same Decionis authority through the same
`DecionisGate`, claiming the same single-use grants, leaving the same chained evidence. The
commercial boundary is what surrounds it (managed policies, organizational authority, Presence
coordination, retention, fleet visibility), never a weaker gateway for the self-hosted path.

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
