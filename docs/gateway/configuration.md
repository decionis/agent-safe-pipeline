# Gateway configuration

One schema, read the same way by every distribution: a file, `agentsafe.yaml`, plus environment
variables and command-line flags, in a fixed precedence.

```text
command-line flags
      ↓ over
environment variables
      ↓ over
agentsafe.yaml
      ↓ over
the stored login (agentsafe login), for the Decionis key, organization and endpoint only
      ↓ over
safe defaults
```

Each setting is resolved on its own: a flag for the port and a file value for the upstream give a
gateway with both. A layer that has a setting but cannot parse it is a refusal that names the
setting, never a silent fall-through to the next layer, so a typo cannot land on a default.
`agentsafe config` prints the effective configuration with the layer each setting came from, and
never a secret value.

The full schema is in the [configuration reference](../reference/config.md) and every variable in
the [environment reference](../reference/environment.md). The smallest file:

```yaml
version: 1
gateway:
  listen: "127.0.0.1:8080"
  upstream: "http://localhost:3000"
```

`agentsafe init` writes one, with routes from an OpenAPI document when it finds one and the port
from `package.json` when a script names one.

## The authority

| Setting                   | Meaning                                                                                   |
| ------------------------- | ----------------------------------------------------------------------------------------- |
| `authority.endpoint`      | `https://api.decionis.com` by default; `local` selects the demo authority explicitly      |
| `authority.mode`          | `shadow` (default with a Decionis key) or `enforcement` (default with the demo authority) |
| `authority.failurePolicy` | `failClosed` (default) or `failOpen`; see [failure policy](./failure-policy.md)           |
| `authority.tenantId`      | the key's organization; `DECIONIS_TENANT_ID` is the usual place                           |
| `authority.timeoutMs`     | the budget for one authority call, 4,000 by default, at most 15,000                       |

The section may also be spelled `decionis:`; both name the same settings, and giving both is
refused. The Decionis key itself never goes in the file: `DECIONIS_API_KEY`, `DECIONIS_API_KEY_FILE`
(the only form accepted in production), or `agentsafe login`.

Without a key and without `authority.endpoint`, the gateway runs the demo authority: the loopback
double of the Decionis routes from `@decionis/agent-safe-pipeline/testing`, with a synthetic policy,
reached through the same `DecionisGate` as the real one. It is refused under `NODE_ENV=production`
and named `local/demo` on the banner, in every report and in the evidence.

## The upstream

`gateway.upstream` is where authorized requests go. `https://` is the default expectation; a
plain-http upstream is accepted on loopback, and elsewhere only with `gateway.upstreamInsecure:
true` (`AGENTSAFE_UPSTREAM_INSECURE=true`), which is a statement that the network, not TLS,
protects that hop, as it does inside a cluster with a mesh. A path in the upstream URL is a base
path every forwarded request is placed under. `gateway.system` and `gateway.environment` name the
downstream target in the intent; they default to the upstream's host and to `local` (`production`
under `NODE_ENV=production`).

`gateway.upstreamPublicOnly: true` (`AGENTSAFE_UPSTREAM_PUBLIC_ONLY=true`) is for a gateway whose
upstream someone other than its operator chose, as a hosted gateway's tenant does. The upstream
must then be `https://` at a public host, and it is reached through the same guarded egress the
executor uses: the name is resolved once, and if any address it answers with is loopback,
link-local, private (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`), shared (`100.64/10`),
benchmarking (`198.18/15`), NAT64 (`64:ff9b::/96`) or the Azure platform address
(`168.63.129.16`), nothing is sent: the answer is `502` with `UPSTREAM_ADDRESS_REFUSED` and
`NOT_FORWARDED`, and `EGRESS_REFUSED` is on the security stream. An address written as the host is
checked the same way, at start and on every request. Without it, as by default, private addresses
are allowed, because that is where an operator's own services live.

## Hosted

`gateway.hosted: true` (`AGENTSAFE_HOSTED_GATEWAY=true`) is for a gateway someone runs on a
tenant's behalf, as Decionis runs hosted shadow. It changes four things:

- the upstream is public-only, whatever `upstreamPublicOnly` says;
- the mode is shadow: a hosted gateway set to enforce is refused at start, because enforcing
  would mean holding the tenant's provider credentials;
- `/_agentsafe/status` and `/_agentsafe/metrics` answer only `Authorization: Bearer
$AGENTSAFE_METRICS_TOKEN`, the operator's token, with `401` for any other, and are not there
  at all (`404`) when no token is set; `healthz` and `readyz` stay open for the platform's probes;
- every `Set-Cookie` the upstream sends is relayed without its `Domain` attribute, so a cookie is
  kept for the exact host it came from and one tenant's upstream cannot set a cookie that the
  client would send to another tenant's host under the same domain;
- the tenant's key is required (below), so a hosted gateway admits only its tenant.

## Many tenants in one process

`agentsafe host --registry /etc/agentsafe/tenants.yaml` serves every tenant the registry names, each
as its own hosted gateway at `{id}.{domain}`:

```yaml
version: 1
domain: decionisedge.com
evidenceDir: /var/lib/agentsafe/tenants # optional: one directory per tenant
tenants:
  - id: acme # a DNS label; www, api, status, admin and console are the operator's
    upstream: https://api.acme.example
    tenantKeyDigests: ["sha256:…"] # one, or two during a rotation
    rateLimit: { requestsPerSecond: 5, burst: 20 } # optional; else the registry's, else 50/100
    workspace:
      tenantId: 7c0e… # the Decionis workspace the tenant's evaluations run in
      apiKeyFile: /run/secrets/tenants/acme/decionis-api-key
    interception: # optional: the tenant's routes, as in agentsafe.yaml
      routes:
        - { path: /payments/**, action: payment.create, methods: [POST] }
```

Each tenant's gateway is built exactly as a hosted gateway configured by hand would be: public-only
upstream, shadow only, operator-only status and metrics, host-only cookies, its tenant key required,
and its workspace key read from its own mounted file. From the host's environment it inherits only
how to reach the authority (`NODE_ENV`, `DECIONIS_API_URL`, `DECIONIS_TIMEOUT_MS`,
`DECIONIS_ALLOW_INSECURE_LOOPBACK`, `AGENTSAFE_UPSTREAM_TIMEOUT_MS`, `AGENTSAFE_FAILURE_POLICY`),
never a credential. A request is routed to one tenant by its `Host` alone, so nothing about one
tenant is reachable from another's host. Every line a tenant's gateway prints names the tenant:
its chained lines carry it in their envelope (`AGENTSAFE_HOSTED_TENANT`, set by the host), covered by
the hash, and every other line gets it first, so the host's output can be retained and deleted per
tenant and still verifies with `agentsafe verify-chain`.

The registry is checked whole: a file that cannot be parsed, or breaks a rule (a duplicate id, a
relative key path, more than 1,000 tenants), is refused at start and ignored on reload, and the
tenants already served stay served. A tenant whose own gateway cannot be built (an `http://`
upstream, a missing key file) is reported by code and setting, keeps the gateway it had, and is
tried again every 60 seconds while the registry is unchanged, so a tenant whose key file has not
reached the mount yet is served as soon as it has. A hosted gateway watches its workspace key file,
so a key rotated in a mounted Secret takes effect without a rebuild or a restart, with
`SECRET_ROTATED` on the tenant's security chain. A
reload rebuilds only the tenants whose entry changed; a replaced or removed tenant's gateway
finishes the requests in flight for 30 seconds before it is closed. Each load is one
`TENANT_REGISTRY_LOADED` or `TENANT_REGISTRY_REFUSED` line naming what was built, kept, retired and
failed.

### TLS at the host

With `--tls-cert` and `--tls-key`, `agentsafe host` terminates TLS itself, with the executor's
listener (TLS 1.3, or 1.2 with AEAD ciphers only, no renegotiation), so a layer-4 load balancer is
the whole edge. The key is watched like any mounted secret: when a certificate manager renews the
certificate and key in a Kubernetes Secret, new connections get the new pair and open ones keep
theirs (`TLS_CONTEXT_ROTATED`); a renewal that does not make a valid pair keeps the one in use
(`TLS_ROTATION_REFUSED`). Every response then carries
`Strict-Transport-Security: max-age=31536000; includeSubDomains`. `--redirect-listen` adds a
plain-HTTP listener that answers only redirects to the same host over HTTPS (`301`, or `308` for a
method other than `GET` and `HEAD`, never acting on the request), for the registry's domain and the
hosts under it; any other host is `421`. `--apex-page` is the HTML the domain itself answers at `/`,
with a policy that allows inline style and nothing else.

## The rate a gateway admits

`gateway.rateLimit: { requestsPerSecond: 5, burst: 20 }` (`AGENTSAFE_RATE_LIMIT_RPS` and
`AGENTSAFE_RATE_LIMIT_BURST`, both or neither) limits the traffic one gateway admits: a token bucket
that starts full at `burst` and refills at `requestsPerSecond`. It is taken after the tenant key, so
only the tenant's own traffic spends the tenant's rate and a flood of requests without the key
cannot exhaust it; the gateway's own routes do not take it. A request over the rate is
`429 RATE_LIMITED` with `Retry-After` in whole seconds, and is counted as
`agentsafe_requests_total{kind="rate_limited"}`. A hosted gateway without a limit gets 50 per second
with a burst of 100; otherwise there is none. The limit is per process: behind several replicas the
total is the limit times the replicas. In a tenant registry, `rateLimit` at the top is every
tenant's default and a tenant's own `rateLimit` replaces it.

## The tenant key

`gateway.tenantKeyDigests` (`AGENTSAFE_TENANT_KEY_DIGESTS`, comma-separated) holds one or two
`sha256:<64 hex>` digests of a tenant's ingress key; two while a rotation overlaps, so an agent can
be redeployed with the new key before the old digest is removed. The key itself is never in the
configuration: the operator issues it to the tenant and keeps only its digest.

When digests are set, every request that is not the gateway's own must carry a key in the
`AgentSafe-Tenant-Key` header that hashes to one of them, compared in constant time against each.
Anything else is `401 TENANT_KEY_INVALID`, nothing is forwarded, the refusal is counted as
`agentsafe_requests_total{kind="tenant_key_refused"}`, and `AUTH_FAILED` with method
`tenant_key` and code `TENANT_KEY_MISSING` or `TENANT_KEY_INVALID` is on the security stream,
never with the value presented. The header is removed before any request is forwarded, whether or
not digests are set, so an upstream never sees it, and it cannot be the
`interception.principalHeader`. The gateway's own routes do not take it: `healthz` and `readyz`
answer platform probes, and `status` and `metrics` answer the operator's token. A hosted gateway
refuses to start without a digest.

## Presence

```yaml
presence:
  managed: true
  approverId: cro-principal-id
  approverRole: CRO
  level: high_confidence
  methods: [webauthn, active_liveness]
```

With `presence.managed: true` an `ESCALATE` is orchestrated by Decionis: the gateway holds the
request, Decionis runs the Presence ceremony with the named approver, and a resume asks Decionis
again; a fresh `ALLOW` with a grant executes the held request once. It needs the Decionis
authority and enforcement mode, and no Presence credential exists in the gateway. Without it, an
`ESCALATE` is held and reported, and that is the answer.

## Evidence and output

`evidence.journalDir` names a directory for the chained evidence lines (`evidence.jsonl`) and the
chain heads a restart resumes from. Without it, the lines go to the terminal in JSON output or
with `--verbose`, and are otherwise not written; the banner says which. `output.format` is `human`
on a terminal and `json` under `NODE_ENV=production`; `AGENTSAFE_LOG_FORMAT=json` forces one line
of JSON per event, which is what a container's log pipeline wants.
