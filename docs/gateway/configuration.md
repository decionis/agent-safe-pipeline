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

An upstream whose certificate does not verify, or that refuses the handshake, is sent nothing
either: the answer is `502` with `UPSTREAM_TLS_REJECTED`, or `UPSTREAM_CLIENT_CERT_REFUSED` when
the upstream refused the client certificate a gateway never presents, with TLS 1.3's
`certificate_required` or with the `bad_certificate`, `certificate_unknown`, `unknown_ca` or
`access_denied` that some servers send instead; both are `NOT_FORWARDED`. Under TLS 1.2 that
refusal is usually a bare handshake failure, reported as `UPSTREAM_TLS_REJECTED`. The security
stream carries `UPSTREAM_TLS_REFUSED` with the origin and the code, apart from `EGRESS_REFUSED`: an
upstream's TLS is its owner's to fix, not an attack on the gateway. Any other TLS failure after a
verified handshake broke a connection that may have carried the request, and is
`UPSTREAM_TRANSPORT_FAILED` and `INDETERMINATE`, with no security event. The same failure on a
connection to a destination the operator names, such as the gateway's authority, is
`EGRESS_REFUSED` with `EGRESS_TLS_BROKEN`. An API that requires
mutual TLS cannot be fronted by a gateway at all; [shadow mode](../shadow-mode.md#when-the-gateway-cannot-front-your-api-mutual-tls-third-party-saas)
says what to run instead.

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

`AGENTSAFE_UPSTREAM_PROOF_REQUIRED=true`, which `agentsafe host --require-upstream-proof` sets for
every tenant, makes a hosted gateway forward nothing until its upstream's origin serves a proof
bound to its tenant ([the upstream's proof](#the-upstreams-proof)). It is refused on a gateway that
is not hosted, has no `AGENTSAFE_HOSTED_TENANT`, or has no Decionis organization in
`DECIONIS_TENANT_ID`, since those are what the proof is bound to.

## Many tenants in one process

`agentsafe host --registry /etc/agentsafe/tenants.yaml` serves every tenant the registry names, each
as its own hosted gateway at `{id}.{domain}`:

```yaml
version: 1
domain: decionisedge.com
evidenceDir: /var/lib/agent-safe/tenants # optional: one directory per tenant, on a volume (below)
tenants:
  - id: acme # a DNS label; www, api, status, admin and console are the operator's
    upstream: https://api.acme.example
    tenantKeyDigests: ["sha256:…"] # one, or two during a rotation
    rateLimit: { requestsPerSecond: 5, burst: 20 } # optional; else the registry's, else 50/100
    upstreamTimeoutMs: 30000 # optional; else AGENTSAFE_UPSTREAM_TIMEOUT_MS, else 10000
    workspace:
      tenantId: 7c0e… # the Decionis workspace the tenant's evaluations run in
      apiKeyFile: /var/run/agent-safe/tenants/acme/decionis-api-key
    interception: # optional: the tenant's routes, as in agentsafe.yaml
      routes:
        - { path: /payments/**, action: payment.create, methods: [POST] }
```

Each tenant's gateway is built exactly as a hosted gateway configured by hand would be: public-only
upstream, shadow only, operator-only status and metrics, host-only cookies, its tenant key required,
and its workspace key read from its own mounted file. From the host's environment it inherits only
how to reach the authority (`NODE_ENV`, `DECIONIS_API_URL`, `DECIONIS_TIMEOUT_MS`,
`DECIONIS_ALLOW_INSECURE_LOOPBACK`, `AGENTSAFE_UPSTREAM_TIMEOUT_MS`, `AGENTSAFE_FAILURE_POLICY`),
never a credential; a tenant's own `upstreamTimeoutMs` (1 to 120000) replaces the host's timeout
for that tenant. A request is routed to one tenant by its `Host` alone, so nothing about one
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
`TENANT_REGISTRY_LOADED` or `TENANT_REGISTRY_REFUSED` line naming the registry's `revision`
(`sha256:` and the first 12 hex digits of the SHA-256 of its text, as read) and what was built,
kept, rekeyed, retired and failed.

The schema is strict, so a host refuses a field it does not know. A tenant's `upstreamTimeoutMs`,
and an `interception.maxEmbeddedBodyBytes` of `0`, came after the first builds of `agentsafe host`.
A host built before them refuses the whole registry over the first (`REGISTRY_INVALID`): on a
reload no later change applies, a key revocation included, and at start the process exits, so a
replica restarted on that host never comes up. It refuses that tenant's gateway over the second
(`CONFIG_INVALID`). Write either only once every replica runs a host that accepts it, and take it
out of the registry before rolling back to a host that does not. Between releases every build
reports the same version, so check the image the replicas run, not the version.

A change to a tenant's `tenantKeyDigests` alone rebuilds nothing: the tenant's gateway admits the
new set at once and goes on as it was, its chains, rate and counts included, and the tenant is
`rekeyed`. A revocation never waits on a build. Digests are read the same way in place as at a
build: split at commas, trimmed, and empty values dropped, so a reload of an entry its gateway was
built from admits the same keys. When the rest of an entry cannot be applied, the
tenant keeps the gateway it had, but that gateway admits only the keys the entry still lists; if
the entry's digests are themselves malformed, it keeps only those it already admits that the entry
still names, and a tenant left with none is not served (`421`) until its entry is fixed. Each
replica reads the registry on its own, so a change reaches replicas at different moments: a
tenant's `/_agentsafe/status`, which answers the operator's token only, carries `hosted`, with the
registry `revision` that replica last loaded, the `entry` (a short digest) its gateway was built
from, and a `sha256:` prefix of 12 hex digits for each tenant key it admits, never the digest.

Once the listener is bound, each tenant's gateway prints its banner (`GATEWAY_STARTED`, at
`https://{id}.{domain}` when the host terminates TLS) and links `GATEWAY_STARTED` on its own
gateway-events chain, and so does each gateway a reload builds. A replaced or removed gateway, once
it has drained, prints its `SHADOW_REPORT`, counting what settled while it drained, and
`GATEWAY_STOPPED` with `signal: RELOAD`; on `SIGTERM` or `SIGINT` every gateway does the same with
the signal. `readyz` answers `503` until one load has served every tenant the registry names (and,
with `--require-upstream-proof`, each of their gateways has had its first look at its upstream's
proof, or 30 seconds have passed), and `200` from then on: a new process, in a rollout or after a
restart, takes no traffic while it would answer a tenant `421`, and a tenant that fails later is
reported without taking every other tenant out of service.

### The upstream's proof

Without it, a host is a relay from its own address to any public site a registry entry names. With
`agentsafe host --require-upstream-proof`, each tenant's gateway forwards nothing until its
upstream's origin serves a token bound to three things every entry already has: the tenant's `id`,
its `workspace.tenantId` (the Decionis organization it runs under) and the upstream's origin, as
the WHATWG URL spells it (`https`, the host in lower case, no port when it is 443, no path). The
base path is never part of it: the gateway is sealed to the whole origin, so the proof covers the
whole origin. There is no registry field to write.

The token is
`v1.<issued>.<base64url(SHA-256("agentsafe-upstream\nv1\n" + id + "\n" + organization + "\n" + origin + "\n" + issued)[0:16])>`,
where `<issued>` is the ten-digit Unix time it was issued at and the base64url has no padding. It
holds no secret: whoever
asks for one is given it, and what proves control is that only the origin's controller can serve
it there. For `acme`, organization `6f1c1e0e-2a8b-4a35-9c55-0d6f0a3d2b11`, origin
`https://api.acme.example`, issued `1759492800`, it is `v1.1759492800.GCO1YWc5UIsWe8_w9vbzTQ`.
The origin serves it in either of two ways:

- **A file.** `GET https://<host>/.well-known/agentsafe-upstream` answers `200` with text of at most
  1 KiB, at the origin itself (a redirect is not followed) and without credentials, from the
  fleet's egress address. Any line that is a token bound to the tenant proves it; other lines,
  `#` comments among them, are ignored, so one file can carry several tenants' tokens and a
  rotation's two.
- **A TXT record** at `_agentsafe-challenge.<host>` that contains the token: the record's strings
  are joined, and the token may stand alone or as a part separated by spaces or `=`
  (`agentsafe-upstream=<token>`). It counts only when the origin also answered the file's `GET`
  over verified TLS, because DNS is not authenticated and only that answer ties the name to where
  traffic goes. An address written as the host has no name to publish one under.

The check is the gateway's own, apart from its relay: public addresses only, TLS verified against
the public roots, a loopback name refused, no header of the tenant's, and
`User-Agent: agentsafe-upstream-proof/1`. It runs when the gateway is built and every minute until
the proof is seen, then once a day, give or take an hour. The host checks only the binding, never
a token's age; how fresh a token must be is onboarding's rule. What a tenant's request gets:

| Proof                                              | Request with the tenant key                                                                                                  |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| not seen yet, or not served when first looked for  | `503 UPSTREAM_UNVERIFIED`, `NOT_FORWARDED`, `Retry-After: 60`, and `fallback`, the upstream to call directly in the meantime |
| seen                                               | forwarded                                                                                                                    |
| gone: the origin answered with no bound token      | forwarded with `agentsafe-upstream-proof: missing` for 72 hours, looked for every hour, then `503 UPSTREAM_UNVERIFIED`       |
| no answer at all (a timeout, a refused connection) | whatever it was before                                                                                                       |

A request without the key is refused as before, so only the tenant learns where its proof stands;
the gateway's own routes are unaffected. A redirect or an error status at the proof's path is an
answer without a token. The tenant's security stream carries `UPSTREAM_PROOF_MISSING` (the origin
and `stops_at`), `UPSTREAM_UNVERIFIED` (the origin and `UPSTREAM_PROOF_NOT_SERVED` or
`UPSTREAM_PROOF_GRACE_ENDED`) and `UPSTREAM_PROOF_RESTORED` (the origin and `file` or `dns`); the
proof's text is never written anywhere. The operator's `/_agentsafe/status` carries
`hosted.upstream_proof`: the state, the method, when it was last checked, when a missing proof
stops forwarding, and the code of a check that got no answer.

Where a proof stands is kept per process. A gateway rebuilt for the same tenant, organization and
origin keeps it, so a change to anything else in an entry never stops a proven tenant for a check;
a new origin or organization is proved from the start. A new process looks again, so a grace in
progress does not survive a restart. Turn the flag on only once every tenant's origin serves its
proof.

### Evidence across reloads, restarts and replicas

A tenant's chains belong to the process. A gateway a reload builds takes up the chains of the one
it replaces, so the tenant's evidence goes on in one sequence, with `CHAIN_RESUMED` on its security
chain naming each stream's head at the rebuild; the drained gateway finishes on the same chains.
The one it replaces is found by the tenant's id, not its host, so the chains also go on when a
change to the registry's `domain` moves every tenant to a new host, and when a tenant is removed
and added back while its old gateway still drains.
Without `evidenceDir`, a process start begins each tenant's chains from genesis, which
`agentsafe verify-chain` counts as a start. With it, each tenant's chain heads are kept under
`<evidenceDir>/<id>/chain/`, beside its `evidence.jsonl`, and the next process goes on from them
(`CHAIN_RESUMED`).

The published image runs Node under its permission model: it reads only `/app`, `/etc/agentsafe`
and `/var/run/agent-safe`, and writes only under `/var/lib/agent-safe`. With a read-only root
filesystem, mount a writable volume at `/var/lib/agent-safe` first, and only then set `evidenceDir`
beneath it: a directory the process cannot create fails every tenant's build
(`TENANT_BUILD_FAILED`), so tenants already served keep the gateways they had and a new process
serves none and never becomes ready. The volume must be one replica's own (an `emptyDir` keeps
the heads across a container restart, a volume claim per replica across a reschedule); two
processes writing one tenant's heads fork its chains.

Each replica runs its own chains for every tenant, from its own start, and nothing in a chained
line names the replica. A log pipeline that merges replicas' output must keep each replica's lines
apart (by pod) and in the order that process wrote them; each part then verifies on its own, with
one start for each process start. Ordered by `seq` alone, or interleaved across replicas, the lines
do not verify.

### TLS at the host

With `--tls-cert` and `--tls-key`, `agentsafe host` terminates TLS itself, with the executor's
listener (TLS 1.3, or 1.2 with AEAD ciphers only, no renegotiation), so a layer-4 load balancer is
the whole edge. The key is watched like any mounted secret: when a certificate manager renews the
certificate and key in a Kubernetes Secret, new connections get the new pair and open ones keep
theirs (`TLS_CONTEXT_ROTATED`); a renewal that does not make a valid pair keeps the one in use
(`TLS_ROTATION_REFUSED`). Every response then carries
`Strict-Transport-Security: max-age=31536000; includeSubDomains`, once: the transport policy of
the host is the operator's, so an upstream's own is not relayed beside it. `--redirect-listen` adds
a plain-HTTP listener that answers only redirects to the same host over HTTPS (`301`, or `308` for a
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
A request without one is `401 TENANT_KEY_MISSING` and one with any other key is
`401 TENANT_KEY_INVALID`, each with `WWW-Authenticate: AgentSafe-Tenant-Key` and
`agentsafe-execution: NOT_FORWARDED`. Nothing is forwarded, the refusal is counted as
`agentsafe_requests_total{kind="tenant_key_refused"}`, and `AUTH_FAILED` with method
`tenant_key` and code `TENANT_KEY_MISSING` or `TENANT_KEY_INVALID` is on the security stream,
never with the value presented. The header is removed before any request is forwarded, whether or
not digests are set, so an upstream never sees it, and it cannot be the
`interception.principalHeader`. The gateway's own routes do not take it: `healthz` and `readyz`
answer platform probes, and `status` and `metrics` answer the operator's token. A hosted gateway
refuses to start without a digest.

Anyone who knows a gateway's host can send requests without the key, so what a refusal writes to the
chained security stream is bounded per gateway, whatever the rate and however many addresses it
comes from. In each 60-second window, opened by the first refusal, the first 10 refusals are each an
`AUTH_FAILED` line; the rest are counted by code, and each count is one `AUTH_FAILED_SUPPRESSED`
line with `method`, `code` and `count` when the window closes, or when the gateway closes first. A
gateway therefore writes at most 12 such lines a minute. Every request is still refused and counted
in `agentsafe_requests_total{kind="tenant_key_refused"}`, and the tenant's own key is admitted as
before: the bound is on the evidence a flood costs, not on the tenant's traffic, which a refusal
never spends.

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
