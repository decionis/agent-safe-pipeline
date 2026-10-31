# Configuration reference

The file is YAML, `version: 1`, and every key is optional but the upstream, which may also come
from `--upstream` or `AGENTSAFE_UPSTREAM`. An unknown key is refused by name. The precedence over
flags and variables is in [gateway configuration](../gateway/configuration.md); the variable for
each key is in the [environment reference](./environment.md).

```yaml
version: 1

gateway:
  listen: "127.0.0.1:8080" # host:port, or ":8080" for every interface
  upstream: "http://localhost:3000"
  upstreamInsecure: false # true: plain http off loopback is the network's business
  upstreamPublicOnly: false # true: https at a public host only, every resolved address checked
  upstreamCredential: # optional; the gateway, not its caller, presents the upstream's credential
    header: authorization # a header the gateway neither sets nor sends to the authority
    file: /run/secrets/upstream-credential # absolute; its contents are the header's whole value
  gatewayToken: # optional; the gateway's own token, sent to the upstream as AgentSafe-Gateway-Token
    file: /run/secrets/gateway-token # absolute; a caller's value of the header is always dropped
  hosted: false # true: run for a tenant; public-only, operator-only status, host-only cookies, shadow unless it may enforce
  tenantKeyDigests: [] # one or two "sha256:<64 hex>"; required when hosted
  rateLimit: # optional; a hosted gateway gets 50/s, burst 100
    requestsPerSecond: 5 # above 0, at most 10000
    burst: 20 # 1 to 100000
  upstreamTimeoutMs: 10000 # one forward's budget, at most 120000; running out is INDETERMINATE
  system: "localhost:3000" # downstream_target.system in the intent; the upstream host by default
  environment: "local" # downstream_target.environment; "production" under NODE_ENV=production

authority: # or `decionis:`; not both
  endpoint: "https://api.decionis.com" # or "local" for the demo authority
  mode: shadow # shadow | enforcement
  failurePolicy: failClosed # failClosed | failOpen
  tenantId: "00000000-0000-4000-8000-000000000009" # the key's organization; a UUID
  timeoutMs: 4000 # at most 15000
  allowInsecureLoopback: false # a plain-http authority on loopback, for a local double; never in production

interception:
  http: true # false passes everything through
  unmatched: govern # govern | passthrough
  maxBodyBytes: 1048576 # a governed body above this is refused with 413; at most 16 MiB
  maxEmbeddedBodyBytes: 65536 # JSON up to this is visible to policy; larger is digest-only; 0 embeds none
  principalHeader: null # a request header whose value is carried as claimed_principal
  profile: null # an API intent profile, e.g. walmart/api/v3; its operations follow any route
  privacy: full # full | facts: the authority receives the profile's operation and facts only
  refuseUnknownReads: false # true (the default with subject and a profile): a call the profile cannot check is refused
  observeRefusals: true # false: a refused write's target is not read again (one GET per refusal)
  refusalWindowMs: 1000 # how long after the refusal that read is made; 0 to 30000
  routes:
    - path: /payments/**
      action: payment.create
      methods: [POST] # default: POST, PUT, PATCH, DELETE

containment: # optional: what this deployment says the agent zone must not reach directly
  targets: [] # "name=host:port", at most 64; nothing dials them, they are in the fingerprint

subject: # optional: pin each session to the customer your identity provider names
  issuer: https://login.example.com/ # the token's iss, exactly
  audience: agentsafe-gateway # one of the token's aud
  jwksFile: /etc/agentsafe/idp-jwks.json # the provider's keys; or jwksUrl, or both
  jwksUrl: null # https; fetched at start without a file, refreshed every 5 minutes
  claim: sub # the claim naming the customer
  sessionTtlSeconds: 900 # 60 to 3600; never past the token's own expiry

actor:
  id: agentsafe-gateway # the intent's actor; `runtime` is agentsafe/<version>
  type: GATEWAY

intentTtlSeconds: 120 # how long a captured intent, and a held escalation, stays valid; at most 300

presence:
  managed: false # true: Decionis orchestrates the ceremony on an ESCALATE
  approverId: null # required with managed: true
  approverRole: null
  level: standard # standard | high_confidence
  methods: [webauthn] # webauthn, active_liveness

evidence:
  enabled: true # false: best-effort evidence; nothing is held for a line
  journalDir: null # a directory for evidence.jsonl and the chain heads
  observer: null # who effect evidence names as its observer; the boundary id when null

output:
  format: human # human | json; json under NODE_ENV=production
  verbose: false
```

## Reading the target

In enforcement, a write whose profile operation names a `precondition` read is read three times
by the gateway, each a `GET` it makes as itself (its `upstreamCredential` and `gatewayToken`, none
of the caller's headers). Before the authority is asked, so the intent binds the version; after an
`ALLOW` the upstream answered `2xx`, against the operation's `effect`; and after a BLOCK, a held
ESCALATE or a fail-closed refusal, `refusalWindowMs` later, unless `observeRefusals` is `false`. A
gateway that holds no upstream credential reads unauthenticated, and an upstream that refuses
that read refuses the write (`TARGET_STATE_UNREADABLE`). `evidence.observer` is the identity the
authority's trusted-observer allowlist must list for a read-back to be recorded `CONFIRMED`.
[HTTP interception](../gateway/http-interception.md#the-target-a-write-names) says what each read
establishes.

## Defaults that depend on the authority

| Setting              | With a Decionis key | Without one (demo authority)  |
| -------------------- | ------------------- | ----------------------------- |
| `authority.mode`     | `shadow`            | `enforcement`                 |
| `authority.tenantId` | required            | a reserved fixture identifier |
| secrets required     | `DECIONIS_API_KEY`  | none                          |

The demo authority governs nothing real, so it enforces by default and the first request shows a
refusal; a real authority is watched in shadow first, as the [runbook](../../deploy/Runbook.md)
describes for the executor.

## Refusals

A refusal names the setting: `CONFIG_MISSING: upstream (--upstream, AGENTSAFE_UPSTREAM or
gateway.upstream)`, `CONFIG_INVALID: authority.mode (shadow or enforcement)`,
`CONFIG_INVALID: interception.routes.0.action`. Among the rules it enforces:

- a plain-http upstream off loopback needs `upstreamInsecure: true`;
- a public-only upstream must be `https://` and name a public host, not loopback or an inward
  address;
- a hosted gateway needs at least one tenant key digest, and runs in shadow unless every control
  of [hosted enforcement](../gateway/configuration.md#hosted-enforcement) is on: a process of its
  own (`AGENTSAFE_HOSTED_DEDICATED`), its tenant, a Decionis organization, `failClosed`, the
  upstream's proof, an `upstreamCredential` and evidence;
- `upstreamCredential` needs both its header and its file, an absolute path, and a header that is
  not hop-by-hop, framing, `Content-Type`, `Idempotency-Key`, the principal header, or under
  `agentsafe-`, `x-agent-safe-` or `x-forwarded-`;
- `gatewayToken` names a file, an absolute path, and nothing else: its header is fixed;
- `tenantKeyDigests` holds one or two distinct `sha256:<64 hex>` digests;
- the demo authority, `allowInsecureLoopback` and a key in the environment are refused in
  production;
- `presence.managed` needs the Decionis authority, enforcement mode and an `approverId`;
- `maxEmbeddedBodyBytes` is 0 or more and cannot exceed `maxBodyBytes`;
- `principalHeader` cannot be one of the gateway's own credentials: `AgentSafe-Tenant-Key`,
  `AgentSafe-Session`, `AgentSafe-Subject-Token` or `AgentSafe-Gateway-Token`;
- `privacy: facts` needs a `profile`, and refuses `routes`, a `principalHeader` and
  `unmatched: passthrough`;
- `subject` needs `jwksFile` or `jwksUrl`; `refuseUnknownReads` needs `subject` and a `profile`,
  and cannot be `false` with `subject` on a gateway that holds the upstream credential;
- an `authority.endpoint` other than `local` must be `https://`, or loopback with the allowance.

## The stored login

`agentsafe login` writes `credentials.json` with the key, the organization and the endpoint. Outside
production it is the lowest layer for those three settings; a `DECIONIS_API_KEY` in the environment
wins. The file is never written to by anything else and is never read in production.
