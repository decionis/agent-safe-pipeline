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
  upstreamTimeoutMs: 10000 # at most 120000
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
  maxEmbeddedBodyBytes: 65536 # a JSON body up to this is visible to policy; larger is digest-only
  principalHeader: null # a request header whose value is carried as claimed_principal
  routes:
    - path: /payments/**
      action: payment.create
      methods: [POST] # default: POST, PUT, PATCH, DELETE

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

output:
  format: human # human | json; json under NODE_ENV=production
  verbose: false
```

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
- the demo authority, `allowInsecureLoopback` and a key in the environment are refused in
  production;
- `presence.managed` needs the Decionis authority, enforcement mode and an `approverId`;
- `maxEmbeddedBodyBytes` cannot exceed `maxBodyBytes`;
- an `authority.endpoint` other than `local` must be `https://`, or loopback with the allowance.

## The stored login

`agentsafe login` writes `credentials.json` with the key, the organization and the endpoint. Outside
production it is the lowest layer for those three settings; a `DECIONIS_API_KEY` in the environment
wins. The file is never written to by anything else and is never read in production.
