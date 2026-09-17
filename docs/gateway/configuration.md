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
