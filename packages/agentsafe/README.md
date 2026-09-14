# @decionis/agentsafe

The trusted executor of the Execution Authority architecture as one deployable process. A workflow
or agent host posts a proposal to it over HTTP; the executor attaches the trusted context from its
own configuration, asks the authority for a verdict, and on an `ALLOW` in enforcement claims the
single-use grant and runs the registered handler once. The proposer never receives a grant or a
credential. In shadow it records what the authority would have decided and never executes.

It is `IntentCapture`, `DecionisGate`, `DecionisGrantVerifier`, `ActionRegistry`, `SafeExecutor`,
`ShadowPipeline` and `AuditRecorder` from
[`@decionis/agent-safe-pipeline`](https://www.npmjs.com/package/@decionis/agent-safe-pipeline),
placed behind a listener so they run as their own service, inside your trust domain, on the far
side of a network policy from the agent.

```bash
npm install @decionis/agentsafe
```

## Minimal process

```ts
import { serve, type HandlerRegistration } from "@decionis/agentsafe";
import { JsonObjectSchema } from "@decionis/agent-safe-pipeline";

const handlers: HandlerRegistration = ({ registry, downstream, fetch }) => {
  registry.register("create_payout", {
    parametersSchema: JsonObjectSchema,
    execute: ({ parameters, authorization, dispatch }) =>
      dispatch.run(async (idempotencyKey) => {
        // The provider side effect, and nothing else, goes here.
        const response = await fetch(downstream.url, {
          method: "POST",
          headers: {
            [downstream.credentialHeader]: downstream.credential,
            "idempotency-key": idempotencyKey,
            "x-agent-safe-dossier-id": authorization.dossierId,
          },
          body: JSON.stringify(parameters),
        });
        return { status: response.status, accepted: response.ok };
      }),
    reconcile: async ({ idempotencyKey }) => {
      // Read-only: what did the provider do with this key? Never send again.
      const response = await fetch(
        `${downstream.lookupUrl}`.replace("{idempotency_key}", idempotencyKey),
      );
      if (response.status === 404) return { status: "NOT_EXECUTED" };
      if (response.ok)
        return { status: "COMPLETED", result: { status: response.status, accepted: true } };
      return { status: "UNKNOWN" };
    },
  });
  return ["create_payout"];
};

await serve(handlers);
```

`serve` reads the configuration from the environment and mounted files, refuses to start with any
variable missing (naming the variable, never its value), binds the listener, and closes it on
`SIGTERM`. The bin `agentsafe serve` does the same with the reference forwarding handler,
`forwardRequestHandlers()`, which posts the verified parameters to `DOWNSTREAM_URL`. To assemble the
executor without a process around it, `createTrustedExecutor({ config, handlers })` returns the
service and a `listen`/`close` pair; the offline proof in the repository does exactly that against
loopback doubles.

## What it is, and is not

It is the execution boundary as a process: the same components as the package README of
`@decionis/agent-safe-pipeline` shows in one file, with a listener, a configuration contract, an
escalation resolver for both Presence shapes, and a sealed handler seam.

It is not a hosted service, not the authority (that is the Decionis service, or your own
implementation of the two interfaces in
[OPEN-CORE.md](https://github.com/decionis/agent-safe-pipeline/blob/master/OPEN-CORE.md)), and not
a substitute for the controls the host owns: executor isolation, agent egress denial, credential
scoping
([THREAT-MODEL.md](https://github.com/decionis/agent-safe-pipeline/blob/master/THREAT-MODEL.md),
"Accepted risks"). The Kubernetes manifest in the repository's
[deployment kit](https://github.com/decionis/agent-safe-pipeline/blob/master/deploy/README.md) is
where those controls are written down.

## The wire contract

| Method | Path                  | Token | What it does                                                                        |
| ------ | --------------------- | ----- | ----------------------------------------------------------------------------------- |
| `GET`  | `/health`             | no    | The process is up                                                                   |
| `GET`  | `/ready`              | no    | Configuration loaded and the registry sealed; reports the mode and the actions      |
| `POST` | `/v1/actions`         | yes   | Capture, evaluate, and in enforcement execute once on an `ALLOW`                    |
| `POST` | `/v1/reconciliations` | yes   | Read-only: what the provider did with an attempt whose answer was lost              |
| `POST` | `/v1/escalations`     | yes   | Resume an open escalation: one lookup, then a fresh decision if the person answered |

The caller presents the caller token as `Authorization: Bearer <token>`; it is compared in constant
time against a digest and never logged. Bodies are JSON, at most 100 KiB, and a refusal is a status
and a stable code with nothing from the request echoed back. Every response, refusals included,
carries `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`,
`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`.

### `POST /v1/actions`

```json
{
  "proposal": {
    "action": "forward_request",
    "target": "payout:synthetic-beneficiary-1",
    "parameters": { "amountMinor": 5000, "currency": "USD" }
  },
  "idempotency_key": "payout-1-v1",
  "correlation_id": "synthetic-run-1"
}
```

`proposal` is the agent's part and nothing else. Tenant, actor, downstream target and credentials
come from the executor's configuration, and a request that tries to supply them is refused by the
strict schema (`400 REQUEST_INVALID`). The idempotency key and correlation id are the caller's,
derived from its own record of the work. An action the process has not registered is refused before
any authority is asked (`422 ACTION_NOT_REGISTERED`): no dossier and no grant for something that
could never execute.

The answer, in enforcement:

```json
{
  "mode": "ENFORCEMENT",
  "intent_id": "…",
  "intent_hash": "sha256:…",
  "verdict": "ALLOW",
  "decision_id": "…",
  "dossier_id": "…",
  "reason_codes": [],
  "fail_closed": false,
  "outcome": "COMPLETED",
  "executed": true,
  "authorization": { "decision_id": "…", "dossier_id": "…", "grant_id": "…", "expires_at": "…" },
  "finalization": "RECORDED",
  "result": { "status": 202, "accepted": true },
  "recovery": null
}
```

`outcome` is one of the executor's four
([execution outcomes](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/execution-outcomes.md)):
`COMPLETED`, `BLOCKED`, `FAILED_BEFORE_DISPATCH`, `UNKNOWN_AFTER_DISPATCH`, or `ESCALATE_PENDING`
while a person has yet to answer. A `BLOCK` comes back with `executed: false`, no `authorization`,
and the reason codes. An `ESCALATE` comes back the same way, plus an `escalation` object when the
executor is configured to resolve one (below); with `EXECUTOR_ESCALATION=NONE` the hold is the
answer. `authorization` is the consumed binding, kept as evidence; the grant token itself never
leaves the process.

In shadow, `mode` is `SHADOW`, `outcome` is the observation status (`OBSERVED`, `UNAVAILABLE`,
`TIMED_OUT`, `INVALID`), `executed` is always `false`, and `authorization` is always `null`. The
production action, if there is one, runs in the caller as it did before
([shadow mode](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/shadow-mode.md)).

### `POST /v1/reconciliations`

When a provider took the request and the response was lost, the answer is `UNKNOWN_AFTER_DISPATCH`
with `executed: null` and a `recovery` object: the exact intent and the recovery reference. Present
that object back, unchanged, and the executor asks the provider what it did with the idempotency
key, never sending the request again. The intent is re-hashed on the way in, so a changed intent no
longer matches its reference and is refused with `RECOVERY_BINDING_MISMATCH`. The process keeps no
state between the two calls.

### `POST /v1/escalations`

An `ESCALATE` means a named person has to approve this exact intent. The executor resolves it in
one of two shapes, chosen by `EXECUTOR_ESCALATION`; both are stateless on this side, and in both the
authority decides again with the person's answer as evidence before any grant exists:

| Shape     | Who talks to Presence                                                                                  | What the caller is handed                                                   |
| --------- | ------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------- |
| `DIRECT`  | This process, holding the Presence credential; the request is bound to the intent hash the person sees | `{ mode: "DIRECT", intent, request_id, approval_url, expires_at }`          |
| `MANAGED` | The authority; no Presence credential exists in this process                                           | `{ mode: "MANAGED", intent, escalation }`, the authority's escalation state |

The caller presents the `escalation` object back, unchanged, whenever it wants an answer. The
executor makes one bounded lookup: still pending comes back as `ESCALATE_PENDING` with the state to
present next time; an approval goes back to the authority, which evaluates the same intent again
and, on `ALLOW`, the action runs once; a denial, expiry or cancellation is a `BLOCK`. The intent is
re-hashed on the way in, so a receipt or an escalation that belongs to a different intent yields
nothing, and an intent past `EXECUTOR_INTENT_TTL_SECONDS` is refused with `409 INTENT_EXPIRED`: an
approval cannot revive an expired intent. Nothing waits inside a request, and nothing is kept
between two.

## Configuration

Every variable, in one list (`CONFIG_KEYS`). A missing or invalid value is a refusal to start that
names the variable and never its value. Nothing that identifies a tenant, a system, a person or a
network path has a default.

| Variable                                                      | Meaning                                                                                                 |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `EXECUTOR_MODE`                                               | `SHADOW` or `ENFORCEMENT`                                                                               |
| `EXECUTOR_BIND_ADDRESS`, `PORT`                               | Where the listener binds                                                                                |
| `EXECUTOR_TENANT_ID`                                          | The Decionis tenant, a UUID                                                                             |
| `EXECUTOR_ACTOR_ID`, `_TYPE`                                  | The actor the intent names; `EXECUTOR_ACTOR_RUNTIME` is optional                                        |
| `EXECUTOR_INTENT_TTL_SECONDS`                                 | How long a proposal stays valid, at most five minutes; a ceremony has to finish inside it               |
| `EXECUTOR_CALLER_TOKEN`                                       | The token the proposing workflow presents; secret                                                       |
| `EXECUTOR_ESCALATION`                                         | `NONE`, `DIRECT` or `MANAGED`; refused in shadow, which never escalates                                 |
| `DECIONIS_API_URL`                                            | The authority, HTTPS                                                                                    |
| `DECIONIS_API_KEY`                                            | The server-side Decionis credential; secret                                                             |
| `DECIONIS_ALLOW_INSECURE_LOOPBACK`                            | `true` permits plain HTTP to loopback for local doubles; refused under `NODE_ENV=production`            |
| `PRESENCE_APPROVER_ID`                                        | The person who must approve (`DIRECT` and `MANAGED`); `PRESENCE_APPROVER_ROLE` is optional in `MANAGED` |
| `PRESENCE_VERIFICATION_LEVEL`, `_METHODS`                     | `STANDARD` or `HIGH_CONFIDENCE`, and a comma-separated list of `WEBAUTHN`, `ACTIVE_LIVENESS`            |
| `PRESENCE_API_URL`, `PRESENCE_API_KEY`                        | `DIRECT` only: the Presence service and its server-side credential; secret                              |
| `PRESENCE_ORGANIZATION`                                       | `DIRECT` only: the requesting party the person sees                                                     |
| `PRESENCE_HARDWARE_PKI_REQUIRED`, `_DISALLOW_VIRTUAL_CAMERAS` | `DIRECT` only: `true` or `false`                                                                        |
| `DOWNSTREAM_URL`                                              | Where the reference handler forwards the verified parameters, HTTPS                                     |
| `DOWNSTREAM_LOOKUP_URL`                                       | Optional read-only lookup for reconciliation; must contain `{idempotency_key}`                          |
| `DOWNSTREAM_SYSTEM`, `_OPERATION`, `_ENVIRONMENT`             | The downstream target the intent names                                                                  |
| `DOWNSTREAM_CREDENTIAL`                                       | The header value the downstream expects, prefix included; secret                                        |
| `DOWNSTREAM_CREDENTIAL_HEADER`                                | The header it goes in                                                                                   |
| `DOWNSTREAM_TIMEOUT_MS`                                       | Finite, at most fifteen seconds                                                                         |

Each secret may be given as the variable or as `<NAME>_FILE`, the path of a mounted file, and never
both. The manifest uses the file form so no value sits in a pod specification.

## The seam

A `HandlerRegistration` receives the registry, the downstream configuration, and the fetch it may
use, registers what this process can run, and returns the action names in the order `/ready`
reports them. The registry is sealed the moment it returns. Keep the shape: a strict parameter
schema, the side effect inside `dispatch.run` so a transport failure after the point of no return
is reported as unknown rather than retried, and a `reconcile` that only reads. The credential is
resolved on this side of the boundary and handed to the handler; the agent never sees it and cannot
name it.

## The image

```bash
docker build -f packages/agentsafe/Dockerfile -t agentsafe .
```

Built from the repository root. The image bakes `NODE_ENV=production`, runs as a non-root user,
holds no configuration, and starts `agentsafe serve` with the reference forwarding handler. The
[deployment kit](https://github.com/decionis/agent-safe-pipeline/blob/master/deploy/README.md) has
the manifest that supplies the configuration, the runbook from shadow to enforcement, and how to
take the image the release workflow publishes and verify it instead of building your own.

## What a green run is not

The proof in the repository runs this package against a loopback authority and a loopback provider
with synthetic policy. It shows the boundary holding in this process on this commit; it is not
evidence that a hosted integration exists, that any provider behaves this way, or that a deployment
has the isolation the threat model asks the host for.

## Support and license

Report suspected vulnerabilities through
[GitHub's private advisory form](https://github.com/decionis/agent-safe-pipeline/security/advisories/new),
not a public issue; the response targets are in
[SECURITY.md](https://github.com/decionis/agent-safe-pipeline/blob/master/SECURITY.md). Questions
and defects go to the
[issue tracker](https://github.com/decionis/agent-safe-pipeline/issues). Apache-2.0; see
[LICENSE](https://github.com/decionis/agent-safe-pipeline/blob/master/LICENSE) and
[NOTICE](https://github.com/decionis/agent-safe-pipeline/blob/master/NOTICE).
