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

const handlers: HandlerRegistration = ({ registry, downstream, credential, fetch }) => {
  registry.register("create_payout", {
    parametersSchema: JsonObjectSchema,
    execute: ({ intent, parameters, authorization, dispatch }) =>
      dispatch.run(async (idempotencyKey) => {
        const body = JSON.stringify(parameters);
        // The credential resolves the current secret for this request only;
        // the handler never holds a value of its own.
        const headers = await credential.headersFor({
          method: "POST",
          url: downstream.url,
          body,
          idempotencyKey,
          intentHash: intent.intentHash,
        });
        // The provider side effect, and nothing else, goes here.
        const response = await fetch(downstream.url, {
          method: "POST",
          headers: {
            ...headers,
            "idempotency-key": idempotencyKey,
            "x-agent-safe-dossier-id": authorization.dossierId,
          },
          body,
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

`serve` reads the configuration from the environment, verifies the host posture, opens the secrets
from their mounted files, binds the listener, and closes it on `SIGTERM`; `SIGHUP` re-reads the
secret files. A missing or invalid variable, a host that does not hold the posture, or a secret
file another user could read is a refusal to start that names the variable or the check, never a
value. The bin `agentsafe serve` does the same with the reference forwarding handler,
`forwardRequestHandlers()`, which posts the verified parameters to `DOWNSTREAM_URL`. To assemble the
executor without a process around it, `createTrustedExecutor({ config, secrets, handlers })`
verifies the posture, returns the service and a `listen`/`close` pair, and owns the secret store
from then on; the offline proof in the repository does exactly that against loopback doubles.

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

| Variable                                                      | Meaning                                                                                                                  |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `EXECUTOR_MODE`                                               | `SHADOW` or `ENFORCEMENT`                                                                                                |
| `EXECUTOR_BIND_ADDRESS`, `PORT`                               | Where the listener binds                                                                                                 |
| `EXECUTOR_TENANT_ID`                                          | The Decionis tenant, a UUID                                                                                              |
| `EXECUTOR_ACTOR_ID`, `_TYPE`                                  | The actor the intent names; `EXECUTOR_ACTOR_RUNTIME` is optional                                                         |
| `EXECUTOR_INTENT_TTL_SECONDS`                                 | How long a proposal stays valid, at most five minutes; a ceremony has to finish inside it                                |
| `EXECUTOR_CALLER_TOKEN`                                       | The token the proposing workflow presents; secret                                                                        |
| `EXECUTOR_ESCALATION`                                         | `NONE`, `DIRECT` or `MANAGED`; refused in shadow, which never escalates                                                  |
| `EXECUTOR_POSTURE`                                            | `ENFORCED` (the default) or `DEVELOPMENT`, which waives the host checks and says so; refused under `NODE_ENV=production` |
| `EXECUTOR_POSTURE_INTERVAL_SECONDS`                           | How often the drift checks repeat while running; ten seconds to ten minutes, sixty by default                            |
| `EXECUTOR_SECRETS_DIR`                                        | The directory every `<NAME>_FILE` must resolve inside; required in production when any file is mounted                   |
| `DECIONIS_API_URL`                                            | The authority, HTTPS                                                                                                     |
| `DECIONIS_API_KEY`                                            | The server-side Decionis credential; secret                                                                              |
| `DECIONIS_ALLOW_INSECURE_LOOPBACK`                            | `true` permits plain HTTP to loopback for local doubles; refused under `NODE_ENV=production`                             |
| `PRESENCE_APPROVER_ID`                                        | The person who must approve (`DIRECT` and `MANAGED`); `PRESENCE_APPROVER_ROLE` is optional in `MANAGED`                  |
| `PRESENCE_VERIFICATION_LEVEL`, `_METHODS`                     | `STANDARD` or `HIGH_CONFIDENCE`, and a comma-separated list of `WEBAUTHN`, `ACTIVE_LIVENESS`                             |
| `PRESENCE_API_URL`, `PRESENCE_API_KEY`                        | `DIRECT` only: the Presence service and its server-side credential; secret                                               |
| `PRESENCE_ORGANIZATION`                                       | `DIRECT` only: the requesting party the person sees                                                                      |
| `PRESENCE_HARDWARE_PKI_REQUIRED`, `_DISALLOW_VIRTUAL_CAMERAS` | `DIRECT` only: `true` or `false`                                                                                         |
| `DOWNSTREAM_URL`                                              | Where the reference handler forwards the verified parameters, HTTPS                                                      |
| `DOWNSTREAM_LOOKUP_URL`                                       | Optional read-only lookup for reconciliation; must contain `{idempotency_key}`                                           |
| `DOWNSTREAM_SYSTEM`, `_OPERATION`, `_ENVIRONMENT`             | The downstream target the intent names                                                                                   |
| `DOWNSTREAM_CREDENTIAL`                                       | The header value the downstream expects, prefix included; secret                                                         |
| `DOWNSTREAM_CREDENTIAL_HEADER`                                | The header it goes in                                                                                                    |
| `DOWNSTREAM_TIMEOUT_MS`                                       | Finite, at most fifteen seconds                                                                                          |

## Secrets

Each secret is given as `<NAME>_FILE`, the path of a mounted file, or outside production as the
variable `<NAME>`; never both, and in production only the file, because a file is the one shape
whose permissions and rotation this process can verify. A secret file must be a regular file,
inside `EXECUTOR_SECRETS_DIR`, and either private to the process's user or owned by root and
readable by the process's group alone, which is how a Kubernetes Secret volume mounts with
`fsGroup` set; anything else is a refusal that names the variable.

Secrets are read into handles that hand the value out only for the duration of a request and zero
it on disposal; a handle never becomes a string by `toString`, `toJSON`, or `util.inspect`. The
mount directory is watched and polled: a changed file becomes current atomically, the clients that
took a credential at construction (the gate, the verifier, the Presence client) are rebuilt as one
set, the old handle is zeroed after a grace, and the security stream records `SECRET_ROTATED` with
the name. A file that fails its checks on reload is refused with `SECRET_RELOAD_REFUSED` and the
previous value stays current. A rotated caller token admits the new value from the next request
and refuses the old one.

Every line that leaves the process passes a redactor that holds no secret value, only the digests
of the current secrets: a whole value that reaches a line is recognised by hashing the line's
tokens, and a bearer credential, a PEM block, a compact JWS, or the configured downstream header is
recognised by shape. A redaction is reported as `LEAK_SUSPECTED` on the security stream and never
stops the line.

Where the value comes from is yours: a Kubernetes Secret, the Secrets Store CSI driver in front of
a cloud KMS or Vault, or External Secrets. Each lands the credential as a file this process reads
and follows; none of them is integrated here, and an HSM-resident signing key that must never leave
its device needs a signing sidecar this package does not provide.

## Host posture

A process cannot create its own isolation. What it can do is verify the posture it is able to
observe and refuse to run without it, so that a deployment which skipped a control finds out at
start rather than at an incident. Under `EXECUTOR_POSTURE=ENFORCED`, the default, every check
below must hold or the process exits with `REFUSED_TO_START` naming the check; a subset is
repeated every `EXECUTOR_POSTURE_INTERVAL_SECONDS`, and a regression while running is
`POSTURE_DRIFT`, during which new enforcement work is refused with `503 POSTURE_DEGRADED` until the
host recovers (`POSTURE_RESTORED`).

| Check                                                                                             | What refuses                                                                                                |
| ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `ROOT_UID`                                                                                        | The effective user is root                                                                                  |
| `ROOT_WRITABLE`, `CWD_WRITABLE`                                                                   | The root filesystem or the working directory is writable                                                    |
| `SA_TOKEN_PRESENT`                                                                                | A Kubernetes service-account token is mounted                                                               |
| `NODE_ENV`                                                                                        | `NODE_ENV` is not `production`                                                                              |
| `PROXY_ENV`                                                                                       | Any `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` or `NODE_USE_ENV_PROXY` is set                     |
| `NODE_OPTIONS`, `EXTRA_CA`, `KEYLOG`                                                              | `NODE_OPTIONS`, `NODE_EXTRA_CA_CERTS` or `SSLKEYLOGFILE` is set                                             |
| `TLS_REJECT_DISABLED`                                                                             | `NODE_TLS_REJECT_UNAUTHORIZED=0`                                                                            |
| `INSPECTOR_ACTIVE`                                                                                | The inspector is listening                                                                                  |
| `SECRET_IN_ENV`                                                                                   | A secret was given as a variable in production                                                              |
| `SECRET_FILE_OUTSIDE_DIR`, `SECRET_FILE_MODE`, `SECRET_FILE_OWNER`                                | A secret file resolves outside `EXECUTOR_SECRETS_DIR`, or another user could read it                        |
| `PERMISSION_MODEL_ABSENT`, `PERMISSION_FS_WRITE`, `PERMISSION_CHILD_PROCESS`, `PERMISSION_WORKER` | Node's permission model is off, or allows writes outside the journal directory, child processes, or workers |

`EXECUTOR_POSTURE=DEVELOPMENT`, for a developer's machine and the offline proof, waives the
host-specific checks and records each waiver as `POSTURE_WAIVED` on the security stream. It never
waives `ROOT_UID`, `SA_TOKEN_PRESENT`, or `TLS_REJECT_DISABLED`, and it is refused under
`NODE_ENV=production`. The checks say what the process can see; the container runtime, Pod
Security Admission, and the network policy in the
[deployment kit](https://github.com/decionis/agent-safe-pipeline/blob/master/deploy/README.md)
are what make the posture true.

## The seam

A `HandlerRegistration` receives the registry, the downstream configuration, the credential that
proves this process to the downstream, and the fetch it may use, registers what this process can
run, and returns the action names in the order `/ready` reports them. The registry is sealed the
moment it returns. Keep the shape: a strict parameter schema, the side effect inside
`dispatch.run` so a transport failure after the point of no return is reported as unknown rather
than retried, and a `reconcile` that only reads. The credential is resolved on this side of the
boundary at the moment of dispatch and handed to the handler as headers; the agent never sees it
and cannot name it.

## The image

```bash
docker build -f packages/agentsafe/Dockerfile -t agentsafe .
```

Built from the repository root. The runtime is distroless: no shell, no package manager, the
`nonroot` user, `NODE_ENV=production` baked in, and node started under its permission model,
allowed to read the application and the mounts under `/var/run/agent-safe`, to write only under
`/var/lib/agent-safe`, and to spawn nothing. The image holds no configuration and starts
`agentsafe serve` with the reference forwarding handler. The
[deployment kit](https://github.com/decionis/agent-safe-pipeline/blob/master/deploy/README.md) has
the manifest that supplies the configuration and the posture, the runbook from shadow to
enforcement, and how to take the image the release workflow publishes and verify it instead of
building your own.

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
