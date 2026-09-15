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

`serve` reads the configuration from the environment, seals the global `fetch`, verifies the host
posture, opens the secrets from their mounted files, restores the evidence chains from the
journal, binds the listener, and on `SIGTERM` closes it and persists the chain heads. A journal
directory it cannot open is also a refusal to start, reported after the posture, because a host
that does not hold its posture is wrong about something more fundamental than a directory and its
refusal names the check; `SIGHUP`
re-reads the secret files, and a rotated TLS key replaces the listener's context in place. A missing or invalid variable, a host that does not hold the posture, or a secret
file another user could read is a refusal to start that names the variable or the check, never a
value. The bin `agentsafe serve` does the same with the reference forwarding handler,
`forwardRequestHandlers()`, which posts the verified parameters to `DOWNSTREAM_URL`;
`agentsafe verify-chain <file>` checks a log's chains offline. To assemble the
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

| Method | Path                         | Who                                 | What it does                                                                        |
| ------ | ---------------------------- | ----------------------------------- | ----------------------------------------------------------------------------------- |
| `GET`  | `/health`                    | anyone                              | The process is up                                                                   |
| `GET`  | `/ready`                     | anyone                              | Configuration loaded and the registry sealed; reports the mode and the actions      |
| `POST` | `/v1/actions`                | a `PROPOSER`                        | Capture, evaluate, and in enforcement execute once on an `ALLOW`                    |
| `POST` | `/v1/reconciliations`        | the `PROPOSER` that proposed        | Read-only: what the provider did with an attempt whose answer was lost              |
| `POST` | `/v1/escalations`            | the `PROPOSER` that proposed        | Resume an open escalation: one lookup, then a fresh decision if the person answered |
| `GET`  | `/v1/control/status`         | an `OPERATOR` with `status`         | Mode, actions, posture, principals, the evidence chain's head, the secrets' names   |
| `POST` | `/v1/control/secrets/reload` | an `OPERATOR` with `secrets.reload` | Re-read every secret file now; the report names files, never values                 |
| `GET`  | `/metrics`                   | an `OPERATOR` with `metrics`        | The OpenMetrics exposition                                                          |

Who may call is the principals file, described below; without one, the one legacy caller presents
the caller token as `Authorization: Bearer <token>`. Every request that is not public passes the
door in one fixed, fail-closed order: the window for failed attempts (`429 RATE_LIMITED`); a
client certificate together with a bearer, which is ambiguous and refused (`401 AUTH_AMBIGUOUS`);
the certificate, by SAN URI and optional pin; the bearer, by digest across every bearer principal
in constant time, then as a workload token; the principal's lock (`423 PRINCIPAL_LOCKED`, only once
the principal is known, so a lock is never an existence oracle); the principal's own window; the
route's role (`403 ROLE_FORBIDDEN`); the route's scope (`403 SCOPE_FORBIDDEN`). A refusal is a
status and a stable code with nothing from the request echoed back, and one `AUTH_FAILED` event
with the method and the code. Bodies are JSON, at most 100 KiB. Every response, refusals included,
carries `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`,
`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`.

### The listener

The listener is TLS: `EXECUTOR_TLS_CERT_FILE` and the `EXECUTOR_TLS_KEY` secret, TLS 1.3 unless
`EXECUTOR_TLS_MIN_VERSION=1.2` admits 1.2 with ECDHE and an AEAD cipher only, no renegotiation,
HTTP/1.1 only. With `EXECUTOR_TLS_CLIENT_CA_FILE` every connection is asked for a client
certificate; the handshake admits a connection without one, deliberately, because the kubelet's
HTTPS probes present none. With a principals file, a certificate is one credential kind among
three and names its principal by SAN URI; without one, every route that is not public requires an
authorized certificate and the caller token together, so a probe reaches `/health` and nothing
else. A rotated key replaces the TLS
context in place; connections already open keep the context they negotiated. Plaintext, for a
developer's machine and the offline proof, needs `EXECUTOR_ALLOW_PLAINTEXT_LISTENER=true` and is
refused under `NODE_ENV=production`. A refusal at the door is recorded on the security stream as
`AUTH_FAILED` with the method, `bearer` or `mtls`, and nothing else.

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

| Variable                                                      | Meaning                                                                                                                    |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `EXECUTOR_MODE`                                               | `SHADOW` or `ENFORCEMENT`                                                                                                  |
| `EXECUTOR_BIND_ADDRESS`, `PORT`                               | Where the listener binds                                                                                                   |
| `EXECUTOR_TENANT_ID`                                          | Legacy mode only: the Decionis tenant, a UUID                                                                              |
| `EXECUTOR_ACTOR_ID`, `_TYPE`                                  | Legacy mode only: the actor the intent names; `EXECUTOR_ACTOR_RUNTIME` is optional                                         |
| `EXECUTOR_INTENT_TTL_SECONDS`                                 | How long a proposal stays valid, at most five minutes; a ceremony has to finish inside it                                  |
| `EXECUTOR_CALLER_TOKEN`                                       | Legacy mode only: the token the one caller presents; secret                                                                |
| `EXECUTOR_PRINCIPALS_FILE`                                    | The principals file; excludes `EXECUTOR_TENANT_ID`, `EXECUTOR_ACTOR_*` and the caller token; required in production        |
| `EXECUTOR_ALLOW_LEGACY_CALLER`                                | `true` lets production run without a principals file, on the legacy caller alone                                           |
| `EXECUTOR_JWT_AUDIENCE`, `EXECUTOR_JWKS_FILE`                 | Together: the audience workload tokens must carry, and the JWKS they are verified against                                  |
| `EXECUTOR_JWKS_URL`, `EXECUTOR_JWKS_CA_FILE`                  | Optional: where the JWKS is refreshed from through the guarded fetch, and the bundle that address is verified against      |
| `EXECUTOR_JWKS_REFRESH_SECONDS`                               | How often, one minute to a day, five minutes by default                                                                    |
| `EXECUTOR_JWT_CLOCK_TOLERANCE_SECONDS`                        | Leeway on a token's times, up to five minutes, thirty seconds by default                                                   |
| `EXECUTOR_RATE_LIMIT_UNAUTHENTICATED`                         | `<count>/<seconds>` for attempts that never became a principal; `20/60` by default                                         |
| `EXECUTOR_AUTH_LOCKOUT`                                       | `<failures>/<seconds>/<lock seconds>` for a principal's proven failures; `10/60/300` by default, `0/…` disables            |
| `EXECUTOR_ESCALATION`                                         | `NONE`, `DIRECT` or `MANAGED`; refused in shadow, which never escalates                                                    |
| `EXECUTOR_POSTURE`                                            | `ENFORCED` (the default) or `DEVELOPMENT`, which waives the host checks and says so; refused under `NODE_ENV=production`   |
| `EXECUTOR_POSTURE_INTERVAL_SECONDS`                           | How often the drift checks repeat while running; ten seconds to ten minutes, sixty by default                              |
| `EXECUTOR_SECRETS_DIR`                                        | The directory every `<NAME>_FILE` must resolve inside; required in production when any file is mounted                     |
| `EXECUTOR_TLS_CERT_FILE`, `EXECUTOR_TLS_KEY`                  | The listener's certificate chain and its private key; the key is a secret, given as `EXECUTOR_TLS_KEY_FILE` in production  |
| `EXECUTOR_TLS_CLIENT_CA_FILE`                                 | Optional: the CA that callers' client certificates chain to; every non-public route then requires one                      |
| `EXECUTOR_TLS_MIN_VERSION`                                    | `1.3` (the default) or `1.2`, which admits TLS 1.2 with AEAD ciphers only                                                  |
| `EXECUTOR_ALLOW_PLAINTEXT_LISTENER`                           | `true` runs the listener without TLS, for a developer's machine; refused under `NODE_ENV=production`                       |
| `EXECUTOR_EGRESS_MAX_RESPONSE_BYTES`                          | The most any outbound response may carry, 1 KiB to 16 MiB, 1 MiB by default                                                |
| `EXECUTOR_JOURNAL_DIR`                                        | Optional: where the evidence chains' heads persist across a restart; absolute, writable by the process                     |
| `EXECUTOR_AUDIT_CHECKPOINT_LINES`                             | How many chained lines between persisted heads, one hundred by default                                                     |
| `DECIONIS_API_URL`                                            | The authority, HTTPS                                                                                                       |
| `DECIONIS_API_KEY`                                            | The server-side Decionis credential; secret                                                                                |
| `DECIONIS_ALLOW_INSECURE_LOOPBACK`                            | `true` permits plain HTTP to loopback for local doubles; refused under `NODE_ENV=production`                               |
| `DECIONIS_CA_FILE`, `DECIONIS_SPKI_PINS`                      | Optional: the PEM bundle the authority is verified against, and two or more `sha256/<base64>` SPKI pins                    |
| `PRESENCE_APPROVER_ID`                                        | The person who must approve (`DIRECT` and `MANAGED`); `PRESENCE_APPROVER_ROLE` is optional in `MANAGED`                    |
| `PRESENCE_VERIFICATION_LEVEL`, `_METHODS`                     | `STANDARD` or `HIGH_CONFIDENCE`, and a comma-separated list of `WEBAUTHN`, `ACTIVE_LIVENESS`                               |
| `PRESENCE_API_URL`, `PRESENCE_API_KEY`                        | `DIRECT` only: the Presence service and its server-side credential; secret                                                 |
| `PRESENCE_ORGANIZATION`                                       | `DIRECT` only: the requesting party the person sees                                                                        |
| `PRESENCE_CA_FILE`                                            | `DIRECT` only, optional: the PEM bundle the Presence service is verified against                                           |
| `PRESENCE_HARDWARE_PKI_REQUIRED`, `_DISALLOW_VIRTUAL_CAMERAS` | `DIRECT` only: `true` or `false`                                                                                           |
| `DOWNSTREAM_URL`                                              | Where the reference handler forwards the verified parameters, HTTPS                                                        |
| `DOWNSTREAM_LOOKUP_URL`                                       | Optional read-only lookup for reconciliation; must contain `{idempotency_key}`                                             |
| `DOWNSTREAM_SYSTEM`, `_OPERATION`, `_ENVIRONMENT`             | The downstream target the intent names                                                                                     |
| `DOWNSTREAM_CREDENTIAL_KIND`                                  | `STATIC_HEADER` (the default), `PRIVATE_KEY_JWT` or `SIGNED_REQUEST`; the other kinds' keys must be absent                 |
| `DOWNSTREAM_CREDENTIAL`                                       | `STATIC_HEADER`: the header value the downstream expects, prefix included; secret                                          |
| `DOWNSTREAM_CREDENTIAL_HEADER`                                | `STATIC_HEADER`: the header it goes in                                                                                     |
| `DOWNSTREAM_TOKEN_URL`, `DOWNSTREAM_CLIENT_ID`                | `PRIVATE_KEY_JWT`: the token endpoint, HTTPS, and the client id                                                            |
| `DOWNSTREAM_PRIVATE_KEY`                                      | `PRIVATE_KEY_JWT`: the PKCS#8 key the assertion is signed with; secret                                                     |
| `DOWNSTREAM_PRIVATE_KEY_ID`, `_ALGORITHM`                     | `PRIVATE_KEY_JWT`: optional `kid`, and `ES256` (the default) or `PS256`                                                    |
| `DOWNSTREAM_TOKEN_AUDIENCE`, `DOWNSTREAM_TOKEN_SCOPE`         | `PRIVATE_KEY_JWT`: optional assertion audience (the token endpoint by default) and scope                                   |
| `DOWNSTREAM_SIGNING_KEY`, `DOWNSTREAM_SIGNING_KEY_ID`         | `SIGNED_REQUEST`: the Ed25519 PKCS#8 key or the HMAC secret, and the `keyid` the downstream knows it by; the key is secret |
| `DOWNSTREAM_SIGNING_ALGORITHM`                                | `SIGNED_REQUEST`: `ed25519` (the default) or `hmac-sha256`                                                                 |
| `DOWNSTREAM_CA_FILE`, `DOWNSTREAM_SPKI_PINS`                  | Optional: the PEM bundle the downstream is verified against, and two or more `sha256/<base64>` SPKI pins                   |
| `DOWNSTREAM_TIMEOUT_MS`                                       | Finite, at most fifteen seconds                                                                                            |

## Principals

`EXECUTOR_PRINCIPALS_FILE` names every caller: who they are, what role they hold, and how they
prove it. The file is `agent-safe.principals/1`, at most two hundred principals, checked for its
mode and owner like a secret although it holds no secret: a bearer credential is the SHA-256 of
the token, a certificate is named by its SAN URI, a workload token by its issuer and subject.

```json
{
  "version": "agent-safe.principals/1",
  "principals": [
    {
      "id": "treasury-workflow",
      "role": "PROPOSER",
      "tenant_id": "00000000-0000-4000-8000-000000000001",
      "actor": { "id": "synthetic-payout-agent", "type": "AI_AGENT", "runtime": "workflow-runner" },
      "allowed_actions": ["forward_request"],
      "credential": {
        "kind": "WORKLOAD_JWT",
        "issuer": "https://kubernetes.default.svc.cluster.example",
        "subject": "system:serviceaccount:agent-safe-agents:treasury-workflow",
        "required_claims": { "kubernetes.io/namespace": "agent-safe-agents" }
      },
      "rate_limit": "120/60"
    },
    {
      "id": "batch-runner",
      "role": "PROPOSER",
      "tenant_id": "00000000-0000-4000-8000-000000000001",
      "actor": { "id": "synthetic-batch-agent", "type": "AI_AGENT" },
      "allowed_actions": ["forward_request"],
      "credential": { "kind": "BEARER", "token_sha256": "<sha256 of the token, hex>" }
    },
    {
      "id": "ops-oncall",
      "role": "OPERATOR",
      "scopes": ["status", "metrics", "secrets.reload"],
      "credential": { "kind": "MTLS", "san_uri": "spiffe://bank.example/ns/ops/sa/oncall" }
    }
  ]
}
```

A `PROPOSER` carries the tenant and actor its intents name and the actions it may propose; an
`OPERATOR` carries scopes from `halt`, `resume`, `secrets.reload`, `status`, `metrics`,
`evidence`. The tenant and actor come from the principal, never from the request, and the
principal's id travels inside the hashed intent as `context.caller_principal`, so the authority's
policy can see who asked and a reconciliation or a resumption is refused unless the intent
presented is the caller's own (`403 INTENT_PRINCIPAL_MISMATCH`). An action a principal may not
propose is `403 ACTION_NOT_PERMITTED_FOR_PRINCIPAL`, refused before the intent is captured. A
proposer whose id or actor is the configured approver, or whose actor is an operator, is refused
at start or as `422 SEPARATION_OF_DUTIES_VIOLATED`; the authority's maker-checker rule is not
duplicated, only the obvious self-approval shapes are stopped early.

Loading refuses a duplicate id, a credential identity claimed twice
(`PRINCIPALS_CREDENTIAL_SHARED`), an action nobody registered, a workload credential without
`EXECUTOR_JWT_AUDIENCE` and `EXECUTOR_JWKS_FILE`, and a certificate credential without
`EXECUTOR_TLS_CLIENT_CA_FILE`. `BEARER` principals are allowed in production and named on the
security stream at start (`BEARER_PRINCIPAL_CONFIGURED`), because a digest in a file is still a
bearer secret somewhere else.

Workload tokens are verified against the JWKS in `EXECUTOR_JWKS_FILE`, which the platform team
places from the cluster's `/openid/v1/jwks`, optionally refreshed from `EXECUTOR_JWKS_URL`
through the guarded fetch with the last good set kept on any failure. RS256, ES256 and EdDSA only;
`iss`, `sub`, `exp` and `iat` required; at most a day old; the audience must include the
executor's or the one the principal names; `required_claims` must match exactly. Each refusal has
its own code (`JWT_SIGNATURE_INVALID`, `JWT_AUDIENCE_MISMATCH`, `JWT_ISSUER_UNKNOWN`,
`JWT_EXPIRED`, `JWT_ALGORITHM_REFUSED`, `JWT_SUBJECT_UNKNOWN`, `JWT_CLAIM_MISMATCH`). There is no
`jti` cache by design: a projected token is a bearer for its lifetime, a replayed request is
defeated by the idempotency key, the intent hash and the single-use grant, and a signed request
exists for per-request proof.

Failed attempts that never became a principal share one window,
`EXECUTOR_RATE_LIMIT_UNAUTHENTICATED`; a principal whose proven identity keeps failing (a workload
token with the wrong audience or claim, a pinned certificate that does not match) is locked after
`EXECUTOR_AUTH_LOCKOUT` failures, unlocked only by expiry or a restart, and the lock is recorded
as `PRINCIPAL_LOCKED`; a principal's own `rate_limit` bounds what it may send.

Without a principals file the executor runs in legacy mode: one `PROPOSER` named `legacy-caller`
is synthesised from `EXECUTOR_TENANT_ID`, `EXECUTOR_ACTOR_*` and the caller token, allowed every
registered action, with no operator at all, so every control route answers `403`. The security
stream says `LEGACY_PRINCIPAL_MODE` at start, and production refuses it unless
`EXECUTOR_ALLOW_LEGACY_CALLER=true` says so by name.

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

## Downstream credentials

`DOWNSTREAM_CREDENTIAL_KIND` says how this process proves itself to the downstream; a handler asks
the credential for headers before the point of no return and never holds a value of its own.

- `STATIC_HEADER` (the default): the value of `DOWNSTREAM_CREDENTIAL` in
  `DOWNSTREAM_CREDENTIAL_HEADER`, prefix included.
- `PRIVATE_KEY_JWT`: OAuth 2.0 client credentials with a `private_key_jwt` assertion, the FAPI
  baseline. An assertion signed with `DOWNSTREAM_PRIVATE_KEY` (ES256 or PS256, `iss` and `sub` the
  client id, `aud` the token endpoint or `DOWNSTREAM_TOKEN_AUDIENCE`, a fresh `jti`, sixty
  seconds of life) is posted to `DOWNSTREAM_TOKEN_URL`, a sealed egress destination under the
  downstream's anchor; the access token is held as a secret handle until thirty seconds before it
  expires, with one refresh in flight at a time. A token that cannot be obtained is a failure
  before dispatch, never an unknown outcome.
- `SIGNED_REQUEST`: an RFC 9421 signature over a fixed set of components with an RFC 9530 content
  digest, Ed25519 or HMAC-SHA256 with `DOWNSTREAM_SIGNING_KEY`, so the downstream can prove that
  this process, holding this key, sent this request for this intent. The handler must send
  `idempotency-key` and `x-agent-safe-intent-hash` with the values it asked the credential to
  sign; the reference handler does.

The keys of the kinds not selected must be absent, and each kind names the one secret it needs. A
downstream verifies a signed request like this:

```text
components  = ("@method" "@path" "content-digest" "idempotency-key" "x-agent-safe-intent-hash")
params      = the text after "agentsafe=" in the signature-input header:
              (components);created=<unix seconds>;keyid="<id>";alg="ed25519"|"hmac-sha256"
base        = '"@method": ' + METHOD                                   + "\n"
            + '"@path": ' + PATH                                       + "\n"
            + '"content-digest": sha-256=:' + base64(sha256(body)) + ':' + "\n"
            + '"idempotency-key": ' + the idempotency-key header       + "\n"
            + '"x-agent-safe-intent-hash": ' + that header             + "\n"
            + '"@signature-params": ' + params
signature   = base64 between the colons after "agentsafe=" in the signature header
accept only if the content-digest matches the body you received,
           created is inside your clock window,
           keyid names a key you issued to the executor,
           and verify(alg, key, base, signature) holds
```

`SignedRequestCredential.verify` in this package is that procedure, for tests and for a downstream
written in TypeScript.

## Egress

Every connection this process opens, to the authority, to the Presence service when it holds
that credential, to the downstream and its lookup, goes through one guarded fetch. Its policy is
sealed from the configuration: the origin and path prefix of each address the configuration
names, and nothing else, each with the trust anchor declared for it (`DECIONIS_CA_FILE`,
`PRESENCE_CA_FILE`, `DOWNSTREAM_CA_FILE`, or the platform's store when none is) and, for the
authority and the downstream, optional SPKI pins that any certificate in the chain may satisfy. A
request to any other origin, to a path outside the prefix, over plain HTTP anywhere but loopback,
or with credentials in the URL is refused before a socket exists. A name is resolved once and
refused if it answers with this host, the link-local range, multicast, or nowhere; private ranges
are allowed, because that is where an institution's systems live. TLS is 1.2 or later against the
destination's anchor, with hostname verification and the pins; a redirect is never followed, and
one that leaves the origin is reported; the body is read whole under
`EXECUTOR_EGRESS_MAX_RESPONSE_BYTES` and returned as a standard `Response`, which is what the gate,
the verifier, the Presence transport and the handlers take from a fetch. Every refusal is
`EGRESS_REFUSED` on the security stream with the origin and a code, `EGRESS_ORIGIN_NOT_ALLOWED`,
`EGRESS_SCHEME_NOT_ALLOWED`, `EGRESS_PATH_NOT_ALLOWED`, `EGRESS_ADDRESS_REFUSED`,
`EGRESS_TLS_REJECTED`, `EGRESS_TLS_PIN_MISMATCH`, `EGRESS_BODY_TOO_LARGE`, `EGRESS_TIMEOUT`,
`EGRESS_REDIRECT_REFUSED`, `EGRESS_RESPONSE_INVALID` or `EGRESS_INIT_UNSUPPORTED`, and is counted.

Three layers hold this: the wiring, which hands the guarded fetch to every component and to the
handler seam; the global `fetch`, which `serve` replaces at start with one that refuses and makes
unassignable, and whose absence is the posture check `GLOBAL_FETCH_UNLOCKED`; and a lint rule in
the repository that confines socket modules to the two directories that may open one, which is a
review control and said so. None of them binds the agent: the network policy in the deployment kit
is what keeps the agent from the downstream.

## Host posture

A process cannot create its own isolation. What it can do is verify the posture it is able to
observe and refuse to run without it, so that a deployment which skipped a control finds out at
start rather than at an incident. Under `EXECUTOR_POSTURE=ENFORCED`, the default, every check
below must hold or the process exits with `REFUSED_TO_START` naming the check; a subset is
repeated every `EXECUTOR_POSTURE_INTERVAL_SECONDS`, and a regression while running is
`POSTURE_DRIFT`, during which new enforcement work is refused with `503 POSTURE_DEGRADED` until the
host recovers (`POSTURE_RESTORED`).

| Check                                                                                             | What refuses                                                                                                   |
| ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `ROOT_UID`                                                                                        | The effective user is root                                                                                     |
| `ROOT_WRITABLE`, `CWD_WRITABLE`                                                                   | The root filesystem or the working directory is writable                                                       |
| `SA_TOKEN_PRESENT`                                                                                | A Kubernetes service-account token is mounted                                                                  |
| `NODE_ENV`                                                                                        | `NODE_ENV` is not `production`                                                                                 |
| `PROXY_ENV`                                                                                       | Any `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` or `NODE_USE_ENV_PROXY` is set                        |
| `NODE_OPTIONS`, `EXTRA_CA`, `KEYLOG`                                                              | `NODE_OPTIONS`, `NODE_EXTRA_CA_CERTS` or `SSLKEYLOGFILE` is set                                                |
| `TLS_REJECT_DISABLED`                                                                             | `NODE_TLS_REJECT_UNAUTHORIZED=0`                                                                               |
| `INSPECTOR_ACTIVE`                                                                                | The inspector is listening                                                                                     |
| `SECRET_IN_ENV`                                                                                   | A secret was given as a variable in production                                                                 |
| `SECRET_FILE_OUTSIDE_DIR`, `SECRET_FILE_MODE`, `SECRET_FILE_OWNER`                                | A secret file resolves outside `EXECUTOR_SECRETS_DIR`, or another user could read it                           |
| `PERMISSION_MODEL_ABSENT`, `PERMISSION_FS_WRITE`, `PERMISSION_CHILD_PROCESS`, `PERMISSION_WORKER` | Node's permission model is off, or allows writes outside the journal directory, child processes, or workers    |
| `GLOBAL_FETCH_UNLOCKED`                                                                           | The global `fetch` is not the refusing stub `serve` installs, so code could reach the network around the guard |
| `PRINCIPALS_FILE_MODE`, `PRINCIPALS_FILE_OWNER`                                                   | The principals file is not a regular file another user could not write, or is owned by someone else            |

`EXECUTOR_POSTURE=DEVELOPMENT`, for a developer's machine and the offline proof, waives the
host-specific checks, the fetch lock among them because a test process is its own client, and
records each waiver as `POSTURE_WAIVED` on the security stream. It never waives `ROOT_UID`,
`SA_TOKEN_PRESENT`, or `TLS_REJECT_DISABLED`, and it is refused under `NODE_ENV=production`. The checks say what the process can see; the container runtime, Pod
Security Admission, and the network policy in the
[deployment kit](https://github.com/decionis/agent-safe-pipeline/blob/master/deploy/README.md)
are what make the posture true.

## Evidence and metrics

The process writes two chained streams: the evidence stream on standard output,
`agent-safe.executor-evidence/1`, one line per lifecycle event with the pipeline's identifiers,
digests, verdict and reason codes plus the authenticated caller; and the security stream on
standard error, `agent-safe.security/1`, one line per thing that happened to the process. Every
line carries `seq`, `prev_hash` and `hash`, so a line altered, removed or reordered after the fact
is detectable by anyone holding the lines. `agentsafe verify-chain <file>` walks a log and exits
non-zero on any break; `verifyAuditChain(lines)` is the same walk as a function. With
`EXECUTOR_JOURNAL_DIR` set, the chain heads persist under it and a restart continues the sequence,
recording `CHAIN_RESUMED`; a crash between two checkpoints leaves a visible sequence gap rather
than a seamless chain. The envelope, the verifier's findings, and what the chain does not prove
are in
[docs/executor-evidence.md](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/executor-evidence.md).

Counters with fixed label names count proposals by verdict, executions by outcome, refusals at
the door by method, egress refusals by code, secret rotations by name, posture drift by check,
redactions, TLS context rotations, chained lines by stream, principals locked, and operator
actions by action. They are rendered as OpenMetrics
text through `executor.metrics.registry.render()` and on `GET /metrics` to an operator with the
`metrics` scope; a proposer is not the party that should read them, and every operator action is
recorded as `OPERATOR_ACTION` with the principal and the action.

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
allowed to read the application and the mounts under `/var/run/agent-safe`, to read and write
`/var/lib/agent-safe` (the evidence chains' journal, which it writes and reads back after a
restart), and to spawn nothing. The image holds no configuration and starts
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
