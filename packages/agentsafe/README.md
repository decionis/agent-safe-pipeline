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

## The gateway

The same runtime is also an HTTP-interception gateway: put it in front of an agent, an API or a
service, and every `POST`, `PUT`, `PATCH` and `DELETE` that passes through it is captured as an
intent, decided by the authority, and forwarded byte for byte only on an `ALLOW`, once, under a
claimed single-use grant. A `BLOCK` is refused, an `ESCALATE` is held, and an authority that
cannot be reached is its own state, never a verdict.

```bash
npm install -g @decionis/agentsafe
agentsafe proxy --upstream http://localhost:3000 --port 8080
```

Without a Decionis key that runs a local demo authority in the same process, on loopback, with a
synthetic policy, and says so on every line. With `DECIONIS_API_KEY` and `DECIONIS_TENANT_ID` (or
`agentsafe login`) it asks Decionis, in shadow first. `agentsafe init` writes the configuration
file, `agentsafe doctor` checks the binary, the configuration, the upstream, Decionis and the
credentials, `agentsafe config` prints what resolved and from where, and `agentsafe status` asks
a running gateway what it is doing. The five-minute path is
[docs/quickstart](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/quickstart/README.md);
what is intercepted, bound and forwarded is
[docs/gateway/http-interception.md](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/gateway/http-interception.md);
every command, key and variable is under
[docs/reference](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/reference/cli.md).

The rest of this README is the proposal executor, `agentsafe serve`: the same lifecycle behind an
envelope ingress with principals, a downstream credential and a verified host posture, for a
deployment that holds the boundary as a bank does.

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
`agentsafe verify chain <file>` (also `verify-chain`) checks a log's chains offline. To assemble the
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

| Method | Path                          | Who                                 | What it does                                                                               |
| ------ | ----------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------ |
| `GET`  | `/health`                     | anyone                              | The process is up                                                                          |
| `GET`  | `/ready`                      | anyone                              | Ready, or 503 while halted or still resolving an attempt; reports the mode and the actions |
| `POST` | `/v1/actions`                 | a `PROPOSER`                        | Capture, evaluate, and in enforcement execute once on an `ALLOW`                           |
| `POST` | `/v1/reconciliations`         | the `PROPOSER` that proposed        | Read-only: what the provider did with an attempt whose answer was lost                     |
| `POST` | `/v1/escalations`             | the `PROPOSER` that proposed        | Resume an open escalation: one lookup, then a fresh decision if the person answered        |
| `GET`  | `/v1/control/status`          | an `OPERATOR` with `status`         | Mode, actions, posture, principals, the chain's head, the halt, the open attempts          |
| `POST` | `/v1/control/halt`            | an `OPERATOR` with `halt`           | Stop taking new work, with a reason                                                        |
| `POST` | `/v1/control/resume`          | an `OPERATOR` with `resume`         | Take work again, with a reason; refused while the cause of the halt stands                 |
| `GET`  | `/v1/control/open-attempts`   | an `OPERATOR` with `status`         | The attempts whose outcome this process does not know                                      |
| `POST` | `/v1/control/secrets/reload`  | an `OPERATOR` with `secrets.reload` | Re-read every secret file now; the report names files, never values                        |
| `POST` | `/v1/control/evidence-export` | an `OPERATOR` with `evidence`       | Write a bundle of this process's own evidence, and return its manifest                     |
| `GET`  | `/metrics`                    | an `OPERATOR` with `metrics`        | The OpenMetrics exposition                                                                 |

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
  "effect": null,
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

A provider that was reached and refused deterministically comes back as `DEFINITELY_NOT_EXECUTED`
with `executed: false`, its own reason among the reason codes, and no `effect` block: a handler
that throws returns no result to read one from. The observation is not lost — the adapter registers
it before throwing, so the authority receives the effect evidence with the finalization, and the
security stream carries `PROVIDER_REFUSED`.

`effect` is what the adapter observed, for a family that has an effect plane: the outcome, the
confirmation, the comparison against what was authorised, the fields that differ, the observation
method, both effect digests, the response digest, the provider's reference, and the digest of the
record itself. It is `null` for an action with no adapter, and it never carries a provider body, a
parameter, or a credential. An observed effect that is not the authorised one leaves `outcome` at
`COMPLETED`, because the handler returned, and says the rest in this block with `EFFECT_MISMATCH`
among the reason codes; what the executor then does about it is
`EXECUTOR_ON_EFFECT_MISMATCH`. The states and the mismatch behaviour are in
[execution outcomes](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/execution-outcomes.md).

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
| `EXECUTOR_JOURNAL_DIR`                                        | Where the evidence chains' heads and the attempt journal live; absolute, writable, required in enforcement                 |
| `EXECUTOR_JOURNAL_REQUIRED`                                   | `false` lets enforcement run without a journal, for a developer's machine; refused under `NODE_ENV=production`             |
| `EXECUTOR_JOURNAL_RETAIN_DAYS`                                | How many days of attempt files a restart reads back, one to a year, seven by default                                       |
| `EXECUTOR_READY_REQUIRES_NO_UNKNOWN_ATTEMPTS`                 | `true` keeps `/ready` at 503 while any attempt's outcome is unknown                                                        |
| `EXECUTOR_HALT_FILE`                                          | Optional: a file whose presence halts the executor, watched and polled                                                     |
| `EXECUTOR_HALT_ON_AUTH_FAILURES`                              | `<count>/<seconds>` of door refusals that halt the executor; `50/60` by default                                            |
| `EXECUTOR_HALT_ON_EGRESS_REFUSALS`                            | `<count>/<seconds>` of refused outbound requests that halt it; `5/60` by default                                           |
| `EXECUTOR_HARD_LIMIT_SINGLE_MINOR`                            | `CHF:2500000000,EUR:1000000`: the most one action may move, per currency, in minor units                                   |
| `EXECUTOR_HARD_LIMIT_WINDOW_SECONDS`                          | The window the count and sum below are measured over; required with either                                                 |
| `EXECUTOR_HARD_LIMIT_WINDOW_COUNT`                            | Optional: the most actions that may execute inside the window                                                              |
| `EXECUTOR_HARD_LIMIT_WINDOW_SUM_MINOR`                        | Optional: the most value that may move inside the window, in minor units                                                   |
| `EXECUTOR_MAX_CLOCK_SKEW_MS`                                  | How far the authority's clock may differ before the executor halts; two seconds by default                                 |
| `EXECUTOR_AUDIT_CHECKPOINT_LINES`                             | How many chained lines between persisted heads, one hundred by default                                                     |
| `EXECUTOR_EVIDENCE_DIR`                                       | Where an operator's evidence bundle is written; exporting is refused with `409` when absent                                |
| `EXECUTOR_EVIDENCE_WINDOW_LINES`                              | Lines of each stream this process keeps for a bundle, 100 to 200000, five thousand by default                              |
| `EXECUTOR_EVIDENCE_SIGNING_KEY`                               | Optional Ed25519 PKCS#8 key that signs a bundle's manifest; secret, and needs an evidence directory                        |
| `EXECUTOR_IMAGE_DIGEST`                                       | What the platform says this deployment is running; carried into a bundle and marked not self-verified                      |
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
| `DOWNSTREAM_LOOKUP_BY_REFERENCE_URL`                          | Optional read-back by the provider's own reference; must contain `{provider_reference}`                                    |
| `BANKING_ADAPTER_ID`, `BANKING_ADAPTER_VERSION`               | The observer identity the effect evidence names; `AGENTSAFE_CORE_BANKING` and `0.1.0` by default                           |
| `EXECUTOR_ON_EFFECT_MISMATCH`                                 | `HALT` (the default) or `ALERT`: what an observed effect that is not the authorised one does                               |

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
as `PRINCIPAL_LOCKED`; a principal's own `rate_limit` bounds what it may send, and a rule that is
not `<count>/<seconds>` is refused at start-up naming the principal by id rather than by its
position in the file.

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
mount directory is watched and polled: a changed file becomes current atomically, the old handle is
zeroed after a grace, and the security stream records `SECRET_ROTATED` with the name. The gate and
the verifier read the authority's credential from the handle at each request, so a rotated file
reaches the next request with nothing rebuilt and a request already in flight keeps the value it
sent. The Presence client is the exception: it takes a string once, from a package this repository
does not own, so a rotated Presence key rebuilds the credential-holding clients as one set and says
so as `AUTHORITY_CLIENTS_REBUILT`. A file that fails its checks on reload is refused with `SECRET_RELOAD_REFUSED` and the
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
- `SIGNED_REQUEST`: an RFC 9421 signature with an RFC 9530 content digest, Ed25519 or HMAC-SHA256
  with `DOWNSTREAM_SIGNING_KEY`. Every request covers the method, the path, the body's digest, the
  idempotency key and the intent hash, so the downstream can prove that this process, holding this
  key, sent this request for this intent. A dispatch also covers `x-agent-safe-grant-id` and
  `x-agent-safe-decision-id`, and, when the authority attested the claim,
  `x-agent-safe-claim-attestation`: the authority's own signed proof that this grant was claimed
  for this intent, which a downstream verifies against the authority's public JWKS. The handler
  must send every covered header with the value it asked the credential to sign; `headersFor`
  returns them beside the signature, and the reference handlers send them.

The three are not equally strong, and the choice decides what an agent that reaches the provider
anyway can do with the path:

| Kind              | What the downstream is shown                                          | What a captured value is worth                                                                    |
| ----------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `STATIC_HEADER`   | A bearer                                                              | Everything, until it is rotated: whoever holds it is the executor                                 |
| `PRIVATE_KEY_JWT` | A bearer minted from a key                                            | The access token until `exp`; the key itself stays in the process                                 |
| `SIGNED_REQUEST`  | A per-request signature, and the authority's attestation of the claim | Nothing. It is bound to this method, path, body, idempotency key, intent hash, grant and decision |

For anything reaching a system of record, `SIGNED_REQUEST` is the one that keeps the boundary when
the network does not: a caller with a perfect route and a copied set of headers still cannot
produce a signature, so the provider can refuse it. With the attestation covered, the provider can
also refuse an instruction the authority never claimed, not merely one the executor never signed:
the signature proves that this process sent this request, and the attestation inside it proves
that the authority claimed this grant for this intent, with a digest of the very parameters the
provider is looking at. See [bypass resistance](../../docs/bypass-resistance.md).

The keys of the kinds not selected must be absent, and each kind names the one secret it needs. A
downstream verifies a signed request like this:

```text
params      = the text after "agentsafe=" in the signature-input header:
              (components);created=<unix seconds>;keyid="<id>";alg="ed25519"|"hmac-sha256"
components  = the quoted names inside the parentheses, in order. Always:
              "@method" "@path" "content-digest" "idempotency-key" "x-agent-safe-intent-hash"
              On a dispatch, also: "x-agent-safe-grant-id" "x-agent-safe-decision-id"
              When the authority attested the claim, also: "x-agent-safe-claim-attestation"
base        = for each component, in that order, one line:
                '"@method": ' + METHOD
                '"@path": ' + PATH
                '"content-digest": sha-256=:' + base64(sha256(body)) + ':'
                '"<header-name>": ' + that header's value, for every other component
              joined by "\n", then
            + "\n" + '"@signature-params": ' + params
signature   = base64 between the colons after "agentsafe=" in the signature header
refuse unless the content-digest matches the body you received,
              every component you require is among the covered ones -- a system of
              record that effects anything requires all eight --
              every covered header is present and equals the value in the base,
              created is inside your clock window,
              keyid names a key you issued to the executor,
              and verify(alg, key, base, signature) holds
then, for anything you will effect, verify the attestation:
              split x-agent-safe-claim-attestation on "." into header, payload, signature
              header.alg is "EdDSA", header.typ is "decionis-claim-attestation+jwt"
              header.kid names a key in the authority's
                GET /.well-known/decionis-execution-grant-jwks.json
              Ed25519-verify(key, header + "." + payload, signature) holds
              payload.sub equals x-agent-safe-grant-id
              payload.decision_id equals x-agent-safe-decision-id
              payload.binding.intent_hash equals x-agent-safe-intent-hash
              payload.binding.execution_payload_digest equals
                "sha256:" + hex(sha256(canonical(body))) under
                payload.binding.execution_payload_canonicalization_profile ("RFC8785/JCS")
              payload.exp has not passed, and payload.sub was not seen within the lease
```

`SignedRequestCredential.verify` in this package is the first half of that procedure, with
`materialFrom` building the material from a received request and `require` naming what the
signature must cover; the offline proof's strict provider double is the whole of it, attestation
included, written against nothing but the authority's public keys.

## The attempt journal

An execution nobody could reconcile afterwards is worse than a refusal. So
before the executor may run an action, the attempt is on disk:

| Record           | When                                                        | What it carries                                                       |
| ---------------- | ----------------------------------------------------------- | --------------------------------------------------------------------- |
| `ATTEMPT_OPENED` | After the authority allows, before the executor runs        | The identifiers, the caller, and the captured intent verbatim         |
| `GRANT_CLAIMED`  | After the grant is consumed, before the provider is touched | The grant, its expiry, and the digest of what is about to be sent     |
| `ATTEMPT_CLOSED` | Once the outcome is known                                   | The outcome, whether it executed, and how the authority was finalized |
| `RECONCILED`     | When a lost outcome is resolved                             | The status, and whether a restart or the caller resolved it           |

The claim is the record that must never be lost: it is written by a decorator
inside the handler, after `SafeExecutor` consumed the grant and before the
handler's own body. A journal that cannot take it throws there, which is
still _before_ dispatch, so the registry reports `FAILED_BEFORE_DISPATCH`,
`SafeExecutor` finalizes the attempt as `FAILED`, and the authority learns
the attempt failed rather than waiting for a lease to lapse. The decorator is
applied by the registry the adopter's registration fills, so an ordinary
handler gets the durable claim without knowing about it.

An outcome that is **unknown** is the one thing that must not be closed: the
attempt stays open, and the next process resolves it. `EXECUTOR_JOURNAL_DIR`
names the directory; under it, `attempts/` holds append-only JSONL, one file
per UTC day, each record flushed to the device before the append returns, the
directory private to the process, a record over 256 KiB refused rather than
truncated. In enforcement a directory is required unless
`EXECUTOR_JOURNAL_REQUIRED=false` says otherwise, which production refuses.

What the journal holds is the request's own parameters, which the evidence
streams never carry, so it is as sensitive as the traffic itself and belongs
on a volume with the same protection. It is per process: a pod that loses its
volume loses its open attempts, which is why the manifest gives each replica
its own claim and why the authority's lease recovery remains the backstop.

## Startup reconciliation

`listen()` resolves what the last process left behind before this one accepts
a connection. Each open attempt's stored intent is re-hashed rather than
trusted, and the provider is asked what it did with that idempotency key
through the handler's read-only `reconcile`. Nothing is ever re-executed:
the reconciler calls the registry's read path, never its execute path.

| Resolution                | What it means                                                                           |
| ------------------------- | --------------------------------------------------------------------------------------- |
| `RECONCILED_COMPLETED`    | The provider says it acted; the attempt is closed                                       |
| `RECONCILED_NOT_EXECUTED` | The provider says it did not; the attempt is closed                                     |
| `STILL_UNKNOWN`           | The provider cannot say; the attempt stays open and the next start asks again           |
| `UNCLAIMED`               | No grant was consumed, so the provider was never reached; the authority's lease owns it |
| `BINDING_MISMATCH`        | The stored intent no longer hashes to its record: a tampered journal, asked nothing     |

`GET /v1/control/open-attempts` lists them, `/ready` reports how many are
unknown, and `EXECUTOR_READY_REQUIRES_NO_UNKNOWN_ATTEMPTS=true` keeps the
process out of a load balancer until none are.

## The halt

The stop is deliberately easy to reach and deliberately hard to leave. An
operator halts with a reason; a file halts by existing; and a posture drift,
a spike of refusals at the door, a spike of refused outbound requests, or a
clock that cannot be trusted halt on their own.

While halted, a proposal or a resumption is refused with `503` in the same
shape the caller already parses (`verdict: BLOCK`, `outcome: BLOCKED`,
`fail_closed: true`, `reason_codes: ["EXECUTOR_HALTED"]`) and a `Retry-After`
of thirty seconds. The refusal is recorded through the audit recorder as
`EXECUTION_BLOCKED`, so a halt is evidence and not just an absence. Nothing
is asked of the authority, so a halted executor costs no dossier and no
grant. What is already in flight finishes and is journaled, because
abandoning a dispatch is how an outcome becomes unknown. `/ready` answers
`503`; `/health` stays `200`, so a halt never becomes a restart loop.

Resuming is an operator's act with a reason, refused with
`409 HALT_CAUSE_PERSISTS` while the halt file is still there or a posture
drift still stands. A process that starts with the halt file present starts
halted. A spike threshold is reachable from the agent zone by design: a
compromised caller that floods the door stops the executor rather than being
ignored, which is the fail-closed choice, and the thresholds are
configurable for institutions that would rather not.

## Host ceilings

`EXECUTOR_HARD_LIMIT_SINGLE_MINOR` is the most one action may move, per ISO
4217 code, in minor units, and the window settings bound how many actions and
how much value pass in a period. They only ever refuse: a policy that would
allow more is still bounded here, and a ceiling can never widen what the
authority narrowed.

The check runs before the authority is asked, so nothing this host would
refuse costs a dossier or a grant, and the commit runs after an `ALLOW` and
before the executor runs, so a refusal consumes no grant and two requests
cannot cross the window by racing. A refusal is `422` with its own code
(`HARD_LIMIT_EXCEEDED`, `HARD_LIMIT_CURRENCY_UNKNOWN`,
`HARD_LIMIT_AMOUNT_INVALID`, `HARD_LIMIT_WINDOW_COUNT_EXCEEDED`,
`HARD_LIMIT_WINDOW_SUM_EXCEEDED`), recorded as evidence and counted.

The amount is read from the intent's own parameters: an integer
`amountMinor` and a three-letter `currency`. An action carrying neither is
not a payment and is bounded by the count window alone; one carrying half of
a value is refused rather than guessed at; a currency the configuration never
named is refused. A banking adapter family will carry its own projection
later; this is the generic one.

The window is process memory. A restart forgets it and two replicas each keep
their own, which is stated plainly because it is why these are a backstop
against a policy mistake, not a treasury control.

## Clocks

A boundary that binds short-lived grants cannot afford to disagree with the
party issuing them: a host running behind would accept a grant the authority
considers expired, and one running ahead would refuse grants that are still
good. So every answer from the authority is measured against this host's
clock, the skew is recorded, and past `EXECUTOR_MAX_CLOCK_SKEW_MS` the
executor halts rather than guess which clock is right. The skew is measured,
never corrected, and the round trip's own latency is inside the measurement,
which is why the bound is seconds rather than milliseconds.

Dispatch deadlines are monotonic and bounded by the authorization: a provider
is never given more time than the grant has left, and correcting the wall
clock cannot extend a call already in flight.

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

## Incident response

Three things are for the moment something has gone wrong.

**The stop**, which is above. Reach for it early: work in flight finishes and is journaled, so a
halt costs the proposals that have not started and nothing else.

**A bundle**, taken from a running process by an operator holding the `evidence` scope:

```bash
curl -sS -X POST https://executor.example:8443/v1/control/evidence-export   -H 'content-type: application/json' -d '{"reason":"on-call took a bundle"}'
```

It writes five files into a directory under `EXECUTOR_EVIDENCE_DIR`, named by the instant so two
exports during one incident do not overwrite each other: both chained streams as this process
still held them, the open attempts, the posture by check, and a manifest that digests every one of
them. The manifest also carries the chain heads, a digest of the non-secret configuration, the
image digest as the platform reported it (marked not self-verified, because a process cannot read
the digest of its own image), and every secret's name with a rotation count.

What is not in it: any secret, any digest of a secret (a low-entropy credential's digest is a
guessable oracle), any request parameter, and any provider body. The attempt journal holds
parameters, so a bundle names attempts by identifier and state and never copies the journal. Take
that from the volume, under the same handling as the traffic, and only when you need it.

**A verifier** that needs nothing from the executor:

```bash
agentsafe verify-bundle ./2026-03-02T10-00-00-000Z
```

It recomputes every file's digest against the manifest, walks both chains, and checks that each
stream's last line is the head the manifest claims. Then it says which of two things it
established:

| It reports               | What that means                                                                     |
| ------------------------ | ----------------------------------------------------------------------------------- |
| `INTERNAL_CONSISTENCY`   | The bundle is the bundle that was made. Nothing here establishes **who** made it    |
| `ORIGIN_AND_CONSISTENCY` | A signature over the manifest verified against a public key **the reader** supplied |

The reader's key comes from `AGENTSAFE_EVIDENCE_PUBLIC_KEY`, never from the bundle: a signature
verified with a key the bundle carried would prove nothing, so the verifier will not do it. Set
`EXECUTOR_EVIDENCE_SIGNING_KEY_FILE` before an incident if you want the second row; afterwards is
too late.

The six playbooks, per incident class, are in
[incident response](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/incident-response.md),
with command-bearing copies under
[`deploy/incident/`](https://github.com/decionis/agent-safe-pipeline/blob/master/deploy/incident)
and alerting rules as data, applied by nothing, in
[`deploy/alerts/TrustedExecutor.yaml`](https://github.com/decionis/agent-safe-pipeline/blob/master/deploy/alerts/TrustedExecutor.yaml).

## The seam

A `HandlerRegistration` receives the registry, the downstream configuration, the credential that
proves this process to the downstream, the fetch it may use, the register where a handler that
observes an effect records what it saw, and the family's own settings, registers what this process
can run, and returns the action names in the order `/ready` reports them. The registry is sealed the
moment it returns. Keep the shape: a strict parameter schema, the side effect inside
`dispatch.run` so a transport failure after the point of no return is reported as unknown rather
than retried, and a `reconcile` that only reads. The credential is resolved on this side of the
boundary at the moment of dispatch and handed to the handler as headers; the agent never sees it
and cannot name it.

## Adapters

An adapter is how a family of consequential actions reaches a provider, and it is deliberately
four small methods, three of them pure:

| Method          | What it does                                                                      |
| --------------- | --------------------------------------------------------------------------------- |
| `prepare`       | Works out what the action asks for and what its effect should be. Reaches nothing |
| `execute`       | Performs the side effect, once, inside the dispatch the pipeline opened           |
| `observeEffect` | Reads what the provider said into the family's projection. Pure                   |
| `reconcile`     | Asks the provider what it did with an idempotency key. Read-only, always          |

`adapterActionHandler` bridges any adapter to the pipeline's `ActionHandler`: prepare, then the
side effect inside `dispatch.run` bounded by the smaller of the timeout and what is left of the
grant, then the observation, then the comparison field by field against what was authorised, then
the record, registered against that exact authorization for the verifier to finalize with. A
provider that neither committed nor refused throws, so the outcome is reported as unknown rather
than guessed. `SafeExecutor` and the pipeline's registry are untouched.

A second family is a new directory beside `banking/`, not a rewrite: the handler bridge, the
comparison, the evidence and the verifier all work off the adapter contract alone.

### The banking family

`bankingHandlers()` registers every action type this build mirrors from the BEAP v0.1 profile,
each bridged to the same adapter over the configured downstream. An action arrives as the
canonical `BankingAction` in the proposal's parameters, and the executor derives the transport's
action name and target from it rather than trusting them; a disagreement is a refusal before the
authority is asked. The amount is read as a `bigint` of minor units at the currency's own ISO 4217
scale, and an `iban:` reference is check-digit validated.

The reference transport maps the provider's answer without inferring anything:

| The provider says                         | This boundary reports                       |
| ----------------------------------------- | ------------------------------------------- |
| 2xx, a status meaning it took the request | Committed, acknowledged, not yet confirmed  |
| 2xx, a status meaning it posted           | Committed, then read back before confirming |
| a deterministic refusal with a body       | Failed; nothing was effected                |
| anything else: no body, a timeout, a 5xx  | Indeterminate, and reconciliation owns it   |

An adopter with their own core replaces the transport and keeps everything else, because the
profile's arithmetic, the projection, the comparison and the evidence belong to the adapter rather
than the transport. What the executor implements of the profile, and what it does not claim, is in
[BEAP conformance](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/beap-conformance.md);
the confirmation states and the mismatch behaviour are in
[execution outcomes](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/execution-outcomes.md).

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
the manifests that supply the configuration, the posture and the two zones' network policies, the
runbook from shadow to enforcement, and how to take the image the release workflow publishes and verify it instead of
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
