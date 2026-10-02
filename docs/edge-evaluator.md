# The edge evaluator

The trusted executor normally asks Decionis about every intent (`POST /v1/authority/enforce-and-bind`).
With the edge evaluator it decides inside the deployment instead: the same binding, evaluated
against a policy bundle Decionis signed, by a WebAssembly build of the Decionis policy core, gives
the same `ALLOW`, `ESCALATE` or `BLOCK` the hosted route gives, with no network call on the way.
Escalations still go to Decionis, so Presence and presence attestations work exactly as they do
hosted.

```text
proposal -> intent -> EdgeDecisionAuthority --ALLOW--> local authorization -> SafeExecutor (once)
                              |  (module + signed bundle, in process)
                              +--BLOCK--> refused
                              +--ESCALATE / no usable bundle--> DecionisGate (enforce-and-bind)
```

## Licensing

The evaluator module is proprietary to Decionis and licensed separately; it is not in this
repository, not in the `@decionis/agentsafe` package and not in the image. What is here is the open
host: `EdgeDecisionAuthority`, the bundle manager and the local authorization verifier in
`@decionis/agent-safe-pipeline`, Apache-2.0 like the rest of the pipeline. Without the module the
executor runs on the hosted authority exactly as before. In edge mode the executor reads the signed
entitlement Decionis issues and reports its edge usage monthly, but only to warn: no licence
condition ever stops, delays or changes a decision, and the host refuses no feature for want of
one ([Entitlement warnings](#entitlement-warnings)). See [OPEN-CORE.md](../OPEN-CORE.md).

## How a bank runs it

1. Obtain the module from Decionis under the edge licence and mount it read-only into the executor
   (for example `/opt/decionis/policy_core_edge.wasm`). The host requires module ABI 3 and refuses
   to start on anything else: a file it cannot read, bytes that are not WebAssembly, an older ABI.
2. Give the executor an organisation API key with `policy:read` (the bundle route) beside the
   scopes it already needs. It is the existing `DECIONIS_API_KEY`; no new secret exists.
3. Configure:

   | Variable                            | Value                                                                      |
   | ----------------------------------- | -------------------------------------------------------------------------- |
   | `EXECUTOR_DECISION_AUTHORITY`       | `edge`                                                                     |
   | `EXECUTOR_EDGE_WASM_PATH`           | the module, an absolute path                                               |
   | `EXECUTOR_EDGE_ORG_ID`              | the Decionis organisation the bundles are issued to                        |
   | `EXECUTOR_EDGE_BUNDLE_SOURCE`       | `url` (default) or `file`                                                  |
   | `EXECUTOR_EDGE_BUNDLE_FILE`         | `file` only: where an operator places the signed bundle                    |
   | `EXECUTOR_EDGE_REFRESH_SECONDS`     | routine refresh, 60 to 86400, 3600 by default                              |
   | `EXECUTOR_EDGE_ON_UNAVAILABLE`      | `hosted` (default) or `block`                                              |
   | `EXECUTOR_EDGE_REPLAY_STORE`        | `memory` (default) or `postgres`: where single use is held                 |
   | `EXECUTOR_EDGE_SINGLE_REPLICA`      | `true`: required with `memory`, the statement that one replica runs        |
   | `EXECUTOR_EDGE_REPLAY_DATABASE_URL` | `postgres` only: the connection string; secret (`_FILE` in production)     |
   | `EXECUTOR_EDGE_REPLAY_TABLE`        | `postgres` only: the claims table, `agentsafe_edge_replay` by default      |
   | `EXECUTOR_EDGE_INSTALLATION_ID`     | the installation a usage report names; generated and kept when absent      |
   | `EXECUTOR_EDGE_USAGE_SIGNING_KEY`   | Ed25519 PKCS#8 key usage reports are signed with; secret                   |
   | `EXECUTOR_EDGE_USAGE_KEY_ID`        | the `kid` it is registered under; the key's RFC 7638 thumbprint by default |
   | `EXECUTOR_EDGE_USAGE_REPORT_DIR`    | `file` only: where signed usage reports are written for upload             |
   | `EXECUTOR_EDGE_ENTITLEMENT_FILE`    | `file` only: the signed entitlement an operator placed                     |
   | `EXECUTOR_EDGE_JWKS_FILE`           | `file` only: the Decionis JWKS pinned to verify it, given with the above   |

   Edge settings without `EXECUTOR_DECISION_AUTHORITY=edge` are refused rather than ignored.

4. Start the executor. It loads the module before it listens, fetches the first bundle when it
   starts listening, and writes `EDGE_BUNDLE_LOADED` (bundle id, policy version, key id, expiry) to
   the security stream.

## What each verdict does

| Local verdict            | What happens                                                                                                                                   |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `ALLOW` (enforcement)    | A local authorization, held in process and consumed once by `SafeExecutor`; no Decionis grant exists, so nothing is claimed or finalized there |
| `BLOCK`                  | Refused, as it would be hosted                                                                                                                 |
| `ESCALATE` (enforcement) | The same intent goes to Decionis (`enforce-and-bind`, with `MANAGED` escalation when configured); the handoff and resumption are hosted        |
| Approval evidence        | Always evaluated hosted                                                                                                                        |
| In `SHADOW`              | The verdict is recorded and returned; nothing is authorized and nothing escalates                                                              |

An intent runs once whichever path allowed it: the local verifier claims the `intent_id` for a
local authorization and for a hosted grant alike, in a store every replica shares when there is
more than one ([Replicas](#replicas-and-the-shared-replay-store)).

## The bundle refresh model

A bundle is a compact JWS Decionis signs over the organisation's active, approved policy bundle,
valid for a window (`nbf` to `exp`, seven days by default). The module verifies the signature
against keys pinned in its release, the audience against `EXECUTOR_EDGE_ORG_ID`, the window against
the time the host supplies, and the bundle against its digest.

- **`url`**: `GET /v1/edge/policy-bundles/current` on `DECIONIS_API_URL`, through the guarded
  fetch, with the organisation's key. Fetched every `EXECUTOR_EDGE_REFRESH_SECONDS`, and earlier
  whenever less than a quarter of the loaded bundle's window remains, but never more often than
  every 30 seconds while that bundle is current.
- **`file`**: for a deployment with no route to Decionis. An operator places the bundle (the JWS on
  its own, or the issuance response as returned) at `EXECUTOR_EDGE_BUNDLE_FILE`; the executor reads
  it at least every ten seconds and loads it when it holds a different bundle.

A new bundle is loaded and verified beside the current one, becomes current in one step, and the
old one is then released from the module. A fetch that fails, or a bundle the module refuses,
leaves the current bundle in place and is retried with backoff (one second, doubling, at most five
minutes and never beyond the routine interval). Each failure is an `EDGE_BUNDLE_REFRESH_FAILED`
line with a code such as `BUNDLE_HTTP_503` or `BUNDLE_SIGNATURE_INVALID`; no URL, header, body or
key is ever logged.

## What happens on expiry

There is no grace period. At the bundle's `exp` the executor releases it (`EDGE_BUNDLE_EXPIRED`)
and decides nothing on it again. Until a fresh bundle loads, every intent follows
`EXECUTOR_EDGE_ON_UNAVAILABLE`:

- `hosted` (default): ask Decionis, exactly as a hosted deployment does;
- `block`: refuse, fail closed, with the reason `EDGE_BUNDLE_UNAVAILABLE`.

The same applies before the first bundle loads, when the module faults, and when its answer cannot
be read. A module that traps is not called again by that process: its memory can no longer be
trusted, so decisions follow `EXECUTOR_EDGE_ON_UNAVAILABLE` until the executor restarts. The edge
never allows without a valid bundle. A local authorization never outlives the intent or the bundle
it was decided on.

## Evidence

Every local decision is a line on the executor's hash-chained evidence stream
(`agent-safe.executor-evidence/1`), beside the lifecycle lines `SafeExecutor` writes:

| Event                      | Fields                                                                                                                                                      |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EDGE_DECISION`            | `mode`, `intent_id`, `intent_hash`, `decision_id`, `verdict`, `reason_codes`, `policy_version`, `bundle_id`, `kid`, `jti`, `evaluation_digest`, `delegated` |
| `EDGE_UNAVAILABLE`         | `mode`, `intent_id`, `intent_hash`, `reason`, `module_code`, `fallback` (`HOSTED` or `BLOCK`)                                                               |
| `EDGE_EXECUTION_FINALIZED` | `intent_id`, `intent_hash`, `decision_id`, `outcome`: a local attempt's commit outcome, which has no hosted dossier to join                                 |

No line carries a parameter, an amount, an account or any other value from the intent: the same
identifiers and digests the hosted record carries, and nothing more. A decision that cannot be
recorded is not made (`EDGE_RECORD_UNAVAILABLE`). These lines are what edge usage is counted from.

## Replicas and the shared replay store

A local authorization is consumed once, and so is every intent: the local verifier claims the
`intent_id` in a `ReplayStore` before it lets the executor run, for a local authorization and for a
hosted grant alike, and the edge authority asks the same store before it decides, so an intent that
has already run is refused (`INTENT_ALREADY_CONSUMED`) without being decided or counted again.

Where the store lives decides how far "once" reaches:

- **`memory`** (the default) holds claims in the process. It is right for exactly one replica, and
  the executor says so by refusing to start with it unless `EXECUTOR_EDGE_SINGLE_REPLICA=true`
  (`CONFIG_INVALID: EXECUTOR_EDGE_REPLAY_STORE`).
- **`postgres`** is shared by every replica: a claim is one row, unique on `(namespace, intent_id)`
  (the namespace is `EXECUTOR_EDGE_ORG_ID`), inserted with `ON CONFLICT DO NOTHING`, so of two
  replicas that decided the same intent the database lets one run it. Several replicas need it.

The operator creates the table once, before the first replica starts; the executor never creates
or alters it, and its database role needs `SELECT`, `INSERT` and `DELETE` on that table and nothing
else. `agentsafe edge replay-schema [--table <name>]` prints the DDL:

```sql
CREATE TABLE IF NOT EXISTS agentsafe_edge_replay (
  namespace text NOT NULL,
  intent_id text NOT NULL,
  expires_at timestamptz NOT NULL,
  claimed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (namespace, intent_id)
);
CREATE INDEX IF NOT EXISTS agentsafe_edge_replay_expires_at ON agentsafe_edge_replay (expires_at);
```

The connection string is a secret like any other (`EXECUTOR_EDGE_REPLAY_DATABASE_URL_FILE` in
production; TLS through the URL's `sslmode`). The connection is direct TCP from the executor, not
through the guarded HTTP fetch, so the network policy must allow it. At start the executor probes
the table and refuses to start when it cannot (`REPLAY_STORE_UNAVAILABLE`), since nothing could then
be run once. Every hour it deletes claims that lapsed more than a day ago; a row is never claimable
again while it exists, so the store is never weaker than the in-memory one. The `pg` driver is an
optional dependency of `@decionis/agentsafe`, present in the npm install and the image and loaded
only when this store is configured; the single-file executable does not carry it
(`REPLAY_DRIVER_MISSING`), so a replicated deployment runs the image or the npm package.

## Usage reports

The governed action is the single meter everywhere, edge decisions included. Each installation
counts its `EDGE_DECISION` lines per UTC calendar month and reports them to Decionis in a signed
usage report; Decionis adds `total - delegated` to the organisation's usage for the month through
the same metering hosted actions use (a delegated decision is an `ESCALATE` Decionis decided and
already metered).

- **What is counted.** Every `EDGE_DECISION` line whose `at` falls in the month, by `mode` and by
  `verdict`, the delegated ones also counted apart, and the `jti` of every bundle decided on. An
  `EDGE_UNAVAILABLE` line is not a decision and is not counted.
- **The range.** The report names the evidence chain it was counted from (`stream`) and the first
  and last counted line (`first_seq`, `first_hash`, `last_seq`, `last_hash`), all null in a month
  with no decision. Anyone holding the collected log can recount it.
- **The installation.** One evidence chain. `EXECUTOR_EDGE_INSTALLATION_ID` names it; without it the
  executor generates `inst_<uuid>` and keeps it in `<EXECUTOR_JOURNAL_DIR>/edge/usage.json` beside
  the tally, which persists with the chain's head (at the journal's cadence and on stop) so the count
  resumes exactly where the chain does. With several replicas each has its own installation id (in
  Kubernetes, a StatefulSet's pod name with its journal volume). A tally whose head is not the
  chain's restored head belongs to a chain that is gone; it is dropped with `EDGE_USAGE_TALLY_RESET`
  and that month is recounted from the log.
- **The key.** `EXECUTOR_EDGE_USAGE_SIGNING_KEY` (Ed25519, PKCS#8). The executor logs
  `EDGE_USAGE_KEY_LOADED` with its `kid` at start; `agentsafe edge usage-key` prints the `kid`, the
  public JWK and the body to register it with `POST /v1/execution/provider-keys` as a
  `usage_report` key whose `issuer` is the installation id.
- **When.** Within the hour after a month ends, and every hour until delivered: `url` deployments
  `POST /v1/edge/usage-reports` (`{"report": "<compact JWS>"}`, the organisation's key; a
  `USAGE_REPORT_DUPLICATE` conflict, Decionis already holding the month at the same or a later
  chain position, counts as delivered, and any other refusal is logged by its code, such as
  `USAGE_REPORT_KEY_UNKNOWN` for a key not yet registered); `file` deployments write
  `usage-<YYYY-MM>-<installation>.jws` to `EXECUTOR_EDGE_USAGE_REPORT_DIR` for an operator to upload.
  A month with no decision is still reported, so a quiet installation is never overdue. Each
  delivery is an `EDGE_USAGE_REPORTED` line, each failure an `EDGE_USAGE_REPORT_FAILED` line with a
  code, and `agentsafe_edge_usage_reports{result}` counts both.

The report is a compact JWS, `alg` EdDSA, `typ` `decionis-edge-usage+jwt`, `kid` the registered key:

```json
{
  "iss": "branch-7.executor-0",
  "aud": "<organisation id>",
  "iat": 1790816400,
  "jti": "<uuid>",
  "period": "2026-09",
  "period_start": "2026-09-01T00:00:00.000Z",
  "period_end": "2026-10-01T00:00:00.000Z",
  "counts": {
    "by_mode": { "ENFORCEMENT": 3, "SHADOW": 1 },
    "by_verdict": { "ALLOW": 2, "ESCALATE": 1, "BLOCK": 1 },
    "total": 4
  },
  "delegated": 1,
  "chain": {
    "stream": "agent-safe.executor-evidence/1",
    "first_seq": 3,
    "last_seq": 7,
    "first_hash": "sha256:...",
    "last_hash": "sha256:..."
  },
  "bundles": ["jti-1", "jti-2"]
}
```

`period_end` is exclusive: the first instant of the next month. Each breakdown sums to `total`.
[`conformance/edge/usage-report-v1.json`](../conformance/edge/usage-report-v1.json) is a signed
report with the evidence it was counted from and its key's public half, for an ingestion to verify.

Offline, from the collected log of the executor's stdout:

```sh
# Count a month and sign the report (--out <file> to write it, --send to deliver it now).
agentsafe edge usage-report --period 2026-09 --log executor.log \
  --key usage.pem --installation branch-7.executor-0 --org <organisation id>
# Check a report's signature, then recount it from the log.
agentsafe edge verify-usage-report usage-2026-09-branch-7.executor-0.jws \
  --log executor.log --public-jwk usage.jwk
```

`usage-report` walks the chain back from the log's last line (or `--head <hash>`), past any branch
a crash abandoned, and refuses to sign when a line's hash does not match it or the log does not
reach back to the month's start. `verify-usage-report` requires the range to be one unbroken chain
from `first_hash` to `last_hash` and the decisions on it to count exactly what the report says;
it exits 0 when they do and 1 when they do not.

## Entitlement warnings

Decionis issues a signed entitlement per organisation (`typ` `decionis-edge-entitlement+jwt`): the
plan, the tier, the actions a month includes, a self-managed volume band, whether the edge is
included, and how many days after a month its usage report is due. The executor reads it at start
and every hour: `GET /v1/edge/entitlement` with the organisation's key, verified against the keys at
`/.well-known/decionis-policy-bundle-jwks.json` on the same origin (`url`), or the file at
`EXECUTOR_EDGE_ENTITLEMENT_FILE` verified against the JWKS pinned at `EXECUTOR_EDGE_JWKS_FILE`
(`file`).

| Warning                     | When                                                                                                |
| --------------------------- | --------------------------------------------------------------------------------------------------- |
| `ENTITLEMENT_MISSING`       | No entitlement could be read                                                                        |
| `ENTITLEMENT_INVALID`       | Its signature did not verify against the JWKS, or it is not an entitlement for this organisation    |
| `ENTITLEMENT_EXPIRED`       | Its `exp` has passed (the rest of it is still read)                                                 |
| `EDGE_NOT_ENTITLED`         | `edge` is `false`                                                                                   |
| `INCLUDED_ACTIONS_EXCEEDED` | This installation's governed actions this month (decisions not delegated) exceed the plan's         |
| `VOLUME_BAND_EXCEEDED`      | They exceed the volume band's `max_actions_per_month`, when the band states one                     |
| `USAGE_REPORT_KEY_MISSING`  | No usage-report key is configured, so no report will ever be made                                   |
| `USAGE_REPORT_OVERDUE`      | A completed month's report is undelivered `usage_report_due_days` (35 without an entitlement) after |

A warning that begins is an `EDGE_LICENCE_WARNING` line on the security stream and sets
`agentsafe_edge_licence_warning{code}` to 1; one that ends is `EDGE_LICENCE_CLEARED` and sets it to 0.
That is all a warning does. **No licence condition ever stops, delays, degrades or changes a
decision**: the licence check holds no reference to the decision path, and an executor whose
entitlement is missing, expired or excludes the edge decides exactly as one whose entitlement is
current. The count it compares is this installation's own; Decionis meters the organisation.

## Air-gapped operation

A deployment with no route to Decionis runs `EXECUTOR_EDGE_BUNDLE_SOURCE=file`, and everything that
would cross the network crosses it by hand:

| What                      | Direction           | How                                                                                           |
| ------------------------- | ------------------- | --------------------------------------------------------------------------------------------- |
| Policy bundle             | Decionis → executor | Place it at `EXECUTOR_EDGE_BUNDLE_FILE`; read every ten seconds                               |
| Entitlement and JWKS      | Decionis → executor | Place them at `EXECUTOR_EDGE_ENTITLEMENT_FILE` and `EXECUTOR_EDGE_JWKS_FILE`; re-read hourly  |
| Monthly usage report      | executor → Decionis | Collect `usage-<YYYY-MM>-<installation>.jws` from `EXECUTOR_EDGE_USAGE_REPORT_DIR` and upload |
| Usage-report key (public) | executor → Decionis | `agentsafe edge usage-key`, registered once per installation                                  |

The entitlement's `exp` (about 35 days) and the report's due days set the rhythm: one transfer a
month in each direction keeps every warning clear. Escalations still need Decionis: an `ESCALATE` is handed to the hosted authority, and in a
deployment that cannot reach it the hosted call fails closed, so an air-gapped policy should not
escalate.

## Limits

- What hosted Decionis computes from its own state (ledgers, current-state lookups, grant issuance,
  managed escalation) is out of the module's scope; anything that needs it is an `ESCALATE` or is
  decided hosted.
- The usage tally and the licence comparison are per installation; the organisation's total is
  Decionis's, from every installation's reports.
