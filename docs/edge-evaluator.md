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
executor runs on the hosted authority exactly as before; nothing in this repository checks a
licence, and the host refuses no feature for want of one. See [OPEN-CORE.md](../OPEN-CORE.md).

## How a bank runs it

1. Obtain the module from Decionis under the edge licence and mount it read-only into the executor
   (for example `/opt/decionis/policy_core_edge.wasm`). The host requires module ABI 3 and refuses
   to start on anything else: a file it cannot read, bytes that are not WebAssembly, an older ABI.
2. Give the executor an organisation API key with `policy:read` (the bundle route) beside the
   scopes it already needs. It is the existing `DECIONIS_API_KEY`; no new secret exists.
3. Configure:

   | Variable                        | Value                                                   |
   | ------------------------------- | ------------------------------------------------------- |
   | `EXECUTOR_DECISION_AUTHORITY`   | `edge`                                                  |
   | `EXECUTOR_EDGE_WASM_PATH`       | the module, an absolute path                            |
   | `EXECUTOR_EDGE_ORG_ID`          | the Decionis organisation the bundles are issued to     |
   | `EXECUTOR_EDGE_BUNDLE_SOURCE`   | `url` (default) or `file`                               |
   | `EXECUTOR_EDGE_BUNDLE_FILE`     | `file` only: where an operator places the signed bundle |
   | `EXECUTOR_EDGE_REFRESH_SECONDS` | routine refresh, 60 to 86400, 3600 by default           |
   | `EXECUTOR_EDGE_ON_UNAVAILABLE`  | `hosted` (default) or `block`                           |

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
local authorization and for a hosted grant alike.

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

## Limits

- Single use of a local authorization is enforced in the executor's process. Run one executor per
  boundary, or put a shared `ReplayStore` behind `LocalAuthorizationVerifier` when embedding the
  pipeline in a replicated service.
- What hosted Decionis computes from its own state (ledgers, current-state lookups, grant issuance,
  managed escalation) is out of the module's scope; anything that needs it is an `ESCALATE` or is
  decided hosted.
