# Shadow mode

Shadow mode answers one question before an authority is given enforcement power: **what would
Decionis have decided about the actions this system already executes?** It is an adoption path,
not a safety control. Nothing in shadow mode can stop, delay, or change a production action, and
nothing it produces can authorize one.

```text
Agent -> intent -> existing execution (unchanged) -> production result
                |
                +-> Decionis in SHADOW mode -> observation (verdict, dossier, no grant)
```

Shadow mode is not a dry run and not a test environment with no real writes. The production
action runs and takes effect exactly as it did before; what is withheld is the authority, not the
write. Whether a handler performs a real write is a property of the handler and its environment,
independent of the evaluation mode: an enforcement gate can drive a handler that returns a
simulated receipt, and a shadow observation can sit beside a real production write.

## Isolation boundary

`ShadowPipeline` enforces four properties, each covered by deterministic tests:

| Property                | Guarantee                                                                                                                                                                             |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Production is unchanged | The existing execution callback is invoked exactly once. Its result or thrown error is returned verbatim in `production`; the pipeline never rethrows on behalf of the authority.     |
| Latency is isolated     | `observe` returns as soon as production settles. The observation runs under its own timeout (default 2 s, clamped to 15 s) and never delays production completion.                    |
| Failure is isolated     | A slow, rejected, malformed, or unreachable authority yields `TIMED_OUT`, `UNAVAILABLE`, or `INVALID`. The observation promise never rejects.                                         |
| Authority is withheld   | The observation has no `authorization`, is frozen, and is marked `mode: "SHADOW"` and `authority: "OBSERVATIONAL"`. Any grant an authority returns is discarded and reported instead. |

## Wire contract

`DecionisGate` sends `mode: "SHADOW"` when constructed with `mode: "SHADOW"`. Decionis evaluates
policy, records the Decision Dossier, and does not issue an execution grant. If a response carries
a token anyway, the gate returns `authorization: null` before the decision leaves the gate.

`ShadowPipeline` refuses an authority that declares `evaluationMode: "ENFORCEMENT"`. An enforcement
gate mints grants; sending observational traffic through it would create unconsumed live grants and
an audit trail that looks authoritative.

```ts
import { AuditRecorder, DecionisGate, ShadowPipeline } from "@decionis/agent-safe-pipeline";

const shadow = new ShadowPipeline(
  new DecionisGate({
    baseUrl: process.env.DECIONIS_API_URL!,
    apiKey: process.env.DECIONIS_API_KEY!,
    mode: "SHADOW",
  }),
  { audit: new AuditRecorder({ sink }), timeoutMs: 1_500 },
);

// Migration path: production first, observation in the background.
const run = await shadow.observe(captured, () => legacyRefund(order));
return run.production; // observation is delivered to the audit sink

// Measurement script: wait for both sides.
const comparison = await shadow.compare(captured, () => legacyRefund(order));
```

## Observation shape

```ts
interface ShadowObservation {
  mode: "SHADOW";
  authority: "OBSERVATIONAL";
  status: "OBSERVED" | "UNAVAILABLE" | "TIMED_OUT" | "INVALID" | "ABORTED";
  intentHash: string;
  verdict: "ALLOW" | "ESCALATE" | "BLOCK" | null;
  decisionId: string | null;
  dossierId: string | null;
  reasonCodes: readonly string[];
  grantDiscarded: boolean;
  durationMs: number;
}
```

`verdict` is non-null only for `OBSERVED`. A fail-closed decision from the gate, such as a transport
failure, is reported as `UNAVAILABLE` with the gate's reason code rather than as a policy `BLOCK`,
so "would have blocked" counts only real policy outcomes. `grantDiscarded: true` means the authority
returned execution authority that the pipeline dropped; with a correctly configured shadow gate it
is always `false`, so treat `true` as a configuration alarm.

## Ordering semantics

| Situation                            | Behavior                                                                                                       |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| Production completes before shadow   | `observe` returns with `production`; `observation` settles later on its own bound.                             |
| Shadow completes before production   | The observation is held; production still runs to completion unchanged.                                        |
| Production throws                    | `production` is `{ status: "FAILED", error }` with the original error object; the observation still completes. |
| Shadow rejects or throws             | `UNAVAILABLE`; production is unaffected.                                                                       |
| Shadow exceeds `timeoutMs`           | `TIMED_OUT`; a still-running authority request is discarded when it settles.                                   |
| Caller aborts the `signal`           | `ABORTED` for the observation only. Production is never cancelled by this pipeline.                            |
| Authority returns a mis-bound result | `INVALID` with `SHADOW_BINDING_MISMATCH` or `SHADOW_DECISION_MALFORMED`.                                       |

## Evidence

With an `AuditRecorder`, every observation is emitted as one `SHADOW_EVALUATED` event classified
`OBSERVATIONAL`. Its reason codes begin with `SHADOW_<status>` followed by the authority's codes,
and it carries the verdict, decision, and dossier identifiers. The recorder refuses a shadow event
that claims any other classification and refuses any observational event that references a grant,
so a reader can tell from the record alone that the evaluation was never authoritative.

`SafeExecutor` rejects an observation, or a persisted shadow audit event, with
`DECISION_NOT_AUTHORITATIVE` before it records or inspects the object as a decision. This holds
after an unsafe cast and after a JSON round trip.

## Rollout guidance

1. Capture intents exactly as enforcement will capture them: same trusted context, same handler
   parameter schema, same idempotency key derivation. Shadow results are only as good as the intent.
2. Start with `observe` and an audit sink on a sample of traffic; raise the sample once the added
   local overhead is confirmed negligible. Sampling is a caller decision; the pipeline does not
   sample.
3. Review `OBSERVED` verdict distribution against the policy you expect. Treat `UNAVAILABLE` and
   `TIMED_OUT` rates as the availability cost that fail-closed enforcement would impose.
4. Do not reuse a shadow-observed captured intent for enforcement. Capture a fresh intent when
   switching a path to `DecionisGate` in `ENFORCEMENT` mode with `SafeExecutor`.
5. Keep the `SHADOW` label in logs and dashboards. The only way a shadow result gains authority is
   a person reading it as one.
