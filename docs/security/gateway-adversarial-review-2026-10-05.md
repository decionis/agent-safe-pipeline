# AgentSafe gateway and card boundary adversarial review

Review date: 5 October 2026. Baseline: `master` at `2e564711`.

The review exercised local code, synthetic authorities and loopback targets. It covered HTTP
classification/routing, intent normalization, pre-dispatch binding and issuer card claim
concurrency, alongside the existing grant, escalation, egress and replay tests. No production,
customer, Koard or live Decionis endpoint was attacked.

## Findings and fixes

| ID      | Severity                                | Reproduced failure                                                                                                                                                                             | Fix                                                                                                                                                                                                                                                                         |
| ------- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GW-01   | High                                    | `MKCOL`, `MOVE` and other methods outside the four governed verbs were classified as safe. A local `MKCOL` reached the upstream without a decision.                                            | Safe-method allowlist is GET/HEAD/OPTIONS. Unsupported methods receive 405 before forwarding while interception is enabled.                                                                                                                                                 |
| GW-02   | High, conditional on upstream overrides | An unevaluated GET retained method-override headers that an upstream framework can interpret as DELETE or another write.                                                                       | Reject the three common override headers with `HTTP_METHOD_OVERRIDE_REFUSED`. Integrations must disable custom method overrides and side-effecting safe methods.                                                                                                            |
| GW-03   | Medium; mutation at the local handoff   | Changing a held request's raw query, content type, account header or idempotency header after capture still dispatched. The old check bound only method, path and body.                        | Capture and recheck a digest of all held request metadata and bytes. Mutation raises `PAYLOAD_BINDING_MISMATCH` before dispatch. Raw header values remain local.                                                                                                            |
| GW-04   | Medium                                  | A query named `__proto__` disappeared from the policy parameters but was still sent upstream.                                                                                                  | Reject the canonical contract's forbidden property names and group query values in a Map. This also removes repeated full-query scans.                                                                                                                                      |
| CARD-01 | High                                    | Concurrent requests reused one authorization id for two different cards. Both received APPROVE, and the second overwrote the retry/result lookup. Identical concurrent retries also disagreed. | Reserve authorization ids before asynchronous claim work. Bind each to the complete request digest; join identical retries and reject conflicting requests before spending another card's grant. Bound in-flight ids to 10,000 per process and clean them up on completion. |
| GW-05   | High when routes narrow the boundary    | Under unmatched passthrough, `/%70ayments` evaded `/payments`. Encoded separators and path-parameter forms also admitted differing router interpretations.                                     | Match decoded literal characters once; refuse ambiguous paths. Keep the exact transmitted path bound. Configured patterns must use decoded literal characters; encoded wildcard syntax is refused.                                                                          |

Severity is scoped to the demonstrated preconditions, not a formal CVSS assessment. In particular,
GW-03 is a local handoff mutation test; it does not establish that a remote caller can modify an
in-flight JavaScript object.

## Regression evidence

The initial gateway/card baseline passed 196 tests. Twelve newly added cases failed against the
unfixed code across method classification, override admission, binding, query normalization and
card concurrency. A second reproduction run added seven failing path-routing cases. The fixed
suite also includes positive header-order and Unicode-routing cases, forbidden-name variants and
the actual HTTP listener's refusal behavior.

Focused command:

```bash
pnpm --filter @decionis/agentsafe exec vitest run \
  test/gateway test/http/GatewayHttpServer.test.ts test/service/CardFlow.test.ts
```

The key assertions observe downstream request counts, dispatch counts, claim counts and stable
retry results. They do not merely check that a guard helper returned a constant.

## Final validation

Validation ran on the completed implementation using Node.js 25.9.0 and pnpm 9.15.3:

| Check                            | Result                                                                                                                                                                            |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm install --frozen-lockfile` | Passed without lockfile changes.                                                                                                                                                  |
| `pnpm verify`                    | Passed: formatting, lint, metadata, fixtures, dossiers, licenses, dependency audits, discovery, performance, type checking, schema, tests and builds.                             |
| Test suites within verification  | AgentSafe: 1,212 passed; pipeline: 423 passed; automation: 167 passed; Node integration: 7 passed; contract: 17 passed; performance: 2 passed. Sixteen opt-in tests were skipped. |
| `pnpm mutation`                  | Passed at 100% in both configured suites. Pipeline: 600 killed, 1 timeout; AgentSafe: 3,695 killed, 26 timeouts. No surviving or uncovered mutants in the configured scope.       |
| Package inspection               | Built the AgentSafe tarball and checked its contents, including the changed gateway implementation.                                                                               |
| PDF review                       | Rendered and visually inspected all ten pages; checked page counts, selectable text and embedded fonts.                                                                           |

The mutation command covers the repository's existing 37-file allowlist; it does not mutate the
newly changed gateway modules or `TrustedExecutorService.ts`. Their fixes are covered by the
reproduced negative tests above and the full test run. CodeQL and protected CI checks remain
separate from this local validation.

## Deployment consequences and limits

- Existing consumers of the exported `RoutePlan` must handle `REFUSE`. Custom forwarded intents
  need the new `context.request_sha256`; missing binding fails closed.
- Unsupported HTTP methods, override headers and ambiguous paths are rejected while interception
  is enabled. Explicitly disabling interception still makes the runtime an unrestricted relay.
- A deployment must prevent direct calls around the gateway. Generic safe methods must actually be
  safe at the upstream. Application-specific method overrides and routing rewrites require their
  own explicit executor integration.
- Card coordination is per process. Sticky routing or another deliberate architecture is required
  for multiple replicas; these changes do not add a distributed card store or restart recovery.
- In-memory retry retention is finite. The issuer remains responsible for its own idempotent card
  decision and ledger reconciliation. A cached APPROVE is the result of the original request,
  not fresh authority for another transaction.
- The claimed-principal HTTP header is a claim, not authenticated actor identity. Bank integrations
  should use the executor's verified principals for proposer/operator separation.
- Policy quality, Koard's ceremony, live provider-key revocation, processor latency and actual issuer
  result signatures are separate acceptance boundaries. This local review does not certify them.

See [the revised banking briefs](../banking/README.md) for the clarified joint-delivery flows,
data-boundary corrections and issuer integration requirements.
