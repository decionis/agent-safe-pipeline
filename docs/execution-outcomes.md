# Execution outcomes and reconciliation

Grant consumption and provider execution are separate boundaries. A single-use grant is consumed
before a handler runs, but a provider may accept a side effect and lose the response. Treating that
case as an ordinary failure invites a duplicate retry.

`SafeExecutor.run` therefore returns one of four outcomes:

| Outcome                  | Meaning                                                                          | May the caller retry the side effect? |
| ------------------------ | -------------------------------------------------------------------------------- | ------------------------------------- |
| `BLOCKED`                | No valid execution authority reached the handler                                 | Obtain or correct authority first     |
| `FAILED_BEFORE_DISPATCH` | A grant was consumed, but the trusted provider-dispatch boundary was not crossed | Only with a fresh decision and grant  |
| `COMPLETED`              | The trusted handler returned a provider result                                   | No; return or persist that result     |
| `UNKNOWN_AFTER_DISPATCH` | Dispatch began, but completion could not be proved                               | No; reconcile first                   |

`executed` is `true`, `false`, or `null` respectively so an unknown outcome cannot be mistaken for a
definite failure.

## Finalization

Every outcome that consumed a grant also reports `finalization`. After the attempt, `SafeExecutor`
asks the verifier to record the commit outcome with the authority: `COMMITTED` for `COMPLETED`,
`FAILED` for `FAILED_BEFORE_DISPATCH`, and `INDETERMINATE` for `UNKNOWN_AFTER_DISPATCH`.
`DecionisGrantVerifier` claims the grant through `/v1/execution/claim-token` and finalizes it through
`/v1/execution/finalize-token`, so commit evidence joins the Decision Dossier chain.

| `finalization` | Meaning                                                                                                                                   |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `RECORDED`     | The authority accepted the commit evidence                                                                                                |
| `PENDING`      | Delivery failed or was rejected; the authority's claim-lease recovery owns the evidence                                                   |
| `UNSUPPORTED`  | The verifier has no finalization contract at all; the development fixture does have one and records each outcome in an inspectable ledger |

Finalization is evidence, never authority. It runs after the dispatch boundary, never retries a side
effect, never throws, and never changes `outcome` or `executed`. The terminal audit event carries
`COMMIT_FINALIZATION_<status>` in its reason codes.

## Effect evidence

`AuthorizationFinalizationInput` takes an optional `effectEvidence`: a Protocol 1.1
`AuthorityEffectEvidence` record, an observation of what actually happened downstream. The pipeline is
domain-free, so it never constructs, interprets, upgrades, or downgrades an observation; only the
trusted runtime that watched the provider knows what the effect was. `DecionisGrantVerifier` forwards
the record verbatim as `effect_evidence` on the finalize request. `SafeExecutor` never supplies one,
because it cannot: a caller that wants effect evidence recorded calls the verifier's `finalize`
directly with it.

### The drop rule

Evidence is sent only when the executor can prove the authority will bind it:

- the record conforms to the contract's own bounded shape (ten keys, identifiers of at most 500
  characters after trimming, digests in `sha256:` form),
- the **grant the authority returned** committed to an expected-effect digest (not merely the intent —
  a deployment whose enforce route accepts the field but whose grant issuer is older would otherwise
  be refused),
- the evidence names that exact digest, and
- its `execution_correlation_id` equals the commit correlation id this grant was claimed with.

The shape check is not interpretation: whether an observation qualifies as `CONFIRMED` stays the
authority's judgement. It bounds what a caller-controlled object can put on an authenticated request,
and it takes the snapshot the three checks then run against, so the values that are verified are
exactly the values that are sent.

Otherwise the evidence is dropped and the finalization is sent without it. Dropping is the safe
direction: the authority answers evidence it cannot bind with a 409 that refuses the **entire**
finalization, so sending unbindable evidence would trade an observation for the commit record.

### The evidence-free retry

Two authority-side rejections cannot be predicted locally: an unset trusted-observer allowlist, and
an observation timestamp the authority's own clock reads as outside the finalization window. Either
refuses the whole finalization. So when a finalization that carried evidence is answered with **409**
— the one status a finalization refusal uses — `DecionisGrantVerifier` posts exactly once more
**without** the observation. The retry body is byte-identical to the body this package sent before
effect evidence existed: it retries no side effect and sends nothing it has not already sent.

Nothing else triggers a second post. A finalization that carried no evidence is never retried; a
rate-limited, unauthenticated, or unavailable authority (429, 401, 5xx) is never re-posted to; and a
transport failure — a throw, a timeout, an oversized body — is not an answer, so it is reported as
`PENDING` with no second attempt. On the one path that does retry, `finalize` can occupy up to twice
the configured `timeoutMs` before it returns, because each post carries its own timeout.

### Reading the authority's answer

`DecionisGrantVerifier.effectReport(authorization)` returns what the **authority** said, or `null`
until a finalization was recorded:

| Field                    | Meaning                                                                      |
| ------------------------ | ---------------------------------------------------------------------------- |
| `effectEvidenceSent`     | This verifier forwarded an observation on the recorded finalization          |
| `effectEvidenceRefused`  | An earlier attempt carried the observation and the authority refused it      |
| `effectEvidenceRecorded` | The authority's `effect_evidence_recorded`, for a finalization that sent one |
| `effectConfirmation`     | The authority's `effect_confirmation`, defaulting to `UNCONFIRMED`           |

The last two are the authority's statement, narrowed by what this executor knows it sent: a response
claiming a recorded or confirmed observation for a finalization that carried none is reported closed,
because an authority cannot have recorded what it was not given. `effectEvidenceRefused` is the one
signal that separates a refused observation from one that was dropped or never supplied — without it
the evidence-free retry would erase the fact that an observation existed at all.

`CONFIRMED` is not reachable from this package alone. The hosted authority accepts a confirmed
observation only from an API-key identity listed in its own trusted-effect-observer allowlist, and the
pipeline holds an API key string with no way to learn its own key id. A deployer who sets that
allowlist server-side and configures the matching observer id in the evidence the trusted runtime
builds can reach `CONFIRMED`; nothing here makes it automatic.

## Trusted handler contract

Put the provider side effect inside `dispatch.run`. The callback receives the idempotency key that
was supplied by trusted intent capture and bound into the canonical intent. The dispatch wrapper
permits one invocation and records the point after which an exception is ambiguous.

```ts
registry.register("refund_order", {
  parametersSchema: RefundSchema,
  execute: async ({ parameters, dispatch }) =>
    await dispatch.run(async (idempotencyKey) => provider.refund(parameters, { idempotencyKey })),
  reconcile: async ({ idempotencyKey }) => {
    const existing = await provider.findRefund(idempotencyKey);
    if (existing) return { status: "COMPLETED", result: existing };
    if (await provider.provesNoRefund(idempotencyKey)) return { status: "NOT_EXECUTED" };
    return { status: "UNKNOWN" };
  },
});
```

The handler is trusted code. Calling the provider outside `dispatch.run`, using a different
idempotency key, or initiating a side effect from `reconcile` violates the trust boundary. Neither
the dispatch nor reconciliation context contains the Decionis execution token or provider
credentials.

## Recovery

An unknown result includes an immutable `agent-safe.recovery/1` reference containing only the bound
intent, decision, dossier, grant, expiry, and idempotency identifiers. Pass that reference and the
original captured intent to `SafeExecutor.reconcile`.

Reconciliation is a provider lookup, not authorization. It may return the original completed
result, prove that no action occurred, or remain unknown. Concurrent reconciliation calls for the
same intent and idempotency key share one in-flight lookup. A rejected, malformed, or unavailable
lookup remains `UNKNOWN_AFTER_DISPATCH`; raw provider errors are not exposed.

No path automatically invokes the handler a second time. Even when reconciliation proves that no
action occurred, the prior grant remains consumed. A new side effect requires a fresh authority
decision and fresh grant. If reconciliation returns the original provider result, return it without
new authorization or execution.

Caller cancellation after provider dispatch cannot prove that the action stopped. Preserve the
unknown result or its recovery reference and reconcile it. Production handlers should also use the
same bound key with the provider's native idempotency facility and retain provider records long
enough for the application's recovery window.
