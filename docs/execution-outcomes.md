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
