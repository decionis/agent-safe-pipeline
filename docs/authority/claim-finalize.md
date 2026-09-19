# Claim and finalize

An `ALLOW` is not permission; a claimed grant is. The gateway runs the library's own claim and
finalization, unchanged: `SafeExecutor` with `DecionisGrantVerifier` against
`/v1/execution/claim-token` and `/v1/execution/finalize-token`.

## Claim

On an `ALLOW` with a grant, `SafeExecutor` asks the verifier to claim the grant immediately before
the handler runs. The claim is single-use and atomic at the authority: a second presentation of
the same grant, a grant for another intent hash, an expired grant, or a grant whose decision or
dossier does not match the decision in hand, claims nothing and the request is not forwarded
(`AUTHORIZATION_INVALID`, `503` from the gateway, state `ERROR`). The handler never sees the grant
token; it sees the verified authorization's identifiers, which it carries to the upstream as
`x-agent-safe-decision-id` and `x-agent-safe-dossier-id`.

The dispatch budget is the smaller of the upstream timeout, what is left of the grant, and what is
left of the claim lease the authority named, measured on a monotonic clock; a slow upstream cannot
outlive the permission the request was made under.

The invariant, stated once: offline verification proves the grant; the Decionis claim consumes the
authority; only a successful claim permits dispatch. A locally verified execution grant MUST NOT,
by itself, authorize downstream execution, because verification is stateless and cannot know
whether the grant was consumed. The same holds for a claim that succeeded and a process that then
failed before the handler ran: the grant is not released for a second claim because execution was
not observed; the claim lease and the finalization outcome say what happened to it. A provider that
wants to refuse for itself checks the authority's attestation of the claim, never the grant: the
[Verifying Provider Profile](./verifying-provider.md).

## Finalize

After the attempt, `SafeExecutor` finalizes the outcome with the authority so the commit evidence
joins the Decision Dossier:

| Upstream               | Outcome                   | Finalization    |
| ---------------------- | ------------------------- | --------------- |
| `2xx`, `3xx`           | `COMPLETED`               | `COMMITTED`     |
| `4xx`                  | `DEFINITELY_NOT_EXECUTED` | `FAILED`        |
| `5xx`, no answer       | `UNKNOWN_AFTER_DISPATCH`  | `INDETERMINATE` |
| refused before sending | `FAILED_BEFORE_DISPATCH`  | `FAILED`        |

Finalization is evidence, not authority: a finalization the authority did not record (`PENDING`)
never changes the outcome, and the report says `Finalized PENDING` so an operator knows. The
[execution outcomes](../execution-outcomes.md) page is the vocabulary; the gateway adds the HTTP
mapping in [HTTP interception](../gateway/http-interception.md#what-each-outcome-means).

## Never twice

One grant, one dispatch: `dispatch.run` refuses a second call inside one attempt, and a grant
cannot be claimed twice. A client that retries a request creates a new intent, a new decision and,
if allowed, a new grant, exactly as it would without the gateway; its own `Idempotency-Key` travels
to the upstream unchanged so the upstream's idempotency still applies. An indeterminate outcome is
recorded and reported, never retried by the gateway.
