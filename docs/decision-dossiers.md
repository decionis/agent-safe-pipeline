# Decision Dossiers

A Decision Dossier records why Decionis allowed, escalated, or blocked an intent and links policy, evidence, and execution-grant metadata. Use its identifier for audit and support correlation.

Do not treat a dossier URL or identifier as an execution credential. Only the signed, short-lived, single-use grant can authorize `SafeExecutor`, and the trusted verifier must consume it atomically.

Avoid putting secrets or raw provider payloads in intent context. Prefer opaque references or precomputed hashes where policy does not need the plaintext.

The repository-owned [synthetic conformance corpus](../dossiers/) publishes exact canonical bytes,
SHA-256 digests, detached Ed25519 signatures, a public JWKS, and the deliberately public private key
used to regenerate them. Its owned-workspace vector proves that issuer context is covered by the
portable-artifact signature and verifies a version `2.1` execution binding with RFC 8785/JCS. It
tests the offline verification contract only. Follow its README's separate live-JWKS command to
verify a production dossier without committing production evidence.

## Who issues, who claims, what links

The dossier and the grant are produced by the same evaluation and travel different paths. Read
the sequence once and the difference stays put:

1. `DecionisGate.evaluate` sends the captured intent to Decionis. Decionis records a Decision
   Dossier for every evaluation, in every mode, and returns a `GateDecision` carrying
   `decisionId`, `dossierId`, `intentHash`, and `reasonCodes`.
2. Only an `ALLOW` carries `authorization`: a short-lived, single-use grant bound to that intent
   hash, decision, audience, and expiry. `ESCALATE` and `BLOCK` carry `authorization: null`, and so
   does every shadow observation, whatever the verdict.
3. An `ESCALATE` becomes executable only after Presence evidence (`receiptDossierId`) goes back to
   Decionis and Decionis evaluates the same intent again. That fresh evaluation is what may issue
   a grant. The receipt authorizes nothing on its own, and neither does the invitation that led to
   it.
4. `SafeExecutor.run` presents the grant to the `AuthorizationVerifier`, which claims it atomically
   immediately before the registered handler runs. A claimed grant cannot be presented again; a
   grant for another intent hash is refused before the handler is reached.
5. Afterwards the attempt is finalized with the authority as evidence: `COMMITTED` for
   `COMPLETED`, `FAILED` for `FAILED_BEFORE_DISPATCH`, `INDETERMINATE` for
   `UNKNOWN_AFTER_DISPATCH`. Every executed result keeps its consumed
   `{decisionId, dossierId, grantId, intentHash}` binding, so the record and the attempt correlate
   without extra bookkeeping. See [execution outcomes](./execution-outcomes.md).

The dossier identifier appears at steps 1 and 5. It links the record to the decision and to the
attempt. It never appears at step 4 as the thing being claimed, and nothing in this package accepts
one there.

## Two records, side by side

Both records below come from the synthetic corpus vector
[`dossiers/vectors/owned-execution-bound.json`](../dossiers/vectors/owned-execution-bound.json).
Identifiers are synthetic; the grant token is never part of a dossier and is elided here.

The decision, as the gate returns it:

```text
verdict        ALLOW
decisionId     synthetic-decision-owned-execution-bound-001
dossierId      synthetic-dossier-owned-execution-bound-001
intentHash     sha256:9eef89f55e857c7d72a88860a6136a3c53e741cd1e22ea39cc92c5a5cca85356
authorization  { token: <short-lived single-use grant>, expiresAt: 2026-09-04T10:05:00.000Z }
```

The dossier, as the record keeps it:

```text
dossier_id                          synthetic-dossier-owned-execution-bound-001
routing_decision.decision_id        synthetic-decision-owned-execution-bound-001
routing_decision.outcome            ALLOW
routing_decision.execution_grant_issued   true
execution_binding.payload.digest    sha256:9eef89f55e857c7d72a88860a6136a3c53e741cd1e22ea39cc92c5a5cca85356
execution_binding.expires_at        2026-09-04T10:05:00.000Z
execution_binding.idempotency_key   fixture_0001
```

The record says that a grant was issued, to which intent, and until when. It does not contain the
grant. Presenting the dossier, its identifier, or its verify link to `SafeExecutor` produces
`BLOCKED`, because the verifier has nothing to claim.

## When the outcome is not known

If dispatch began and completion could not be proved, `SafeExecutor.run` returns
`UNKNOWN_AFTER_DISPATCH` with `executed: null`, finalizes the attempt as `INDETERMINATE`, and never
invokes the handler a second time on its own. The dossier chain then holds an open attempt, not a
failure. Reconcile it through the provider's idempotency key and read-only lookup before deciding
anything; a second dispatch needs a fresh decision and a fresh grant. The rules are in
[execution outcomes](./execution-outcomes.md).
