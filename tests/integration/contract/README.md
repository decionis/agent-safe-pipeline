# Wire-contract harness

Drives `@decionis/agent-safe-pipeline` through its public entry point against loopback stand-ins for
the Decionis authority routes and the Presence approval routes, over a real HTTP stack. It exists to
prove that the packed package sends and consumes the complete contract, not only that its units
behave with an injected `fetch`.

```bash
pnpm test:contract
```

`pnpm verify` runs the same suite through the workspace build. The packed-tarball workflow reruns it
against the installed npm tarball on every supported Node.js line and uploads
`contract-diagnostics.json` when a scenario fails.

## What is stubbed

| Stub                | Routes                                                                                                                                                                         | Behavior                                                                                                                                                                                                                                                              |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AuthorityStub.mjs` | `POST /v1/authority/enforce-and-bind`, `GET`/`DELETE /v1/authority/escalations/:id`, `/v1/execution/claim-token` and its `consume-token` alias, `/v1/execution/finalize-token` | Strict request schemas mirroring the OpenAPI contract, an independent canonicalizer that recomputes the intent hash, idempotent managed-escalation state, synthetic single-use grants, direct evidence re-verification at claim time, commit outcomes, bounded bodies |
| `PresenceStub.mjs`  | `POST /v1/verification-requests`, `GET /v1/verification-requests/:id`                                                                                                          | Pending-then-terminal outcomes driven through the real `@decionis/presence-node` client; receipts carry the displayed intent hash so the authority stub can detect approval swapping                                                                                  |

Each authority route can be scripted once per scenario with a status, body, transform, delay,
truncation, or connection destruction, which is how the fault scenarios are produced.

The scenarios retain the developer-controlled DIRECT Presence flow and add MANAGED coverage for a
grant-free pending response, idempotent initiation, Decionis-only status polling, FIDO2 plus active
liveness forwarding, reauthorization BLOCK/ESCALATE, expiry and failure, exact action/target
mutation, concurrent waits, normal single-use claim, and finalization.

## Provenance rules the harness follows

These files are manifested synthetic fixtures under `pnpm fixture:check`:

- Identities use the `synthetic-` prefix and the reserved tenant UUID block. Credentials are the
  literal `test-key`. No real policy, tenant, order, or receipt appears anywhere.
- Both stubs bind to `127.0.0.1` on an ephemeral port and build their base URL from the constant
  `LOOPBACK_ORIGIN = "http://127.0.0.1"`, appending the port separately. The gate parses every
  URL-shaped literal verbatim, so interpolating inside the URL would fail the check.
- Invitation links use the reserved `presence.example.invalid` host.
- Diagnostics are bounded: the last 200 requests per stub with bodies cut at 2 KiB, written to
  `CONTRACT_DIAGNOSTICS_DIR` or the OS temporary directory.

Adding a scenario file means adding it to `fixtures/manifest.json` in the same change.
