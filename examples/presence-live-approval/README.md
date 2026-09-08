# Presence live approval

Runs one Presence-bound enforcement against the real Decionis and Presence services: capture an
intent, get an `ESCALATE`, hand the approval to Presence with an explicit ceremony, wait for the
person to complete it, re-authorize with the receipt, claim the grant, run a simulated handler, and
finalize. No downstream provider is called; the handler returns a synthetic receipt.

This example needs real server-side credentials and is not part of `pnpm verify`.

## Configure

Create `.env.presence-live` at the repository root. The file is ignored by Git.

```text
DECIONIS_API_URL=https://api.decionis.com
DECIONIS_API_KEY=server-side-secret
DECIONIS_TENANT_ID=00000000-0000-4000-8000-000000000000
PRESENCE_API_URL=https://presence.decionis.com
PRESENCE_API_KEY=presence_sk_server-side-secret
APPROVER_EMAIL=you@example.com
APPROVER_ORGANIZATION=Your organization
```

`APPROVER_EMAIL` is the approver's Presence identity. It is carried in the trusted intent context
under `approver_email`, so it is hash-bound and recorded in the Decision Dossier, and it is the
subject actor Presence routes the request to.

## Run the two ceremonies

```bash
pnpm --filter @decionis/agent-safe-example-presence-live-approval demo -- --ceremony fido
pnpm --filter @decionis/agent-safe-example-presence-live-approval demo -- --ceremony fido-liveness
```

| Ceremony        | Presence requirements                                            |
| --------------- | ---------------------------------------------------------------- |
| `fido`          | `level: STANDARD`, `methods: [WEBAUTHN]`                         |
| `fido-liveness` | `level: HIGH_CONFIDENCE`, `methods: [WEBAUTHN, ACTIVE_LIVENESS]` |

`--amount-minor` (default `50000`) sets the refund amount. The tenant policy decides whether that
amount escalates; if Decionis returns `ALLOW` directly, Presence is not exercised and the run says so.

## What to expect

The run prints one JSON line per stage: `captured`, `decision`, `presence_handoff`, `audit` events,
`reauthorization`, and `execution`. A successful run ends with `outcome: "COMPLETED"` and
`finalization: "RECORDED"`, and exits with status 0.

How the approval reaches the person:

- Presence delivers a push notification to enrolled mobile devices bound to the approver identity.
- Presence itself does not send email, and neither does the Decionis execution-authority path. If
  no push arrives, open the `approvalUrl` printed in the `presence_handoff` line on the approver's
  trusted device. The link carries only an opaque invitation token.
- The intent, the Presence request, and polling all share a five-minute window. Complete the
  ceremony within it; otherwise the run ends with `PRESENCE_TIMEOUT` or `PRESENCE_INTENT_EXPIRED`
  and nothing executes.

## Reading a failure

| Where it stops                                    | Meaning                                                                                        |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `decision` with `failClosed: true`                | Decionis was unreachable, rejected the request, or the tenant is not entitled; see reasonCodes |
| `PRESENCE_REQUEST_FAILED`                         | Presence refused the verification request; check the key, base URL, and approver identity      |
| `reauthorization` with `PRESENCE_DENIED`          | The person denied, or the request expired or was cancelled                                     |
| `reauthorization` with `AUTHORITY_REQUEST_FAILED` | Decionis could not verify the receipt with Presence, for example a missing approver role       |
| `execution` with `AUTHORIZATION_INVALID`          | The claim was refused; the grant may have expired inside the window                            |
