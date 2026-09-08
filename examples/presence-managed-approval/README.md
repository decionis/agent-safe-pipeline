# Presence managed approval

Runs one Decionis-managed Presence escalation against the real Decionis service. The trusted
executor captures a refund intent, calls `enforce-and-bind` once, receives a grant-free pending
escalation, and polls Decionis until the authorization is terminal. Decionis creates the Presence
request, delivers the opaque invitation, verifies the signed receipt, and re-evaluates current
policy before it can return a normal execution grant.

The example never calls Presence and needs no Presence service credential. Its registered handler
is simulated and side-effect-free.

## Configure

Create `.env.presence-managed` at the repository root. The file is ignored by Git.

```text
DECIONIS_API_URL=https://api.decionis.com
DECIONIS_API_KEY=server-side-secret
DECIONIS_TENANT_ID=00000000-0000-4000-8000-000000000000
APPROVER_PRINCIPAL_ID=trusted-principal-id
APPROVER_ROLE_ID=APPROVER
```

The approver constraints come from trusted executor configuration, not agent or model output.
Decionis resolves the principal's effective tenant role; sending `APPROVER_ROLE_ID=APPROVER` does not
self-assign that role.

## Run

```bash
pnpm --filter @decionis/agent-safe-example-presence-managed-approval demo -- --ceremony fido
pnpm --filter @decionis/agent-safe-example-presence-managed-approval demo -- --ceremony fido-liveness
```

| Ceremony        | Managed verification requirements                                |
| --------------- | ---------------------------------------------------------------- |
| `fido`          | `level: STANDARD`, `methods: [WEBAUTHN]`                         |
| `fido-liveness` | `level: HIGH_CONFIDENCE`, `methods: [WEBAUTHN, ACTIVE_LIVENESS]` |

`--amount-minor` defaults to `50000`. The configured tenant policy decides whether the request is
allowed, blocked, or escalated.

The process prints one JSON line for each meaningful stage. A pending line always contains
`grant: null`. A successful managed run proceeds through `managed_escalation_pending`,
`authorization` with `GRANT_READY`, normal claim-before-dispatch execution, and finalization.

Complete the ceremony before the captured intent's five-minute ceiling. Presence authorization
cannot revive an expired execution intent; expiry returns `INTENT_EXPIRED` and
`RECAPTURE_REQUIRED`, and a fresh intent and ceremony are required.
