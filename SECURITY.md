# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Email `security@decionis.com` with the affected version, reproduction, impact, and any proposed remediation. Do not include real customer data or credentials.

We will acknowledge receipt, triage severity, coordinate a fix and disclosure window, and credit reporters who want attribution. There is no promise of a bug bounty unless separately agreed in writing.

## Supported versions

Before the first stable release, only the latest tagged `0.x` version receives security fixes. Consumers should pin exact versions and review release notes.

## Integration requirements

- Never expose Decionis, Presence, or downstream provider credentials to the agent runtime.
- Require TLS and authenticated service-to-service requests in production.
- Treat fixture authority classes, synthetic policies, and examples as development-only.
- Store no secrets in intent parameters, dossiers, logs, source, fixtures, or support bundles.
- Apply provider-side least privilege and idempotency in addition to grant consumption.
