# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the [private GitHub vulnerability-reporting form](https://github.com/decionis/agent-safe-pipeline/security/advisories/new) or email the Decionis security contact at [security@decionis.com](mailto:security@decionis.com). Include the affected version, reproduction, impact, and any proposed remediation. Do not include real customer data or credentials; ask for a secure transfer method if sensitive evidence is essential.

We will coordinate remediation and publication through a GitHub Security Advisory when practical and credit reporters who want attribution. There is no promise of a bug bounty unless separately agreed in writing.

## Response and disclosure targets

These are service targets rather than contractual guarantees. Timing starts when a report reaches either private channel above.

| Stage                                      | Target                                                                              |
| ------------------------------------------ | ----------------------------------------------------------------------------------- |
| Acknowledge receipt                        | Within 2 business days                                                              |
| Initial validation and severity assessment | Within 5 business days                                                              |
| Status updates for a validated report      | At least every 7 calendar days                                                      |
| Critical remediation target                | 14 calendar days after validation                                                   |
| High remediation target                    | 30 calendar days after validation                                                   |
| Moderate or low remediation target         | 90 calendar days after validation or the next planned release, whichever is earlier |
| Coordinated public disclosure              | After a fix is available, targeted within 90 calendar days of validation            |

Active exploitation, credential exposure, or material user risk may require faster disclosure or mitigations. If a target cannot be met, we will explain the constraint and propose a revised date to the reporter. Please keep the report private until the coordinated date.

## Supported versions

Before the first stable release, only the latest tagged `0.x` version receives security fixes. Consumers should pin exact versions and review release notes.

## Integration requirements

- Never expose Decionis, Presence, or downstream provider credentials to the agent runtime.
- Require TLS and authenticated service-to-service requests in production.
- Treat fixture authority classes, synthetic policies, and examples as development-only.
- Store no secrets in intent parameters, dossiers, logs, source, fixtures, or support bundles.
- Apply provider-side least privilege and idempotency in addition to grant consumption.
