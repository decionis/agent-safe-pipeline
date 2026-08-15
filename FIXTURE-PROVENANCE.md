# Fixture provenance

All fixtures in this repository are synthetic, hand-authored for the Agent-Safe Pipeline reference implementation, and licensed with the repository under Apache-2.0. They are not exports, samples, or transformations of customer, production, support, or incident data.

| Fixture family                    | Location                                 | Provenance                                                                                                                                      | Intended use                                                      |
| --------------------------------- | ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| Policy examples                   | `policies/*.json`                        | Hand-authored threshold and environment examples using fictional values                                                                         | Documentation and local demonstrations only                       |
| Intent conformance vector         | `conformance/agent-safe-intent-v1.json`  | Deterministic UUIDs, timestamps, identifiers, and parameters created for this repository; the expected hash is verified by the conformance test | Cross-implementation canonicalization testing                     |
| Example identities and actions    | `examples/*`                             | Fictional tenants, actors, orders, customers, approvals, and `.invalid` URLs                                                                    | Runnable demonstrations only                                      |
| Unit-test data                    | `packages/pipeline/test/*`               | Deterministic test values created alongside the implementation                                                                                  | Automated tests only                                              |
| Fixture authority keys and grants | `FixtureDecisionAuthority` and its tests | Ephemeral Ed25519 keys generated in memory during each run; tokens are short-lived local test artifacts                                         | Development and tests only; construction is blocked in production |

The exact strings `refund-synthetic-1001-v1` and `refund-58291-v1` are documented synthetic idempotency keys. They are narrowly allowlisted in `.gitleaks.toml` because the generic API-key detector otherwise classifies them as credentials. No path-wide or rule-wide secret-scanning exemption is used.

Contributors must document the source and license of any new fixture. Prefer deterministic fictional data. Never sanitize real customer data for use here: create a new synthetic fixture instead.
