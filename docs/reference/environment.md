# Environment reference

Every variable the gateway and its commands read. A variable wins over the file and loses to a
flag; one that cannot be parsed is a refusal that names it. The trusted executor (`agentsafe
serve`) reads its own, larger set, listed in the [package README](../../packages/agentsafe/README.md#configuration).

## Gateway

| Variable                        | File key                       | Meaning                                                                                                        |
| ------------------------------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| `AGENTSAFE_LISTEN`              | `gateway.listen`               | `host:port` or `:port`                                                                                         |
| `PORT`                          | `gateway.listen`               | the port alone, on `127.0.0.1`                                                                                 |
| `AGENTSAFE_UPSTREAM`            | `gateway.upstream`             | the service to protect                                                                                         |
| `AGENTSAFE_UPSTREAM_INSECURE`   | `gateway.upstreamInsecure`     | `true` allows plain http off loopback                                                                          |
| `AGENTSAFE_UPSTREAM_TIMEOUT_MS` | `gateway.upstreamTimeoutMs`    | budget for one forward                                                                                         |
| `AGENTSAFE_UPSTREAM_SYSTEM`     | `gateway.system`               | `downstream_target.system`                                                                                     |
| `AGENTSAFE_ENVIRONMENT`         | `gateway.environment`          | `downstream_target.environment`                                                                                |
| `AGENTSAFE_AUTHORITY`           | `authority.endpoint: local`    | `local` or `decionis`                                                                                          |
| `AGENTSAFE_MODE`                | `authority.mode`               | `shadow` or `enforcement`                                                                                      |
| `DECIONIS_MODE`                 | `authority.mode`               | the same, as `createGate` already reads it                                                                     |
| `AGENTSAFE_FAILURE_POLICY`      | `authority.failurePolicy`      | `failClosed` or `failOpen`                                                                                     |
| `AGENTSAFE_UNMATCHED`           | `interception.unmatched`       | `govern` or `passthrough`                                                                                      |
| `AGENTSAFE_PRINCIPAL_HEADER`    | `interception.principalHeader` | a header carried as `claimed_principal`                                                                        |
| `AGENTSAFE_ACTOR_ID`            | `actor.id`                     |                                                                                                                |
| `AGENTSAFE_ACTOR_TYPE`          | `actor.type`                   |                                                                                                                |
| `AGENTSAFE_EVIDENCE_DIR`        | `evidence.journalDir`          | where `evidence.jsonl` and the chain heads go                                                                  |
| `AGENTSAFE_LOG_LEVEL`           | `output.verbose`               | `debug` turns verbose on                                                                                       |
| `AGENTSAFE_LOG_FORMAT`          | `output.format`                | `json` or `human`                                                                                              |
| `AGENTSAFE_CONFIG`              | —                              | the file, when not `./agentsafe.yaml`                                                                          |
| `AGENTSAFE_HOME`                | —                              | where `agentsafe login` stores the login                                                                       |
| `AGENTSAFE_METRICS_TOKEN`       | —                              | when set, `/_agentsafe/metrics` needs it as a bearer token                                                     |
| `NODE_ENV`                      | —                              | `production` refuses the demo authority, a key in the environment, the stored login and the loopback allowance |
| `NO_COLOR`                      | —                              | no color on the terminal                                                                                       |

## Decionis

| Variable                           | File key                          | Meaning                                             |
| ---------------------------------- | --------------------------------- | --------------------------------------------------- |
| `DECIONIS_API_KEY`                 | —                                 | the key; outside production only                    |
| `DECIONIS_API_KEY_FILE`            | —                                 | a file holding the key; the only form in production |
| `DECIONIS_API_URL`                 | `authority.endpoint`              | `https://api.decionis.com` by default               |
| `DECIONIS_TENANT_ID`               | `authority.tenantId`              | the key's organization id                           |
| `DECIONIS_TIMEOUT_MS`              | `authority.timeoutMs`             |                                                     |
| `DECIONIS_ALLOW_INSECURE_LOOPBACK` | `authority.allowInsecureLoopback` | a plain-http authority on loopback                  |

These are the same variables `createGate` and the trusted executor read, with the same meanings.

## Presence

| Variable                        | File key                | Meaning                                        |
| ------------------------------- | ----------------------- | ---------------------------------------------- |
| `AGENTSAFE_PRESENCE_MANAGED`    | `presence.managed`      | `true` turns managed escalation on             |
| `PRESENCE_APPROVER_ID`          | `presence.approverId`   |                                                |
| `PRESENCE_APPROVER_ROLE`        | `presence.approverRole` |                                                |
| `PRESENCE_VERIFICATION_LEVEL`   | `presence.level`        | `STANDARD` or `HIGH_CONFIDENCE`                |
| `PRESENCE_VERIFICATION_METHODS` | `presence.methods`      | `WEBAUTHN`, `ACTIVE_LIVENESS`, comma-separated |

The gateway holds no Presence credential: managed escalation is orchestrated by Decionis. The
executor's `DIRECT` shape, with `PRESENCE_API_KEY`, is the executor's.
