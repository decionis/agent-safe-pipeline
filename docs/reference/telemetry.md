# Telemetry reference

What the gateway measures, what it records about adoption, and what it never sends.

## Operational metrics

`GET /_agentsafe/metrics` renders OpenMetrics text (guarded by `AGENTSAFE_METRICS_TOKEN` when one
is set), which a Prometheus scraper or an OpenTelemetry collector's Prometheus receiver reads. No
SDK is embedded. Label values are verdicts, states, codes and the action names the configuration
itself produced, never anything a caller sent.

| Family                                         | Labels    | Meaning                                                 |
| ---------------------------------------------- | --------- | ------------------------------------------------------- |
| `agentsafe_requests_total`                     | `kind`    | requests received: `governed`, `passthrough`, `control` |
| `agentsafe_interceptions_total`                | `action`  | consequential requests captured as intents              |
| `agentsafe_decisions_total`                    | `verdict` | authority decisions received in enforcement             |
| `agentsafe_allows_total`                       |           | `ALLOW` decisions enforced                              |
| `agentsafe_blocks_total`                       |           | `BLOCK` decisions enforced                              |
| `agentsafe_escalations_total`                  |           | `ESCALATE` decisions held                               |
| `agentsafe_shadow_decisions_total`             | `verdict` | what the authority would have decided, in shadow        |
| `agentsafe_authority_latency_ms_sum`, `_count` |           | time waiting for the authority                          |
| `agentsafe_forward_latency_ms_sum`, `_count`   |           | time waiting for the upstream                           |
| `agentsafe_authority_errors_total`             | `code`    | fail-closed authority outcomes, by reason code          |
| `agentsafe_execution_indeterminate_total`      |           | executions whose upstream outcome is unknown            |
| `agentsafe_ungoverned_forwards_total`          |           | forwards under an explicit fail-open policy             |
| `agentsafe_escalations_held`                   |           | escalations held right now (a gauge)                    |

The two latency families are a running sum and a count, from which a scraper computes rates and
means between scrapes.

## Activation milestones

The gateway reports, once each, the milestones of its own adoption, on the report stream, as a
name and a time and nothing else. On a terminal each is one dim line (`✓ first governed action`);
in JSON output it is `{"event":"ACTIVATION","milestone":"...","at":"..."}`; `/_agentsafe/status`
shows them under `activation`.

| Milestone               | Reached when                                                                                            |
| ----------------------- | ------------------------------------------------------------------------------------------------------- |
| `installation`          | the installer's last line, `Installed agentsafe <version>`; a process cannot see itself being installed |
| `gateway_started`       | the listener is bound                                                                                   |
| `shadow_enabled`        | started in shadow                                                                                       |
| `enforcement_enabled`   | started in enforcement                                                                                  |
| `decionis_connected`    | started against Decionis rather than the demo authority                                                 |
| `production_deployment` | started under `NODE_ENV=production`                                                                     |
| `first_interception`    | the first consequential request was captured and evaluated                                              |
| `first_governed_action` | the first verdict was enforced: forwarded once, held, or refused                                        |

`first_governed_action` is the number this repository measures itself by.

## What leaves the process

Nothing about the funnel. The milestones are written where the gateway's own output goes and
nowhere else; there is no telemetry endpoint, no opt-in for one, and no identifier of the machine,
the user or the network in any line. The only thing Decionis learns is what every hosted call
already carries: the `User-Agent` of `enforce-and-bind`, `claim-token` and `finalize-token`,
naming the pipeline package and its version and `example=agentsafe-gateway@<version>`, which is
sent only when a key is configured, is not decision input, and does not enter the dossier
([how it is wired](../../README.md#how-it-is-wired)).

## What is never in a metric or a line

Request bodies, response bodies, request headers, credentials, grant tokens, Presence biometrics,
secrets or their digests. The [evidence](../authority/evidence.md) page says what a line carries.
