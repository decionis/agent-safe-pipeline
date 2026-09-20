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

The runtime reports, once each, the steps of its own adoption, on the report stream, as a name and
a time and nothing else. On a terminal each is one dim line (`✓ first governed action`); in JSON
output it is `{"event":"ACTIVATION","milestone":"...","at":"..."}`; `/_agentsafe/status` shows the
gateway's own under `activation`. The path, in order (`ACTIVATION_PATH`):

| Step                    | Reached when                                                                                            | Reported by                     |
| ----------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------- |
| `installation`          | the installer's last line, `Installed agentsafe <version>`; a process cannot see itself being installed | `install.sh`                    |
| `boundary_tested`       | `agentsafe test` ran to a verdict, whatever it found; the gateway cannot see a test that ran before it  | `agentsafe test`, its last line |
| `gateway_started`       | the listener is bound                                                                                   | the gateway                     |
| `shadow_enabled`        | started in shadow                                                                                       | the gateway                     |
| `first_interception`    | the first consequential request was captured and evaluated                                              | the gateway                     |
| `first_governed_action` | the first verdict was enforced: forwarded once, held, or refused                                        | the gateway                     |
| `decionis_connected`    | started against Decionis rather than the demo authority                                                 | the gateway                     |
| `enforcement_enabled`   | started in enforcement                                                                                  | the gateway                     |
| `production_deployment` | started under `NODE_ENV=production`                                                                     | the gateway                     |

`first_governed_action` is the number this repository measures itself by.

## The funnel end to end

Each step is measured where it can be seen, and nowhere is a person or a machine identified:

| Step                                                                                                     | Where it is counted                                                                                                                                                                                                                                                                                                                            |
| -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| installation, by surface                                                                                 | Release asset downloads to date, per asset, recorded daily on the `metrics` branch (`github-releases.jsonl`): what Homebrew, the installer and the Linux packages fetch. npm downloads per package beside them. Image pulls from GHCR and a tap's Homebrew installs have no public counter and are not estimated                               |
| `boundary_tested`, `gateway_started`, first interception and governed action, against the demo authority | The process's own lines only; nothing is sent                                                                                                                                                                                                                                                                                                  |
| `decionis_connected`, first governed action against Decionis, `enforcement_enabled`                      | The authority's own record of the calls it received: every `enforce-and-bind` carries `mode` (`SHADOW` or `ENFORCEMENT`) in its body and, in its `User-Agent`, the runtime (`example=agentsafe-gateway@<version>`) and the surface it was installed from (`surface=homebrew`, `linux`, `installer`, `docker`, `kubernetes`, `npm` or `source`) |

Read down the last row per surface and the funnel is one question per distribution: of the
installs this surface produced, how many reached a first governed action against Decionis, and
how many of those turned enforcement on. The surface is one closed token from `AGENTSAFE_SURFACE`,
which the image, the chart and the systemd unit set, or from where the executable sits when the
variable is unset; a location that is none of the named ones sends no surface at all, never a
guess. What the authority does with the token is its own accounting; it is not decision input and
does not enter the dossier.

## What leaves the process

Nothing about the funnel. The milestones are written where the gateway's own output goes and
nowhere else; there is no telemetry endpoint, no opt-in for one, and no identifier of the machine,
the user or the network in any line. The only thing Decionis learns is what every hosted call
already carries: the `User-Agent` of `enforce-and-bind`, `claim-token` and `finalize-token`,
naming the pipeline package and its version, `example=agentsafe-gateway@<version>`, and the
install surface when one is known, all of which is sent only when a key is configured, is not
decision input, and does not enter the dossier ([how it is wired](../../README.md#how-it-is-wired)).
`agentsafe login --provision`, run by the person, sends the same `User-Agent` on its one call to
mint a workspace, and nothing else. `agentsafe status` shows the surface the process would send as
`Surface`.

## What is never in a metric or a line

Request bodies, response bodies, request headers, credentials, grant tokens, Presence biometrics,
secrets or their digests. The [evidence](../authority/evidence.md) page says what a line carries.
