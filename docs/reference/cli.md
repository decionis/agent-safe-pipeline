# CLI reference

One binary, `agentsafe`, in every distribution. Commands exit `0` on success, `1` when the command
ran and found something wrong (a failed check, a refusal to start), and `2` when the arguments or
the configuration could not be read.

## Gateway commands

### `agentsafe init`

Writes `agentsafe.yaml` in the current directory and modifies nothing else. It reads
`package.json` for a port a `dev`, `start` or `serve` script names, and `openapi.yaml`, `.yml` or
`.json` for the consequential operations ([routes](../gateway/routes.md)).

| Option             | Meaning                                                             |
| ------------------ | ------------------------------------------------------------------- |
| `--upstream <url>` | the service to protect; else the hint, else `http://localhost:3000` |
| `--port <n>`       | the gateway's port, 8080 by default                                 |
| `--mode <m>`       | `enforcement` (default) or `shadow`                                 |
| `--config <file>`  | where to write, instead of `./agentsafe.yaml`                       |
| `--force`          | replace a file that exists                                          |

### `agentsafe proxy`, `agentsafe run`, `agentsafe gateway`

The gateway as a process. The three names run the same command; `run` reads as "run what the
file says", `proxy` as "put this in front of that". The configuration comes from the flags, the
environment, the file and the stored login, in [that precedence](../gateway/configuration.md).

| Option                          | Meaning                                                        |
| ------------------------------- | -------------------------------------------------------------- |
| `--upstream <url>`              | `gateway.upstream`                                             |
| `--port <n>`                    | the port, on `127.0.0.1`                                       |
| `--listen <host:port>`          | `gateway.listen`; `:8080` binds every interface                |
| `--mode <shadow\|enforcement>`  | `authority.mode`                                               |
| `--failure-policy <p>`          | `failClosed` or `failOpen`                                     |
| `--authority <local\|decionis>` | which authority, when both are possible                        |
| `--config <file>`               | the file, instead of `$AGENTSAFE_CONFIG` or `./agentsafe.yaml` |
| `--verbose`                     | evidence lines and protocol detail on the terminal             |
| `--json`                        | one JSON object per line instead of the human rendering        |

The process prints the banner once it listens, one report per intercepted request, and stops on
`SIGTERM` or `SIGINT`: the listener closes, requests in flight get ten seconds, the gateway closes,
the exit status is `0`. A refusal to start names the setting and never its value.

### `agentsafe status`

Asks the gateway that the same configuration would start, at `/_agentsafe/status`, and prints its
mode, authority, counts and evidence head. `--json` prints the answer as it came.

### `agentsafe doctor`

Checks, in order: the binary and Node version; the configuration; the upstream (a `GET` to it;
any HTTP answer is reachable); Decionis (`GET /v1/health`); the credentials (an empty `POST` to
`enforce-and-bind`, which Decionis refuses as malformed once it has accepted the key, so no decision
is minted: `401`/`403` is a rejected key, `400`/`422` an accepted one); the Presence configuration;
the evidence configuration. Each failure says what to do. `--no-network` skips the three probes;
`--json` prints the checks as data. Exit `1` when any check fails.

### `agentsafe test [name=host:port]...`

The boundary test: a fixed set of consequential requests sent three ways at a synthetic loopback
target that records what reaches it (directly, through the gateway in shadow, through the gateway
in enforcement), then the exposure each way, whether routine work still went through once each,
and whether the evidence the run left verifies. The target and the authority (the local demo
policy) are this process's own; nothing in the configuration, the environment or the stored login
is read, so a real upstream and a real key are never in play. Each `name=host:port` is also dialed
from this machine, as `probe-containment` does, and reported as `REACHABLE`, `CONTAINED` or
`INCONCLUSIVE`.

| Exit | Meaning                                                                                                    |
| ---- | ---------------------------------------------------------------------------------------------------------- |
| `0`  | the boundary holds: nothing adversarial reached the target under enforcement, and no named target answered |
| `1`  | exposure: something adversarial got through under enforcement (a runtime defect), or a target answered     |
| `2`  | the test did not run: wrong arguments, or `NODE_ENV=production`, where the synthetic authority refuses     |

`--json` prints the report as one object, `agent-safe.boundary-test/1`: `cases[]` with `direct`,
`shadow`, `enforcement` (and `failOpen` for the outage case), `exposure`, `workFlowed`,
`evidence`, `verdict` (`BOUNDARY_HOLDS` or `BOUNDARY_BROKEN`), `containment` (null without
targets) and `exit`.

### `agentsafe config`

Prints the effective configuration as YAML (`--json` for JSON), with `sources` naming the layer
each setting came from and `secrets.required` naming which secrets it needs. No secret value is
ever printed.

### `agentsafe login`, `agentsafe logout`

`login` reads a Decionis key from standard input or a prompt that does not echo (never from an
argument, so it enters no shell history), and the organization id (`--tenant`, or a prompt) and
endpoint (`--endpoint`), and stores them at `$AGENTSAFE_HOME/credentials.json`, else
`$XDG_CONFIG_HOME/agentsafe/credentials.json`, else `~/.config/agentsafe/credentials.json`, mode
`0600`. `DECIONIS_API_KEY` in the environment takes precedence over the login; production never
reads the login at all. `logout` removes the file.

### `agentsafe version`

Prints the version. `--version` and `-v` do the same.

## Evidence commands

### `agentsafe verify chain [file]`

Walks the chained lines of a file, or of standard input, and exits `1` on any break. Also spelled
`agentsafe verify-chain`. The gateway's `evidence.jsonl` and the executor's log are both inputs.

### `agentsafe verify bundle <dir>`

Verifies an evidence bundle offline: every file's digest against the manifest, both chains, and the
signature when `AGENTSAFE_EVIDENCE_PUBLIC_KEY` holds the public key. Also spelled
`agentsafe verify-bundle`.

Decision Dossiers are verified with `@decionis/verify`, which uses only Node's built-in crypto:
`npx @decionis/verify --file dossier.json --jwks https://api.decionis.com/.well-known/decision-dossier-jwks.json`
([Decision Dossiers](../decision-dossiers.md)).

## Trusted executor commands

### `agentsafe serve`

Runs the proposal executor from the environment, with the reference forwarding handler: the wire
contract in the [package README](../../packages/agentsafe/README.md), the configuration in its
`Configuration` section, the deployment in the [kit](../../deploy/README.md). Unchanged by the
gateway.

### `agentsafe probe-containment <name=host:port>...`

Runs in the agent zone and reports whether a system of record answers without the executor; exits
`1` when any target does ([bypass resistance](../bypass-resistance.md)).

## The gateway's own routes

Every path under `/_agentsafe/` is the gateway's and is never forwarded:

| Route                                                | Answer                                                                                                  |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `GET /_agentsafe/healthz`                            | `200 {"status":"ok"}` while the process lives                                                           |
| `GET /_agentsafe/readyz`                             | `200` once the listener is bound and the authority is configured                                        |
| `GET /_agentsafe/status`                             | what `agentsafe status` prints, as JSON                                                                 |
| `GET /_agentsafe/metrics`                            | OpenMetrics text; `401` without `Authorization: Bearer $AGENTSAFE_METRICS_TOKEN` when one is set        |
| `GET /_agentsafe/v1/escalations/{intent_id}`         | a held escalation, or `404`                                                                             |
| `POST /_agentsafe/v1/escalations/{intent_id}/resume` | asks the authority again; `202` still held, `409` not resumable, the upstream's answer on a fresh grant |

## Environment

Every variable is listed in the [environment reference](./environment.md).
