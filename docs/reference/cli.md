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

### `agentsafe intercept`

The [transparent interceptor](../gateway/transparent-interception.md) as a process: the sidecar
the redirect rules point at. It binds two loopback listeners, one for redirected port-80
connections and one for redirected port-443 connections, reads each connection's destination from
its first bytes (the TLS server name, or the HTTP host), places, governs or refuses it, and prints
one line per connection; `SIGTERM` prints the report of every destination the workload reached
and exits `0`. With nothing to govern it decrypts nothing, decides nothing, holds no key and asks
no authority. With `--govern`, connections to the listed hosts are taken by a gateway for that
host, TLS terminated under the operator's authority, and the gateway's own options and environment
apply as they do to `proxy`.

| Option                                                               | Meaning                                                                                 |
| -------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `--http-port <n>`                                                    | `AGENTSAFE_INTERCEPT_HTTP_PORT`, where redirected `:80` arrives                         |
| `--https-port <n>`                                                   | `AGENTSAFE_INTERCEPT_HTTPS_PORT`, where redirected `:443` arrives                       |
| `--bind <address>`                                                   | `AGENTSAFE_INTERCEPT_BIND`, the listeners' address (`127.0.0.1`)                        |
| `--govern <hosts>`                                                   | `AGENTSAFE_INTERCEPT_GOVERN`, host names to govern, comma-separated                     |
| `--unlisted <passthrough\|refuse>`                                   | `AGENTSAFE_INTERCEPT_UNLISTED`, what becomes of a destination not governed              |
| `--ca-cert <file>`                                                   | `AGENTSAFE_INTERCEPT_CA_CERT_FILE`, the operator authority's certificate                |
| `--ca-key <file>`                                                    | `AGENTSAFE_INTERCEPT_CA_KEY_FILE`, its private key; with the certificate, never without |
| `--mode`, `--failure-policy`, `--authority`, `--config`, `--verbose` | the governed gateways' settings, as for `proxy`                                         |
| `--json`                                                             | one JSON object per line instead of the human rendering                                 |

### `agentsafe status`

Asks the gateway that the same configuration would start, at `/_agentsafe/status`, and prints its
mode, authority, install surface, counts and evidence head. For a gateway in shadow it goes on to
print the [shadow report](../shadow-mode.md#from-shadow-to-enforcement): what the authority would
have allowed, held and refused so far, by action, and the switch that turns enforcement on for
this configuration. `--json` prints the answer as it came, the report inside it as `shadow`.

### `agentsafe doctor`

Checks, in order: the binary and Node version; the configuration; the upstream (a `GET` to it;
any HTTP answer is reachable); Decionis (`GET /v1/health`); the credentials (an empty `POST` to
`enforce-and-bind`, which Decionis refuses as malformed once it has accepted the key, so no decision
is minted: `401`/`403` is a rejected key, `400`/`422` an accepted one); the Presence configuration;
the evidence configuration. Each failure says what to do. `--no-network` skips the three probes;
`--json` prints the checks as data. Exit `1` when any check fails.

### `agentsafe identity`

Which enforcement boundary this process is: the id and whether an operator named it or the
configuration derived it, the runtime, the versions, the environment, the conformance profile, and
the stable placement the manifest declared. `--json` prints it as data. It reads the gateway
configuration when there is one and describes what it would resolve to when there is not, so it
can be run before anything is configured. The container, pod and node appear beneath the report
and are bound into no intent and signed into no evidence. When a runtime declared the artifact this
process runs as, the workload appears too, with its trust source beside it — `supplied`, never
`verified` ([workload provenance](../authority/workload-provenance.md)). Exit `0`; see
[the enforcement boundary](../authority/enforcement-boundary.md).

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
targets), `exit`, and `activation` (`boundary_tested`, the step of the
[adoption path](./telemetry.md#activation-milestones) the run is; on a terminal it is the last
line, `✓ boundary tested`). The `Caller` line above the verdict says what the table shows: the
same caller on every row, never the reason anything was refused
([the Compromised Principal Test](../compromised-principal-test.md)).

Beneath the table, **After the authority is issued**: six attacks that cannot be expressed as bytes
sent at a target, because each needs an authority to exist before it can be attempted. The amount
changed after authorization, the beneficiary changed, a consumed grant presented again, another
workload reusing an approved release's authority, an authority admitted at one boundary presented
at another, and a valid principal proposing an action policy refuses. They are executed, not
described: real intents, real decisions, real claims, and the refusal each produced is printed.
The verdict is `BOUNDARY BROKEN` if any of them was not refused, whatever the requests did.

### `agentsafe test --hosted`

The same requests, without the outage case, sent two ways at the same synthetic target: directly,
and through the gateway in shadow against the Decionis workspace this machine is logged into. This
is the one test that reads the stored login and the `DECIONIS_*` variables (`DECIONIS_API_KEY`,
`_API_KEY_FILE`, `_API_URL`, `_TENANT_ID`, `_TIMEOUT_MS`, `_ALLOW_INSECURE_LOOPBACK`, and
`NODE_ENV`; nothing else, no file, no `AGENTSAFE_*`), and it says so. Nothing real is called and
nothing is enforced; what the run produces is the first governed action against Decionis for the
workspace, one signed Decision Dossier per consequential request, and the first record fetched
with the run's own key and shown by its proof (algorithm, key, issuer tier). A workspace from
`agentsafe login --provision` is enough: it decides in shadow, which is the one lane this test
runs. Every hosted call names the test, `example=agentsafe-test@<version>`, so the authority's
record tells a test run from a gateway in service. It takes no targets.

| Exit | Meaning                                                                                       |
| ---- | --------------------------------------------------------------------------------------------- |
| `0`  | `DECIONIS_DECIDED`: every consequential request got a verdict                                 |
| `1`  | `AUTHORITY_UNREACHABLE` or `PARTLY_DECIDED`: Decionis could not be asked about some or all    |
| `2`  | no login (the message names `agentsafe login --provision` and `agentsafe login`), or a target |

`--json` prints `agent-safe.hosted-boundary-test/1`: `authority` (endpoint, tenant, `provisional`,
`mode`), `cases[]` with `direct` and `decionis` (`consequential`, `status`, `state`, `verdict`,
`reason_codes`, `decision_id`, `dossier_id`), `decided`, `dossiers[]`, `signed` (the first record's
summary, or null with `signedUnavailable` naming why), `milestones` (what the shadow lane reported
of the [adoption path](./telemetry.md#activation-milestones): `decionis_connected` among them),
`verdict`, `exit`, `activation`.

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

`login --provision` mints a free provisional Decionis workspace instead (`POST
/v1/public/agents/provision`: no account, no email, no card, an allowance of governed decisions a
month) and stores its key as the login, the same file and shape an example writes under
`DECIONIS_HOSTED=1`. Such a workspace decides in shadow only: `agentsafe proxy` runs it there and
refuses `--mode enforcement` with it by name; enforcement needs `login` with a key from an
organization. The call carries what every hosted call carries, the runtime's version and the
install surface, and nothing about the machine or the person. With a login already stored, nothing
is minted: a stored provisional workspace is named, a stored key is kept.

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

### `agentsafe verify intent <file|dir>... [--json]`

Agent-Safe Intent conformance, offline ([the specification](../../spec/intent/v1/README.md#7-conformance)).
Each file is a vector from [`conformance/`](../../conformance) or a binding of your own; a
directory is every `.json` file in it. For a vector the canonical bytes and the hash are
recomputed with the runtime's own canonicalizer and compared, a whole binding is held to the
strict schema, and every mutation the vector carries must reproduce and hash differently from the
base and from the others. For a bare binding (no `intent_hash`) the bytes and the hash are
printed, so another implementation can compare its own.

| Exit | Meaning                                                                            |
| ---- | ---------------------------------------------------------------------------------- |
| `0`  | every pinned hash reproduced (or, with nothing pinned, every binding was computed) |
| `1`  | a vector did not reproduce; each finding names the expected and the computed value |
| `2`  | no path, an unknown option, or a named file that is not there or not JSON          |

`--json` prints the report as one object, `agent-safe.intent-conformance/1`: `files[]` with
`kind` (`binding`, `canonical` or `unrecognised`), `ok`, `pinned`, `canonical_json`,
`intent_hash`, `mutations`, `hashes` and `findings[]`, then `unreadable[]`, `reproduced`,
`computed`, `failed` and `exit`.

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
