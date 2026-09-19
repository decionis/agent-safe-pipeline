# Verifying provider as a Kong Gateway plugin

A Kong Gateway plugin, through Kong's Go plugin server, that runs the
[Verifying Provider Profile](../../docs/authority/verifying-provider.md) on every request bound
for the system of record behind a route. The procedure is the `verifier` package of
[`verifiers/envoy`](../envoy/README.md), imported unchanged, so Kong and Envoy verify identically
and pass the same vectors; the plugin is the eighty lines that map Kong's request onto the
procedure and its refusal onto Kong's response.

## The tier this makes

Kong in front of a system of record is the profile's second tier, owner-native verification, on
one condition the profile states and no plugin can check: the system of record admits nothing but
Kong. Kong holds the system's only credential, and the system is reachable by nothing else.
Without that, the route is a network control, and [bypass resistance](../../docs/bypass-resistance.md)
says what those are worth.

## Building and installing

```bash
go build -o verifying-provider .
```

The binary's name is the plugin's name. Kong runs it as a plugin server, one process beside the
gateway (`kong.conf`, or the same settings as `KONG_…` environment variables):

```ini
plugins = bundled,verifying-provider
pluginserver_names = verifying-provider
pluginserver_verifying_provider_socket = /usr/local/kong/verifying-provider.socket
pluginserver_verifying_provider_start_cmd = /usr/local/bin/verifying-provider
pluginserver_verifying_provider_query_cmd = /usr/local/bin/verifying-provider -dump
```

Then the plugin on the route, in declarative configuration or through the Admin API:

```yaml
_format_version: "3.0"
services:
  - name: core-banking
    url: https://core.internal
    routes:
      - name: wires
        paths: ["/v1/wires"]
        plugins:
          - name: verifying-provider
            config:
              executor_keys_file: /etc/kong/executor-keys.json
              authority_jwks: https://api.decionis.com/.well-known/decionis-execution-grant-jwks.json
              authority_issuer: https://decionis.com
              clock_window_seconds: 300
              effects: true
              max_body_bytes: 1048576
```

| Field                  | Meaning                                                                                                                                   | Default                                                                   |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `executor_keys_file`   | a JSON array of the executor keys this provider issued, in the vectors' shape: `keyid`, `alg`, and `public_pem` or `shared_material_utf8` | required                                                                  |
| `authority_jwks`       | the authority's execution-grant JWKS: an `https://` URL, refreshed every ten minutes and on a refusal at most once a minute, or a file    | `https://api.decionis.com/.well-known/decionis-execution-grant-jwks.json` |
| `authority_issuer`     | the `iss` the provider trusts                                                                                                             | `https://decionis.com`                                                    |
| `clock_window_seconds` | how far `created` may lie from now, each way                                                                                              | `300`                                                                     |
| `effects`              | whether the route effects; `false` verifies reads at VP-1 alone                                                                           | `true`                                                                    |
| `max_body_bytes`       | the body bound; a larger body is refused with `413`                                                                                       | `1048576`                                                                 |

The executor names its key with `DOWNSTREAM_SIGNING_KEY_ID`; the file here carries that `keyid`
with the public half of `DOWNSTREAM_SIGNING_KEY`.

The plugin answers `409` with the profile's refusal body, `{"status":"REJECTED","reason_code":"…"}`,
when the profile refuses, which the executor records as `DEFINITELY_NOT_EXECUTED`, and lets the
request through unchanged when it accepts. A covered header received twice is a refusal; a body
beyond the bound is `413`; a plugin that could not load its keys refuses everything with `503`
rather than wave through. One plugin server keeps its replay record in memory; more than one
Kong node that can effect the same grant needs a shared store behind `verifier.ReplayStore`.
Each verdict is one JSON log line naming the method, the path, the grant id and the reason; never
a body, a header value or an attestation. Put the plugin ahead of any path rewrite, since the
profile verifies the path as received; Kong's `request-transformer` runs at a lower priority
than this plugin's `1000`, so it does.

## The vectors

```bash
go test ./...
```

drives the plugin, through go-pdk's test harness, with requests from
[`conformance/provider`](../../conformance/provider/README.md), and the verifier package's own
suite runs every vector, request and receipt.

The plugin runs in Kong's access phase, before the upstream effects anything, so it signs no
receipt (VP-3); the upstream does, with the verifier package's `Receipt`, or a response-phase
plugin does on its behalf once the upstream reports its effect to it, which is a follow-up.
