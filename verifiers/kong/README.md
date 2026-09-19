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
| `receipt_key_file`     | the PKCS#8 PEM of the Ed25519 key the hop signs effect receipts with (VP-3); unset, the hop signs none                                    | unset                                                                     |
| `receipt_kid`          | the `kid` the key's public half is registered under at the authority (`POST /v1/execution/provider-keys`); required with the key          | —                                                                         |
| `receipt_issuer`       | the `iss` registered with that key; required with the key                                                                                 | —                                                                         |
| `receipt_audience`     | the authority the receipts are for                                                                                                        | `authority_issuer`                                                        |

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

## The receipt (VP-3)

The access phase runs before the upstream effects anything, so it cannot say what was effected.
With `receipt_key_file` set, the plugin's response phase can: once the system of record has
answered a dispatch the access phase accepted, the plugin signs the profile's effect receipt over
the claim it verified, from what the system of record reports about the effect, and sets it on the
answer as `x-agent-safe-effect-receipt`. The executor forwards it unread; Decionis verifies it
under the key registered for `receipt_kid` and records it with the commit.

The system of record reports its effect to the hop in four response headers, which are the hop's
contract with its upstream and never leave the hop: the response phase clears them and the receipt
stands in their place.

| Header                          | Meaning                                                                           | When absent                                                                 |
| ------------------------------- | --------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `x-agent-safe-effect-status`    | `EFFECTED`, `REFUSED` or `INDETERMINATE`                                          | from the status: `2xx` effected, `4xx` refused, anything else indeterminate |
| `x-agent-safe-effect-reference` | the system of record's own reference: a ledger entry, a transaction id            | no reference in the receipt                                                 |
| `x-agent-safe-effect-digest`    | `sha256:` over the effect in the terms the grant's `expected_effect_digest` names | no digest in the receipt, so the authority confirms nothing from it         |
| `x-agent-safe-effected-at`      | when the effect took place, RFC 3339                                              | the plugin's clock                                                          |

A dispatch the access phase refused, a read verified at VP-1 alone, and an answer the plugin
produced itself carry no receipt: nothing was claimed of the hop. A receipt the hop could not stand
behind (a malformed digest, for one) is not signed, and the log says so. Signing in the response
phase means Kong buffers the response for this route, as any response-phase plugin does. A system
of record that signs for itself needs no `receipt_key_file` here, and when one is set anyway its
own `x-agent-safe-effect-receipt` passes through untouched: the system of record's signature beats
the hop's.

## The vectors

```bash
go test ./...
```

drives the plugin, through go-pdk's test harness, with requests from
[`conformance/provider`](../../conformance/provider/README.md), including a dispatch through the
access and response phases whose receipt verifies under the hop's key and answers exactly the
attestation the access phase verified; the verifier package's own suite runs every vector,
request and receipt.
