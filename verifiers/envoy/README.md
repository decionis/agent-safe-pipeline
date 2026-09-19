# Verifying provider for Envoy `ext_authz`

An independent Go implementation of the
[Verifying Provider Profile](../../docs/authority/verifying-provider.md), VP-1 and VP-2, and a
small server that runs it behind Envoy's `ext_authz` filter in HTTP mode: the hop an enterprise
already has in front of a system of record (Envoy itself, or Istio, Contour, Gloo, Emissary, which
carry it) becomes a verifying provider without the system of record learning anything new.

The package `verifier` shares no code with `@decionis/agentsafe`; it is written against the
profile's text and held to the profile's vectors, which both implementations must pass.

## The tier this makes

Run beside the last hop the owner controls, this is the profile's second tier, owner-native
verification, on one condition the profile states and this server cannot check: the system of
record admits nothing but that hop. It holds the system's only credential, and the system is
reachable by nothing else. Without that, the hop is a network control, and
[bypass resistance](../../docs/bypass-resistance.md) says what those are worth.

## Running it

```bash
go build ./cmd/extauthz
EXECUTOR_KEYS_FILE=executor-keys.json ./extauthz
```

| Variable               | Meaning                                                                                                                                   | Default                                                                   |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `EXECUTOR_KEYS_FILE`   | a JSON array of the executor keys this provider issued, in the vectors' shape: `keyid`, `alg`, and `public_pem` or `shared_material_utf8` | required                                                                  |
| `AUTHORITY_JWKS`       | the authority's execution-grant JWKS: an `https://` URL, refreshed every ten minutes and on a refusal at most once a minute, or a file    | `https://api.decionis.com/.well-known/decionis-execution-grant-jwks.json` |
| `AUTHORITY_ISSUER`     | the `iss` the provider trusts                                                                                                             | `https://decionis.com`                                                    |
| `CLOCK_WINDOW_SECONDS` | how far `created` may lie from now, each way                                                                                              | `300`                                                                     |
| `EFFECTS`              | whether the endpoints behind this hop effect; `false` verifies reads at VP-1 alone                                                        | `true`                                                                    |
| `MAX_BODY_BYTES`       | the body bound; a larger body is refused with `413`                                                                                       | `1048576`                                                                 |
| `PATH_PREFIX`          | Envoy's `path_prefix`, removed before the path is verified                                                                                | empty                                                                     |
| `LISTEN`               | the address to listen on                                                                                                                  | `127.0.0.1:9001`                                                          |

The executor names its key with `DOWNSTREAM_SIGNING_KEY_ID`; the file here carries that `keyid`
with the public half of `DOWNSTREAM_SIGNING_KEY`.

The server answers `200` with no body when the profile accepts the request, and `409` with the
profile's refusal body, `{"status":"REJECTED","reason_code":"…"}`, when it does not; in HTTP mode
Envoy returns that status and body to the executor unchanged, which the executor records as
`DEFINITELY_NOT_EXECUTED`. One instance keeps its replay record in memory; more than one instance
that can effect the same grant needs a shared store behind `verifier.ReplayStore`. Each verdict is
one JSON log line naming the method, the path, the grant id and the reason; never a body, a header
value or an attestation.

## Envoy

The filter must send the whole body, since the content digest is over its bytes, and must send
the covered headers:

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      failure_mode_allow: false
      with_request_body:
        max_request_bytes: 1048576
        allow_partial_message: false
      http_service:
        server_uri:
          uri: http://127.0.0.1:9001
          cluster: verifying_provider
          timeout: 2s
        authorization_request:
          allowed_headers:
            patterns:
              - exact: content-digest
              - exact: idempotency-key
              - exact: signature
              - exact: signature-input
              - prefix: x-agent-safe-
        authorization_response:
          allowed_upstream_headers:
            patterns: []
```

`failure_mode_allow: false` keeps the boundary closed when this server is down: an unreachable
verifier refuses, it never waves through. Verify with the path as Envoy received it, before any
rewrite: put this filter ahead of rewrites in the chain, or hand it the same `path_prefix` you
set here.

## The receipt (VP-3)

`ext_authz` answers before the upstream effects anything, so the check itself cannot sign a
receipt. The package carries the builder for the layer that can, the upstream service or a
response-phase filter it reports its effect to:

```go
token, err := verifier.Receipt{
    KeyID:       "core-receipts-1",              // registered at POST /v1/execution/provider-keys
    Issuer:      "https://core.example",
    Audience:    "https://decionis.com",
    Attestation: verdict.Attestation,            // what Verify returned
    Effect:      verifier.Effect{Status: verifier.Effected, Reference: "ledger:9081", Digest: effectDigest, EffectedAt: time.Now()},
    IssuedAt:    time.Now().Unix(),
    JTI:         uuid.NewString(),
}.Sign(privateKey)
w.Header().Set(verifier.ReceiptHeader, token)
```

The header and the claims are RFC 8785 canonical before signing, so the receipt vectors hold every
implementation to the same bytes.

## The vectors

```bash
go test ./...
```

runs every vector in [`conformance/provider`](../../conformance/provider/README.md), request and
receipt, through the package and the handler, and the package's own cases for what the vectors
cannot express.
