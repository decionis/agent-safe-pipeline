# Verifying provider in Rust, with a tower layer

An independent Rust implementation of the
[Verifying Provider Profile](../../docs/authority/verifying-provider.md), VP-1 and VP-2, as a
library crate, `decionis-verifying-provider`, with a `tower` layer behind a feature flag for
axum, hyper and anything else that speaks `http::Request`. It shares no code with
`@decionis/agentsafe`, the Go verifier or the Java one; it is written against the profile's text
and held to the profile's vectors, which every implementation must pass. `#![forbid(unsafe_code)]`
throughout.

The dependency tree is deliberately small: the RFC 8785 canonicaliser is the crate's own over
`serde_json`'s value type (names by UTF-16 code unit, numbers as ECMAScript prints them through
`ryu-js`, correctly rounded parsing through serde_json's `float_roundtrip`), the JSON reading is
by hand so no derive macro is compiled, and Ed25519 is `ed25519-compact`, which depends on
nothing. Every crate compiled is MIT, Apache-2.0 or BSD. The crate is a library, so it carries no
lockfile; the consumer's pins it.

## The tier this makes

Run inside the service an enterprise already has in front of a system of record, this is the
profile's second tier, owner-native verification, on one condition the profile states and no
library can check: the system of record admits nothing but that service. It holds the system's
only credential, and the system is reachable by nothing else. Without that, the service is a
network control, and [bypass resistance](../../docs/bypass-resistance.md) says what those are
worth.

## The library

```rust
use decionis_verifying_provider::{verify, ExecutorKey, Jwks, MemoryReplayStore, Options, Request, Verdict};

let options = Options {
    effects: true,                                                // this endpoint effects
    executor_keys: vec![ExecutorKey::ed25519_pem("executor-1", public_key_pem)?],
    authority_jwks: Jwks::parse(jwks_json)?,                      // from https://api.decionis.com/.well-known/decionis-execution-grant-jwks.json
    authority_issuer: "https://decionis.com".to_owned(),
    clock_window_seconds: 300,
    replay: Box::new(MemoryReplayStore::default()),               // one instance; share a store across instances
    now: Box::new(decionis_verifying_provider::unix_now),
};

match verify(&Request { method, path, body, headers: &lower_case_headers }, &options) {
    Verdict::Accepted(attestation) => { /* effect once */ }
    Verdict::Refused(refusal) => { /* answer 409 with refusal.body() */ }
}
```

`verify` is the whole procedure for one received request; header names are lower case, and a
covered header received twice is the caller's to refuse before it collapses the map.

## The tower layer

```toml
decionis-verifying-provider = { version = "0.1", features = ["tower"] }
```

```rust
use decionis_verifying_provider::tower::VerifyingProviderLayer;

let app = axum::Router::new()
    .route("/v1/wires", axum::routing::post(wire))
    .layer(VerifyingProviderLayer::new(options).max_body_bytes(1 << 20));
```

The layer buffers the body up to its bound, verifies, and either answers `409` with the profile's
refusal body, `{"status":"REJECTED","reason_code":"…"}`, or hands the request on with its body
intact. A covered header received twice is a refusal; a body beyond the bound is `413`. Put the
layer ahead of any path rewrite, since the profile verifies the path as received. The inner
service takes a `Full<Bytes>` body, which axum's and hyper's bodies are made from.

## Keys and the authority

The executor names its key with `DOWNSTREAM_SIGNING_KEY_ID`; `ExecutorKey::ed25519_pem` takes
that `keyid` with the SPKI PEM of `DOWNSTREAM_SIGNING_KEY`'s public half, and
`ExecutorKey::hmac` a shared secret for `hmac-sha256`. `Jwks::parse` reads the authority's
execution-grant key set as its well-known path serves it; fetch it from the authority's API
origin, cache it, and refresh on an unknown `kid` at most once per bounded interval, as the
profile's section 9 says.

## The vectors

```bash
cargo test --all-features
```

runs every vector in [`conformance/provider`](../../conformance/provider/README.md) through the
library and, with the `tower` feature, through the layer, and the crate's own cases for what the
vectors cannot express: the RFC 8785 examples, the pipeline's own canonicalization notes, and the
bodies another parser would read differently.
