# Verifying provider for Spring, and for an Apigee Java callout

An independent Java 17 implementation of the
[Verifying Provider Profile](../../docs/authority/verifying-provider.md), VP-1 and VP-2, as a small
library with a servlet filter. It shares no code with `@decionis/agentsafe` or the Go verifier; it
is written against the profile's text and held to the profile's vectors, which every
implementation must pass.

## The tier this makes

Run inside the API layer an enterprise already has in front of a system of record, this is the
profile's second tier, owner-native verification, on one condition the profile states and no
library can check: the system of record admits nothing but that layer. It holds the system's
only credential, and the system is reachable by nothing else. Without that, the layer is a network
control, and [bypass resistance](../../docs/bypass-resistance.md) says what those are worth.

## Spring

```java
ProviderOptions options = new ProviderOptions(
    true,                                              // this endpoint effects
    List.of(ExecutorKey.ed25519("executor-1", publicKeyPem)),
    Jwks.parse(jwksJson),                              // from https://api.decionis.com/.well-known/decionis-execution-grant-jwks.json
    "https://decionis.com",
    Duration.ofSeconds(300),
    new MemoryReplayStore(),                           // one instance; share a store across instances
    Clock.systemUTC());

@Bean
FilterRegistrationBean<VerifyingProviderFilter> verifyingProvider() {
  var registration = new FilterRegistrationBean<>(new VerifyingProviderFilter(new VerifyingProvider(options)));
  registration.addUrlPatterns("/v1/wires/*");
  registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
  return registration;
}
```

The filter buffers the body up to a bound (one MiB unless given), verifies, and either answers
`409` with the profile's refusal body, `{"status":"REJECTED","reason_code":"…"}`, or hands the
request on with its body intact. A covered header received twice is a refusal; a body beyond the
bound is `413`. Register it ahead of anything that reads the body, and ahead of any path rewrite,
since the profile verifies the path as received.

`VerifyingProvider.verify` is the procedure itself, for a framework other than servlets; the
filter is forty lines around it.

## The target's version

An attestation may name the target's version the grant was decided against,
`binding.expected_state_version`: an ETag with its quotes, or a resource version. A provider that
reads the target before effecting passes what it read, `verify(request, ProviderTarget.at(etag))`,
or `ProviderTarget.gone()` when the target no longer exists. Any other version, compared byte for
byte as a strong `If-Match` compares, is `TARGET_STATE_CHANGED`. That is step 9, after the grant
is recorded, so the grant is spent; its verdict is the one refusal that carries the attestation.
A provider that reads no target calls `verify(request)` and makes
`verdict.attestation().expectedStateVersion()` the precondition of its own conditional write. An
attestation that names no version states no precondition, and the target is not compared.

The filter reads no target. It hands the verified attestation to the handler as the request
attribute `VerifyingProviderFilter.ATTESTATION_ATTRIBUTE`,
`com.decionis.verifyingprovider.attestation`, null for a read verified at VP-1 alone. An endpoint
whose write must hold to the version applies `expected_state_version` as its write's
precondition, a conditional write such as `If-Match`, atomically with the effect. Or it calls
`verify(request, target)` itself with the target's current version.

## Apigee

An Apigee Java callout holds the same class: read the request's method, path, headers and body
from the message context into a `ProviderRequest`, call `VerifyingProvider.verify`, and on a
refusal raise a fault with status `409` and the verdict's `refusalBody()`. The callout's jar is
this module's jar with its dependencies shaded in; the Apigee message-flow jars are the proxy's,
not this module's, which is why the callout class lives beside the proxy rather than here.

## Keys and the authority

The executor names its key with `DOWNSTREAM_SIGNING_KEY_ID`; `ExecutorKey.ed25519` takes that
`keyid` with the SPKI PEM of `DOWNSTREAM_SIGNING_KEY`'s public half, and `ExecutorKey.hmac` a
shared secret for `hmac-sha256`. `Jwks.parse` reads the authority's execution-grant key set as
its well-known path serves it; fetch it from the authority's API origin, cache it, and refresh on
an unknown `kid` at most once per bounded interval, as the profile's section 9 says.

## The receipt (VP-3)

After effecting, a service at VP-3 answers with its receipt, built from the attestation the
verifier returned and signed with the service's own Ed25519 key, the public half of which the
organisation registered at `POST /v1/execution/provider-keys`:

```java
String token = new EffectReceipt(
    "core-receipts-1", "https://core.example", "https://decionis.com",
    verdict.attestation(), Optional.of(idempotencyKey),
    new EffectReceipt.Effect(EffectReceipt.Status.EFFECTED, Optional.of("ledger:9081"),
        Optional.of(effectDigest), Instant.now().toString()),
    Instant.now().getEpochSecond(), UUID.randomUUID().toString())
    .sign(privateKey);
response.setHeader(EffectReceipt.HEADER, token);
```

A `TARGET_STATE_CHANGED` verdict carries the attestation too, so the provider receipts that
refusal the same way, with `EffectReceipt.Status.REFUSED`.

The header and the claims are RFC 8785 canonical before signing, so the receipt vectors hold every
implementation to the same bytes.

## The vectors

```bash
mvn -B test
```

runs every vector in [`conformance/provider`](../../conformance/provider/README.md), request and
receipt, through the library, and the module's own cases for what the vectors cannot express. The one dependency
beyond Jackson is `io.github.erdtman:java-json-canonicalization`, the RFC 8785 canonicaliser;
it, Jackson and the TestNG the tests run on are Apache-2.0, and the servlet API the filter
compiles against is the container's, in `provided` scope.
