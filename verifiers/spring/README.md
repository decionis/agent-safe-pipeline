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

## The vectors

```bash
mvn -B test
```

runs every vector in [`conformance/provider`](../../conformance/provider/README.md) through the
library, and the module's own cases for what the vectors cannot express. The one dependency
beyond Jackson is `io.github.erdtman:java-json-canonicalization`, the RFC 8785 canonicaliser;
it, Jackson and the TestNG the tests run on are Apache-2.0, and the servlet API the filter
compiles against is the container's, in `provided` scope.
