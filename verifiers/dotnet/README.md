# Verifying provider for .NET, with ASP.NET Core middleware

An independent .NET 8 implementation of the
[Verifying Provider Profile](../../docs/authority/verifying-provider.md), VP-1 and VP-2, as a
class library, `Decionis.VerifyingProvider`, with ASP.NET Core middleware. It shares no code with
`@decionis/agentsafe` or the Go, Java and Rust verifiers; it is written against the profile's
text and held to the profile's vectors, which every implementation must pass.

The RFC 8785 canonicaliser is the library's own over `System.Text.Json`: names by UTF-16 code
unit, which ordinal comparison is; numbers as ECMAScript prints them, from the shortest
round-trip digits .NET gives and the form the specification's thresholds choose; strings escaped
as the RFC lists. Ed25519, which .NET 8 does not carry, is `BouncyCastle.Cryptography`, MIT.

## The tier this makes

Run inside the API an enterprise already has in front of a system of record, this is the
profile's second tier, owner-native verification, on one condition the profile states and no
library can check: the system of record admits nothing but that API. It holds the system's only
credential, and the system is reachable by nothing else. Without that, the API is a network
control, and [bypass resistance](../../docs/bypass-resistance.md) says what those are worth.

## ASP.NET Core

```csharp
var options = new ProviderOptions(
    Effects: true,                                              // this endpoint effects
    ExecutorKeys: new[] { ExecutorKey.Ed25519("executor-1", publicKeyPem) },
    AuthorityJwks: Jwks.Parse(jwksJson),                        // from https://api.decionis.com/.well-known/decionis-execution-grant-jwks.json
    AuthorityIssuer: "https://decionis.com",
    ClockWindow: TimeSpan.FromSeconds(300),
    Replay: new MemoryReplayStore(),                            // one instance; share a store across instances
    Now: () => DateTimeOffset.UtcNow);

app.UseWhen(context => context.Request.Path.StartsWithSegments("/v1/wires"),
    branch => branch.UseVerifyingProvider(options, maxBodyBytes: 1 << 20));
```

The middleware buffers the body up to its bound, verifies, and either answers `409` with the
profile's refusal body, `{"status":"REJECTED","reason_code":"…"}`, or hands the request on with
its body intact. A covered header received twice is a refusal; a body beyond the bound is `413`.
Register it ahead of anything that reads the body, and ahead of any path rewrite, since the
profile verifies the path as received. It reads that path from the raw request target, not from
`Request.Path`, which ASP.NET Core decodes and, under `Map`, splits into `PathBase`: a signed
`/v1/accounts/acme%20corp` verifies as it was signed, wherever the middleware is mounted.

`VerifyingProvider.Verify` is the procedure itself, for a host other than ASP.NET Core; the
middleware is sixty lines around it.

## The target's version

An attestation may name the target's version the grant was decided against,
`binding.expected_state_version`: an ETag with its quotes, or a resource version. A provider that
reads the target before effecting passes what it read, `Verify(request, new ProviderTarget(etag))`,
or `new ProviderTarget(null)` when the target no longer exists. Any other version, compared byte
for byte as a strong `If-Match` compares, is `TARGET_STATE_CHANGED`. That is step 9, after the
grant is recorded, so the grant is spent; its verdict is the one refusal that carries the
attestation. A provider that reads no target calls `Verify(request)` and makes
`verdict.Attestation.ExpectedStateVersion` the precondition of its own conditional write. An
attestation that names no version states no precondition, and the target is not compared.

The middleware reads no target. It hands the verified attestation to the endpoint in
`HttpContext.Items` under `VerifyingProviderMiddleware.AttestationItem`, null for a read verified
at VP-1 alone; `VerifyingProviderMiddleware.TryGetAttestation(context, out var attestation)` reads
it. An endpoint whose write must hold to the version applies `expected_state_version` as its
write's precondition, a conditional write such as `If-Match`, atomically with the effect. Or it
calls `Verify(request, target)` itself with the target's current version.

## Keys and the authority

The executor names its key with `DOWNSTREAM_SIGNING_KEY_ID`; `ExecutorKey.Ed25519` takes that
`keyid` with the SPKI PEM of `DOWNSTREAM_SIGNING_KEY`'s public half, and `ExecutorKey.Hmac` a
shared secret for `hmac-sha256`. `Jwks.Parse` reads the authority's execution-grant key set as
its well-known path serves it; fetch it from the authority's API origin, cache it, and refresh on
an unknown `kid` at most once per bounded interval, as the profile's section 9 says.

## The receipt (VP-3)

After effecting, a service at VP-3 answers with its receipt, built from the attestation the
verifier returned and signed with the service's own Ed25519 key, the public half of which the
organisation registered at `POST /v1/execution/provider-keys`:

```csharp
var token = new EffectReceipt(
    "core-receipts-1", "https://core.example", "https://decionis.com",
    verdict.Attestation!, idempotencyKey,
    new Effect(EffectStatus.Effected, "ledger:9081", effectDigest, DateTimeOffset.UtcNow.ToString("O")),
    DateTimeOffset.UtcNow.ToUnixTimeSeconds(), Guid.NewGuid().ToString())
    .Sign(privateKey);
context.Response.Headers[EffectReceipt.Header] = token;
```

A `TARGET_STATE_CHANGED` verdict carries the attestation too, so the provider receipts that
refusal the same way, with `EffectStatus.Refused`.

The header and the claims are RFC 8785 canonical before signing, so the receipt vectors hold every
implementation to the same bytes.

## The vectors

```bash
dotnet test
```

runs every vector in [`conformance/provider`](../../conformance/provider/README.md), request and
receipt, through the library and, for a sample, through the middleware, and the library's own cases for what the
vectors cannot express: the RFC 8785 examples, ECMAScript's number forms, and the bodies another
parser would read differently. The test dependencies are xunit (Apache-2.0) and the test SDK
(MIT). Each project's `packages.lock.json` records the version and content hash of every package
the restore resolved; CI restores with `dotnet restore --locked-mode`, so a package that is not what
the lock file records fails the build rather than being taken from the feed. A restore after a
`PackageReference` change rewrites the lock file, and the change commits both.

## Releases

A release is `Decionis.VerifyingProvider` on NuGet, at the version in the project file, with this
README and a symbols package. A maintainer publishes it with the
[Publish the verifiers](../../.github/workflows/verifiers-publish.yml) workflow from `master`:
`verify` restores locked, format-checks, runs the vectors and packs, and `publish` also pushes the
package. A version already on NuGet is never pushed again, so a release raises the version first.
