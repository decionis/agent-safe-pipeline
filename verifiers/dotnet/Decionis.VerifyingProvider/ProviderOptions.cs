using System;
using System.Collections.Generic;

namespace Decionis.VerifyingProvider;

/// <summary>How this provider is configured.</summary>
/// <param name="Effects">Whether this endpoint effects anything; an effecting provider requires all eight components covered.</param>
/// <param name="ExecutorKeys">The keys the provider issued to the executor, unique by keyid.</param>
/// <param name="AuthorityJwks">The authority's execution-grant JWKS, as its well-known path serves it.</param>
/// <param name="AuthorityIssuer">The iss the provider trusts: https://decionis.com for Decionis.</param>
/// <param name="ClockWindow">How far created may lie from now, each way.</param>
/// <param name="Replay">The replay store.</param>
/// <param name="Now">The provider's clock.</param>
public sealed record ProviderOptions(
    bool Effects,
    IReadOnlyList<ExecutorKey> ExecutorKeys,
    Jwks AuthorityJwks,
    string AuthorityIssuer,
    TimeSpan ClockWindow,
    IReplayStore Replay,
    Func<DateTimeOffset> Now);

/// <summary>
/// What the provider received. Header names are lower case; a covered header
/// received more than once is a refusal and must not be collapsed into this
/// map. <see cref="Body"/> is null when the request carried none.
/// </summary>
public sealed record ProviderRequest(string Method, string Path, byte[]? Body, IReadOnlyDictionary<string, string> Headers);
