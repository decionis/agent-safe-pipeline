package com.decionis.verifyingprovider;

import java.time.Clock;
import java.time.Duration;
import java.util.List;

/**
 * How this provider is configured.
 *
 * @param effects whether this endpoint effects anything; an effecting provider requires all eight components covered
 * @param executorKeys the keys the provider issued to the executor, unique by keyid
 * @param authorityJwks the authority's execution-grant JWKS, as its well-known path serves it
 * @param authorityIssuer the iss the provider trusts: https://decionis.com for Decionis
 * @param clockWindow how far created may lie from now, each way
 * @param replay the replay store
 * @param clock the provider's clock
 */
public record ProviderOptions(
    boolean effects,
    List<ExecutorKey> executorKeys,
    Jwks authorityJwks,
    String authorityIssuer,
    Duration clockWindow,
    ReplayStore replay,
    Clock clock) {}
