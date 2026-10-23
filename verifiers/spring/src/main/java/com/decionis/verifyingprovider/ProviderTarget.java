package com.decionis.verifyingprovider;

import java.util.Optional;

/**
 * The target a request would change, as the provider reads it under the lock its effect takes:
 * its version now, or none when it no longer exists. A provider that cannot read it before
 * effecting passes none to {@link VerifyingProvider#verify(ProviderRequest)}, and applies the
 * attestation's {@code expectedStateVersion} as its write's own precondition.
 */
public record ProviderTarget(Optional<String> version) {

  /** The target at this version: an ETag with its quotes, a resource version. */
  public static ProviderTarget at(String version) {
    return new ProviderTarget(Optional.of(version));
  }

  /** The target no longer exists, so it is at no version. */
  public static ProviderTarget gone() {
    return new ProviderTarget(Optional.empty());
  }
}
