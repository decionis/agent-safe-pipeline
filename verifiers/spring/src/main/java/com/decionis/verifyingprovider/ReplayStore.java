package com.decionis.verifyingprovider;

import java.time.Instant;

/**
 * Where a provider keeps the grants it accepted, until their attestation
 * expires. {@link #record} answers true when the grant was not there and is
 * now, and false when it was: the second presentation. Shared by every
 * instance that can effect; the profile's step 8.
 */
public interface ReplayStore {
  boolean record(String grantId, Instant expiresAt);
}
