package com.decionis.verifyingprovider;

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * A replay store for one process: enough for a single instance, and for the
 * vectors. A provider with more than one instance that can effect shares one
 * instead, keyed the same way. Expired grants are forgotten on the next
 * record, which is why the store needs no life beyond the lease.
 */
public final class MemoryReplayStore implements ReplayStore {
  private final Map<String, Instant> seen = new HashMap<>();
  private final Clock clock;

  public MemoryReplayStore(Clock clock) {
    this.clock = clock;
  }

  public MemoryReplayStore() {
    this(Clock.systemUTC());
  }

  @Override
  public synchronized boolean record(String grantId, Instant expiresAt) {
    Instant now = clock.instant();
    seen.entrySet().removeIf(entry -> !entry.getValue().isAfter(now));
    if (seen.containsKey(grantId)) {
      return false;
    }
    seen.put(grantId, expiresAt);
    return true;
  }
}
