/** The interval a loaded bundle may be evaluated in, in epoch milliseconds: `[notBefore, expiresAt)`. */
export interface BundleValidity {
  readonly notBeforeMs: number;
  readonly expiresAtMs: number;
}

/** The refresh schedule's settings, in milliseconds. */
export interface RefreshPolicy {
  /** The routine interval between two fetches. */
  readonly refreshMs: number;
  /** The first retry after a failed fetch; doubled for each failure after it. */
  readonly retryBaseMs: number;
  /** No retry waits longer than this, nor longer than `refreshMs`. */
  readonly retryMaxMs: number;
  /** The shortest wait between two successful fetches, so a short bundle cannot cause a hot loop. */
  readonly minimumMs: number;
}

/**
 * The share of a bundle's validity that must remain: below it, a fresh
 * bundle is fetched whatever the routine interval says.
 */
export const REFRESH_REMAINING_FRACTION = 0.25;

/**
 * When a bundle can be evaluated, and when the next one should be fetched.
 * Pure arithmetic over instants the caller supplies, so the schedule is
 * decided in one place and nothing in it reads a clock.
 */
export class BundleWindow {
  /** Whether `now` is inside the bundle's window. Never true without a bundle. */
  public static usable(validity: BundleValidity | null, now: number): boolean {
    return validity !== null && now >= validity.notBeforeMs && now < validity.expiresAtMs;
  }

  /**
   * The instant at which a quarter of the window remains: the latest a
   * routine refresh may leave it.
   */
  public static lowWater(validity: BundleValidity): number {
    const span = validity.expiresAtMs - validity.notBeforeMs;
    return validity.expiresAtMs - span * REFRESH_REMAINING_FRACTION;
  }

  /**
   * How long to wait before the next fetch. After a failure, an exponential
   * backoff that never exceeds the routine interval. With no bundle, at once.
   * Otherwise the routine interval, brought forward to the low-water mark
   * when that comes first, but never below the minimum.
   */
  public static nextDelay(
    policy: RefreshPolicy,
    validity: BundleValidity | null,
    failures: number,
    now: number,
  ): number {
    if (failures > 0) {
      const backoff = policy.retryBaseMs * 2 ** (failures - 1);
      return Math.min(backoff, policy.retryMaxMs, policy.refreshMs);
    }
    if (validity === null) return 0;
    const untilLowWater = BundleWindow.lowWater(validity) - now;
    return Math.min(policy.refreshMs, Math.max(untilLowWater, policy.minimumMs));
  }
}
