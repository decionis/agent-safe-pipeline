/** A sustained rate and the burst above it one gateway admits, per process. */
export interface RateLimit {
  readonly requestsPerSecond: number;
  readonly burst: number;
}

/** What a hosted gateway admits when its operator named no limit. */
export const HOSTED_DEFAULT_RATE_LIMIT: RateLimit = { requestsPerSecond: 50, burst: 100 };

/** The result of one take: admitted, or refused with how long until a request would be. */
export type RateDecision =
  { readonly admitted: true } | { readonly admitted: false; readonly retryAfterSeconds: number };

/**
 * A token bucket: `burst` tokens to start, refilled at `requestsPerSecond`,
 * one taken per request. Time comes from the clock it is given. A clock
 * that steps backwards refills nothing and moves the baseline with it, so a
 * change of system time neither grants a burst nor stalls the bucket.
 */
export class TokenBucket {
  private tokens: number;
  private last: number;

  public constructor(
    private readonly limit: RateLimit,
    private readonly clock: () => number,
  ) {
    this.tokens = limit.burst;
    this.last = clock();
  }

  public take(): RateDecision {
    const now = this.clock();
    const elapsedMs = Math.max(now - this.last, 0);
    this.last = now;
    this.tokens = Math.min(
      this.limit.burst,
      this.tokens + (elapsedMs * this.limit.requestsPerSecond) / 1_000,
    );
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return { admitted: true };
    }
    const waitMs = ((1 - this.tokens) * 1_000) / this.limit.requestsPerSecond;
    return { admitted: false, retryAfterSeconds: Math.max(Math.ceil(waitMs / 1_000), 1) };
  }
}
