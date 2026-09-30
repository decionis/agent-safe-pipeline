import { describe, expect, it } from "vitest";
import { HOSTED_DEFAULT_RATE_LIMIT, TokenBucket } from "../../src/gateway/RateLimit.js";

describe("the token bucket", () => {
  it("admits the burst at once, then the sustained rate, and says when to try again", () => {
    let now = 1_000_000;
    const bucket = new TokenBucket({ requestsPerSecond: 2, burst: 3 }, () => now);
    expect([bucket.take(), bucket.take(), bucket.take()]).toEqual(
      Array(3).fill({ admitted: true }),
    );
    expect(bucket.take()).toEqual({ admitted: false, retryAfterSeconds: 1 });
    now += 499;
    expect(bucket.take().admitted).toBe(false);
    now += 1;
    expect(bucket.take()).toEqual({ admitted: true });
    expect(bucket.take().admitted).toBe(false);
    // A long pause refills to the burst and no further.
    now += 60_000;
    for (let index = 0; index < 3; index += 1) expect(bucket.take()).toEqual({ admitted: true });
    expect(bucket.take().admitted).toBe(false);
  });

  it("names the wait in whole seconds, at least one", () => {
    let now = 0;
    const slow = new TokenBucket({ requestsPerSecond: 0.25, burst: 1 }, () => now);
    expect(slow.take()).toEqual({ admitted: true });
    expect(slow.take()).toEqual({ admitted: false, retryAfterSeconds: 4 });
    now += 1_500;
    expect(slow.take()).toEqual({ admitted: false, retryAfterSeconds: 3 });
    const fast = new TokenBucket({ requestsPerSecond: 1_000, burst: 1 }, () => now);
    expect(fast.take()).toEqual({ admitted: true });
    expect(fast.take()).toEqual({ admitted: false, retryAfterSeconds: 1 });
  });

  it("neither grants a burst nor stalls when the clock steps backwards", () => {
    let now = 10_000;
    const bucket = new TokenBucket({ requestsPerSecond: 1, burst: 1 }, () => now);
    expect(bucket.take()).toEqual({ admitted: true });
    now -= 5_000;
    expect(bucket.take().admitted).toBe(false);
    // One second after the step is one token, not a wait for the old time to return.
    now += 1_000;
    expect(bucket.take()).toEqual({ admitted: true });
  });

  it("gives a hosted gateway a default it can live with", () => {
    expect(HOSTED_DEFAULT_RATE_LIMIT).toEqual({ requestsPerSecond: 50, burst: 100 });
  });
});
