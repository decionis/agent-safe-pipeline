import { describe, expect, it } from "vitest";
import { RateLimiter } from "../../src/identity/RateLimiter.js";

function limiter(): { readonly limits: RateLimiter; tick(ms: number): void } {
  let now = 1_000_000;
  const limits = new RateLimiter(() => now);
  return {
    limits,
    tick: (ms) => {
      now += ms;
    },
  };
}

describe("RateLimiter", () => {
  it("parses rules and lockouts, and refuses what is not one by the variable's name", () => {
    expect(RateLimiter.parseRule("20/60", "X")).toEqual({ count: 20, windowSeconds: 60 });
    expect(RateLimiter.parseRule(" 1/1 ", "X")).toEqual({ count: 1, windowSeconds: 1 });
    for (const bad of ["0/60", "20", "20/0", "a/b", "20/60/1", ""]) {
      expect(() => RateLimiter.parseRule(bad, "EXECUTOR_RATE_LIMIT_UNAUTHENTICATED")).toThrow(
        "CONFIG_INVALID: EXECUTOR_RATE_LIMIT_UNAUTHENTICATED (expected <count>/<seconds>)",
      );
    }
    expect(RateLimiter.parseLockout("10/60/300", "Y")).toEqual({
      failures: 10,
      windowSeconds: 60,
      lockSeconds: 300,
    });
    expect(RateLimiter.parseLockout("0/60/300", "Y")).toBeNull();
    for (const bad of ["10/60", "10/0/300", "10/60/0", "x/60/300"]) {
      expect(() => RateLimiter.parseLockout(bad, "EXECUTOR_AUTH_LOCKOUT")).toThrow(
        "CONFIG_INVALID: EXECUTOR_AUTH_LOCKOUT (expected <failures>/<seconds>/<lock seconds>)",
      );
    }
  });

  it("allows a key its count per sliding window and no more, key by key", () => {
    const { limits, tick } = limiter();
    const rule = { count: 2, windowSeconds: 10 };
    expect(limits.exhausted("a", rule)).toBe(false);
    expect(limits.allow("a", rule)).toBe(true);
    expect(limits.allow("a", rule)).toBe(true);
    expect(limits.exhausted("a", rule)).toBe(true);
    expect(limits.allow("a", rule)).toBe(false);
    expect(limits.allow("b", rule)).toBe(true);
    tick(9_999);
    expect(limits.allow("a", rule)).toBe(false);
    tick(2);
    expect(limits.exhausted("a", rule)).toBe(false);
    expect(limits.allow("a", rule)).toBe(true);
    expect(limits.allow("a", rule)).toBe(true);
    expect(limits.allow("a", rule)).toBe(false);
  });

  it("locks a key when its failures reach the rule inside the window, once, until the lock expires", () => {
    const { limits, tick } = limiter();
    const rule = { failures: 3, windowSeconds: 60, lockSeconds: 120 };
    expect(limits.recordFailure("p", null)).toBe(false);
    expect(limits.recordFailure("p", rule)).toBe(false);
    expect(limits.recordFailure("p", rule)).toBe(false);
    expect(limits.locked("p")).toBe(false);
    expect(limits.recordFailure("p", rule)).toBe(true);
    expect(limits.locked("p")).toBe(true);
    expect(limits.recordFailure("p", rule)).toBe(false);
    expect(limits.locked("q")).toBe(false);
    tick(119_999);
    expect(limits.locked("p")).toBe(true);
    tick(2);
    expect(limits.locked("p")).toBe(false);
    expect(limits.locked("p")).toBe(false);
    tick(61_000);
    expect(limits.recordFailure("p", rule)).toBe(false);
    expect(limits.recordFailure("p", rule)).toBe(false);
    tick(61_000);
    expect(limits.recordFailure("p", rule)).toBe(false);
    expect(limits.locked("p")).toBe(false);
  });
});
