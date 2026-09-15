import { describe, expect, it } from "vitest";
import { dispatchBudgetMs, MonotonicDeadline } from "../../src/time/MonotonicClock.js";

describe("MonotonicDeadline", () => {
  it("counts down on a clock nothing can move, and aborts when the budget runs out", async () => {
    let nanos = 1_000_000_000n;
    const deadline = MonotonicDeadline.after(2_000, () => nanos);
    expect(deadline.budgetMs).toBe(2_000);
    expect(deadline.elapsedMs).toBe(0);
    expect(deadline.remainingMs).toBe(2_000);
    expect(deadline.expired).toBe(false);
    nanos += 500_000_000n;
    expect(deadline.elapsedMs).toBe(500);
    expect(deadline.remainingMs).toBe(1_500);
    nanos += 2_000_000_000n;
    expect(deadline.remainingMs).toBe(0);
    expect(deadline.expired).toBe(true);
    expect(MonotonicDeadline.after(-5, () => nanos).budgetMs).toBe(0);
    expect(MonotonicDeadline.after(1.9, () => nanos).budgetMs).toBe(1);
    const real = MonotonicDeadline.after(20);
    const signal = real.signal();
    expect(signal.aborted).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 40));
    expect(signal.aborted).toBe(true);
    expect(real.expired).toBe(true);
  });
});

describe("dispatchBudgetMs", () => {
  it("is the smaller of the configured timeout and what is left of the grant", () => {
    const now = (): number => Date.parse("2026-09-15T10:00:00.000Z");
    expect(dispatchBudgetMs(5_000, "2026-09-15T10:00:10.000Z", now)).toBe(5_000);
    expect(dispatchBudgetMs(5_000, "2026-09-15T10:00:02.000Z", now)).toBe(2_000);
    expect(dispatchBudgetMs(5_000, "2026-09-15T10:00:00.000Z", now)).toBe(0);
    expect(dispatchBudgetMs(5_000, "2026-09-15T09:59:59.000Z", now)).toBe(0);
    // An expiry that is not a time leaves the configured timeout alone rather
    // than silently becoming zero.
    expect(dispatchBudgetMs(5_000, "whenever", now)).toBe(5_000);
  });
});
