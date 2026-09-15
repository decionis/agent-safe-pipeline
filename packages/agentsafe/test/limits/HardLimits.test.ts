import { describe, expect, it } from "vitest";
import type { JsonObject } from "@decionis/agent-safe-pipeline";
import { HardLimits, type HardLimitSettings } from "../../src/limits/HardLimits.js";

const ceilings = (text: string): ReadonlyMap<string, bigint> =>
  HardLimits.parseCeilings(text, "EXECUTOR_HARD_LIMIT_SINGLE_MINOR");

function limits(overrides: Partial<HardLimitSettings> = {}): {
  readonly limits: HardLimits;
  tick(ms: number): void;
} {
  let now = 1_000_000;
  const settings: HardLimitSettings = {
    singleMinor: ceilings("CHF:2500000000,EUR:1000000"),
    windowSeconds: 60,
    windowCount: null,
    windowSumMinor: null,
    ...overrides,
  };
  return {
    limits: new HardLimits(settings, () => now),
    tick: (ms) => {
      now += ms;
    },
  };
}

const payment = (amountMinor: number, currency = "CHF"): JsonObject => ({
  amountMinor,
  currency,
  reference: "synthetic-payout-1",
});

describe("HardLimits.parseCeilings", () => {
  it("reads a ceiling per currency in minor units and refuses anything else", () => {
    expect([...ceilings("CHF:2500000000,EUR:1000000")]).toEqual([
      ["CHF", 2_500_000_000n],
      ["EUR", 1_000_000n],
    ]);
    expect([...ceilings(" USD:1 ")]).toEqual([["USD", 1n]]);
    expect(ceilings("CHF:99999999999999999999999999").get("CHF")).toBe(99999999999999999999999999n);
    for (const bad of [
      "CHF",
      "chf:100",
      "CHF:0",
      "CHF:-1",
      "CHF:1.5",
      "CHF:100,",
      "",
      "CHFX:100",
    ]) {
      expect(() => ceilings(bad)).toThrow("CONFIG_INVALID: EXECUTOR_HARD_LIMIT_SINGLE_MINOR");
    }
    expect(() => ceilings("CHF:100,CHF:200")).toThrow(
      "CONFIG_INVALID: EXECUTOR_HARD_LIMIT_SINGLE_MINOR (CHF twice)",
    );
  });
});

describe("HardLimits.monetaryValue", () => {
  it("reads the amount and currency an action carries, and refuses half of one", () => {
    expect(HardLimits.monetaryValue(payment(2_500))).toEqual({
      currency: "CHF",
      amountMinor: 2_500n,
    });
    expect(HardLimits.monetaryValue({ reference: "x" })).toBeNull();
    expect(HardLimits.monetaryValue({})).toBeNull();
    const malformed: JsonObject[] = [
      { amountMinor: 100 },
      { currency: "CHF" },
      { amountMinor: 100, currency: "chf" },
      { amountMinor: 100, currency: "CHFX" },
      { amountMinor: -1, currency: "CHF" },
      { amountMinor: 1.5, currency: "CHF" },
      { amountMinor: "100", currency: "CHF" },
      { amountMinor: Number.MAX_VALUE, currency: "CHF" },
    ];
    for (const bad of malformed) {
      expect([bad, HardLimits.monetaryValue(bad)]).toEqual([bad, "INVALID"]);
    }
    expect(HardLimits.monetaryValue({ amountMinor: 0, currency: "CHF" })).toEqual({
      currency: "CHF",
      amountMinor: 0n,
    });
  });
});

describe("HardLimits", () => {
  it("refuses an amount above its currency's ceiling, and a currency it was never given", () => {
    const { limits: hard } = limits();
    expect(hard.check(payment(2_500_000_000))).toEqual({ allowed: true });
    expect(hard.check(payment(2_500_000_001))).toEqual({
      allowed: false,
      code: "HARD_LIMIT_EXCEEDED",
    });
    expect(hard.check(payment(1_000_001, "EUR"))).toEqual({
      allowed: false,
      code: "HARD_LIMIT_EXCEEDED",
    });
    expect(hard.check(payment(100, "USD"))).toEqual({
      allowed: false,
      code: "HARD_LIMIT_CURRENCY_UNKNOWN",
    });
    expect(hard.check({ amountMinor: "100", currency: "CHF" })).toEqual({
      allowed: false,
      code: "HARD_LIMIT_AMOUNT_INVALID",
    });
    // An action that is not a payment is not refused for lacking an amount.
    expect(hard.check({ reference: "synthetic-change-1" })).toEqual({ allowed: true });
  });

  it("counts what it lets through, and only what it lets through", () => {
    const { limits: hard, tick } = limits({ windowCount: 2, windowSeconds: 60 });
    expect(hard.commit(payment(100))).toEqual({ allowed: true });
    expect(hard.commit(payment(100))).toEqual({ allowed: true });
    expect(hard.check(payment(100))).toEqual({
      allowed: false,
      code: "HARD_LIMIT_WINDOW_COUNT_EXCEEDED",
    });
    expect(hard.commit(payment(100))).toEqual({
      allowed: false,
      code: "HARD_LIMIT_WINDOW_COUNT_EXCEEDED",
    });
    // The refusal above took no place in the window, so time alone reopens it.
    tick(60_001);
    expect(hard.commit(payment(100))).toEqual({ allowed: true });
    expect(hard.commit(payment(100))).toEqual({ allowed: true });
    expect(hard.check(payment(100))).toMatchObject({ allowed: false });
  });

  it("bounds the sum inside the window, refusing the request that would cross it", () => {
    const { limits: hard, tick } = limits({ windowSumMinor: 1_000n, windowSeconds: 30 });
    expect(hard.commit(payment(600))).toEqual({ allowed: true });
    expect(hard.check(payment(401))).toEqual({
      allowed: false,
      code: "HARD_LIMIT_WINDOW_SUM_EXCEEDED",
    });
    expect(hard.commit(payment(400))).toEqual({ allowed: true });
    expect(hard.check(payment(1))).toMatchObject({ allowed: false });
    // An action with no amount does not add to the sum.
    expect(hard.commit({ reference: "synthetic-change-2" })).toEqual({ allowed: true });
    tick(30_001);
    expect(hard.commit(payment(1_000))).toEqual({ allowed: true });
    expect(hard.check(payment(1))).toMatchObject({ allowed: false });
  });

  it("refuses a value whose shape only resembles an amount", () => {
    // A regular expression coerces what it tests, so an array of one string
    // would match a pattern the string never saw. A caller sends JSON.
    for (const parameters of [
      { amountMinor: 5, currency: ["CHF"] },
      { amountMinor: 5, currency: { toString: "CHF" } },
      { amountMinor: 5, currency: true },
      { amountMinor: 5, currency: null },
      { amountMinor: "5", currency: "CHF" },
      { amountMinor: true, currency: "CHF" },
      { amountMinor: [5], currency: "CHF" },
      { amountMinor: 5.5, currency: "CHF" },
      { amountMinor: -1, currency: "CHF" },
      { amountMinor: Number.MAX_SAFE_INTEGER + 2, currency: "CHF" },
    ] as unknown as JsonObject[]) {
      expect(HardLimits.monetaryValue(parameters), JSON.stringify(parameters)).toBe("INVALID");
    }
    // And a zero is an amount, not a missing one.
    expect(HardLimits.monetaryValue({ amountMinor: 0, currency: "CHF" })).toEqual({
      currency: "CHF",
      amountMinor: 0n,
    });
  });

  it("measures its window in seconds, and drops an entry only once it is past", () => {
    const { limits: bounded, tick } = limits({ windowCount: 2, windowSeconds: 60 });
    expect(bounded.commit(payment(1_000)).allowed).toBe(true);
    // Half a minute later the first is still inside a sixty-second window,
    // so the second fills it and the third is refused.
    tick(30_000);
    expect(bounded.commit(payment(1_000)).allowed).toBe(true);
    expect(bounded.check(payment(1_000))).toEqual({
      allowed: false,
      code: "HARD_LIMIT_WINDOW_COUNT_EXCEEDED",
    });
    // Exactly at the boundary the oldest entry leaves, and one slot opens.
    tick(30_000);
    expect(bounded.commit(payment(1_000)).allowed).toBe(true);
    expect(bounded.check(payment(1_000))).toEqual({
      allowed: false,
      code: "HARD_LIMIT_WINDOW_COUNT_EXCEEDED",
    });
  });

  it("counts against the clock it was given, whatever that clock says", () => {
    // The clock is the process's to supply, so there is no default here to
    // be wrong about. A window measured by the real one still works.
    const wall = new HardLimits(
      {
        singleMinor: ceilings("CHF:2500000000"),
        windowSeconds: 60,
        windowCount: 1,
        windowSumMinor: null,
      },
      () => Date.now(),
    );
    expect(wall.commit(payment(1_000))).toEqual({ allowed: true });
    expect(wall.check(payment(1_000))).toEqual({
      allowed: false,
      code: "HARD_LIMIT_WINDOW_COUNT_EXCEEDED",
    });
  });

  it("starts with an empty window, so the first action is never the one that fills it", () => {
    const { limits: single } = limits({ windowCount: 1 });
    expect(single.check(payment(1_000)).allowed).toBe(true);
    expect(single.commit(payment(1_000)).allowed).toBe(true);
    expect(single.check(payment(1_000))).toEqual({
      allowed: false,
      code: "HARD_LIMIT_WINDOW_COUNT_EXCEEDED",
    });
    const { limits: summed } = limits({ windowSumMinor: 1_000n });
    expect(summed.commit(payment(1_000)).allowed).toBe(true);
    expect(summed.check(payment(1))).toEqual({
      allowed: false,
      code: "HARD_LIMIT_WINDOW_SUM_EXCEEDED",
    });
  });

  it("counts an action that moved nothing, and adds nothing to the sum for it", () => {
    const { limits: both } = limits({ windowCount: 2, windowSumMinor: 1_000n });
    // A non-monetary action takes a place in the count window and leaves the
    // sum where it was, so the next payment still has the whole ceiling.
    expect(both.commit({ note: "a reconciliation" }).allowed).toBe(true);
    expect(both.commit(payment(1_000)).allowed).toBe(true);
    expect(both.check({ note: "another" })).toEqual({
      allowed: false,
      code: "HARD_LIMIT_WINDOW_COUNT_EXCEEDED",
    });
  });

  it("only ever refuses: a ceiling is never widened by a window, nor a window by a ceiling", () => {
    const { limits: hard } = limits({
      windowCount: 10,
      windowSumMinor: 10_000_000_000n,
      windowSeconds: 60,
    });
    expect(hard.check(payment(2_500_000_001))).toMatchObject({ code: "HARD_LIMIT_EXCEEDED" });
    const tight = limits({ singleMinor: ceilings("CHF:1000000000"), windowCount: 1 });
    expect(tight.limits.commit(payment(1_000))).toEqual({ allowed: true });
    expect(tight.limits.check(payment(1))).toMatchObject({
      code: "HARD_LIMIT_WINDOW_COUNT_EXCEEDED",
    });
    expect(tight.limits.settings.windowSeconds).toBe(60);
  });
});
