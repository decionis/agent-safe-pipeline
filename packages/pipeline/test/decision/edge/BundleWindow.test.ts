import { describe, expect, it } from "vitest";
import {
  BundleWindow,
  REFRESH_REMAINING_FRACTION,
  type RefreshPolicy,
} from "../../../src/decision/edge/BundleWindow.js";

const policy: RefreshPolicy = {
  refreshMs: 3_600_000,
  retryBaseMs: 1_000,
  retryMaxMs: 300_000,
  minimumMs: 30_000,
};
const validity = { notBeforeMs: 1_000_000, expiresAtMs: 1_000_000 + 8 * 3_600_000 };

describe("BundleWindow.usable", () => {
  it("is false without a bundle", () => {
    expect(BundleWindow.usable(null, 1_500_000)).toBe(false);
  });

  it("is the half-open window [notBefore, expiresAt)", () => {
    expect(BundleWindow.usable(validity, validity.notBeforeMs - 1)).toBe(false);
    expect(BundleWindow.usable(validity, validity.notBeforeMs)).toBe(true);
    expect(BundleWindow.usable(validity, validity.expiresAtMs - 1)).toBe(true);
    expect(BundleWindow.usable(validity, validity.expiresAtMs)).toBe(false);
  });
});

describe("BundleWindow.lowWater", () => {
  it("is the instant a quarter of the window remains", () => {
    expect(REFRESH_REMAINING_FRACTION).toBe(0.25);
    expect(BundleWindow.lowWater(validity)).toBe(1_000_000 + 6 * 3_600_000);
    expect(BundleWindow.lowWater({ notBeforeMs: 0, expiresAtMs: 400 })).toBe(300);
  });
});

describe("BundleWindow.nextDelay", () => {
  it("fetches at once when nothing is loaded and nothing has failed", () => {
    expect(BundleWindow.nextDelay(policy, null, 0, 5)).toBe(0);
  });

  it("backs off exponentially after failures, from the base", () => {
    expect(BundleWindow.nextDelay(policy, null, 1, 0)).toBe(1_000);
    expect(BundleWindow.nextDelay(policy, null, 2, 0)).toBe(2_000);
    expect(BundleWindow.nextDelay(policy, validity, 3, 0)).toBe(4_000);
  });

  it("caps the backoff at the maximum retry and at the routine interval", () => {
    expect(BundleWindow.nextDelay(policy, null, 9, 0)).toBe(256_000);
    expect(BundleWindow.nextDelay(policy, null, 10, 0)).toBe(300_000);
    expect(BundleWindow.nextDelay(policy, null, 1e9, 0)).toBe(300_000);
    expect(BundleWindow.nextDelay({ ...policy, refreshMs: 3_000 }, null, 5, 0)).toBe(3_000);
  });

  it("waits the routine interval while the low-water mark is further away", () => {
    expect(BundleWindow.nextDelay(policy, validity, 0, validity.notBeforeMs)).toBe(3_600_000);
  });

  it("brings the refresh forward to the low-water mark when it comes first", () => {
    const now = BundleWindow.lowWater(validity) - 600_000;
    expect(BundleWindow.nextDelay(policy, validity, 0, now)).toBe(600_000);
  });

  it("never waits less than the minimum, even past the low-water mark", () => {
    const low = BundleWindow.lowWater(validity);
    expect(BundleWindow.nextDelay(policy, validity, 0, low + 10)).toBe(30_000);
    expect(BundleWindow.nextDelay(policy, validity, 0, low - 30_001)).toBe(30_001);
  });
});
