import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  REFUSAL_LINES_PER_WINDOW,
  REFUSAL_WINDOW_MS,
  RefusalSampler,
} from "../../src/gateway/RefusalSampler.js";

describe("the refusal sampler", () => {
  let lines: string[];
  let sampler: RefusalSampler<"MISSING" | "INVALID">;

  beforeEach(() => {
    vi.useFakeTimers();
    lines = [];
    sampler = new RefusalSampler(
      (code) => lines.push(code),
      (code, count) => lines.push(`${code}x${count}`),
      3,
      1_000,
    );
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("writes the first refusals of a window one each, then one count per code when it closes", () => {
    for (const code of [
      "MISSING",
      "MISSING",
      "INVALID",
      "MISSING",
      "INVALID",
      "MISSING",
    ] as const) {
      sampler.refuse(code);
    }
    expect(lines).toEqual(["MISSING", "MISSING", "INVALID"]);
    vi.advanceTimersByTime(999);
    expect(lines).toHaveLength(3);
    vi.advanceTimersByTime(1);
    expect(lines.slice(3)).toEqual(["MISSINGx2", "INVALIDx1"]);
    // The next refusal opens a new window with the whole allowance.
    sampler.refuse("INVALID");
    expect(lines.slice(5)).toEqual(["INVALID"]);
  });

  it("writes nothing more for a window with nothing over its bound, and holds no timer once flushed", () => {
    sampler.refuse("MISSING");
    vi.advanceTimersByTime(1_000);
    expect(lines).toEqual(["MISSING"]);
    for (let index = 0; index < 5; index += 1) sampler.refuse("INVALID");
    sampler.flush();
    expect(lines.slice(1)).toEqual(["INVALID", "INVALID", "INVALID", "INVALIDx2"]);
    expect(vi.getTimerCount()).toBe(0);
    sampler.flush();
    expect(lines).toHaveLength(5);
  });

  it("bounds a flood to the allowance and a count, however large it is", () => {
    const flood = new RefusalSampler<"MISSING">(
      (code) => lines.push(code),
      (code, count) => lines.push(`${code}x${count}`),
    );
    for (let index = 0; index < 100_000; index += 1) flood.refuse("MISSING");
    vi.advanceTimersByTime(REFUSAL_WINDOW_MS);
    expect(lines).toHaveLength(REFUSAL_LINES_PER_WINDOW + 1);
    expect(lines.at(-1)).toBe(`MISSINGx${100_000 - REFUSAL_LINES_PER_WINDOW}`);
  });
});
