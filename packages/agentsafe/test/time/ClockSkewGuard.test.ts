import { describe, expect, it, vi } from "vitest";
import { clockSkewGuard } from "../../src/time/ClockSkewGuard.js";
import { collectedEvents } from "../support/Environment.js";

interface Guarded {
  readonly fetch: typeof fetch;
  readonly lines: string[];
  readonly exceeded: number[];
  readonly observed: number[];
}

function guard(
  options: { readonly maxSkewMs?: number; readonly date?: string | null } = {},
): Guarded {
  const lines: string[] = [];
  const exceeded: number[] = [];
  const observed: number[] = [];
  const inner = (async () =>
    new Response("{}", {
      status: 200,
      headers:
        options.date === null ? {} : { date: options.date ?? "Tue, 15 Sep 2026 10:00:00 GMT" },
    })) as unknown as typeof fetch;
  return {
    fetch: clockSkewGuard(inner, {
      maxSkewMs: options.maxSkewMs ?? 2_000,
      events: collectedEvents(lines),
      onExceeded: (skew) => exceeded.push(skew),
      observe: (skew) => observed.push(skew),
      now: () => Date.parse("2026-09-15T10:00:00.000Z"),
    }),
    lines,
    exceeded,
    observed,
  };
}

describe("clockSkewGuard", () => {
  it("measures the authority's clock against this host's and says nothing while they agree", async () => {
    const agreed = guard();
    expect((await agreed.fetch("https://authority.decionis.example/v1")).status).toBe(200);
    expect(agreed.observed).toEqual([0]);
    expect(agreed.exceeded).toEqual([]);
    expect(agreed.lines).toEqual([]);
    // An HTTP date has one-second resolution, so a sub-second difference is
    // the format and not the clock.
    const rounded = guard({ maxSkewMs: 100, date: "Tue, 15 Sep 2026 10:00:01 GMT" });
    await rounded.fetch("https://authority.decionis.example/v1");
    expect(rounded.observed).toEqual([1_000]);
    expect(rounded.exceeded).toEqual([]);
  });

  it("halts past the bound, ahead or behind, and reports the skew and nothing else", async () => {
    const ahead = guard({ maxSkewMs: 2_000, date: "Tue, 15 Sep 2026 10:00:10 GMT" });
    await ahead.fetch("https://authority.decionis.example/v1");
    expect(ahead.exceeded).toEqual([10_000]);
    expect(ahead.observed).toEqual([10_000]);
    expect(ahead.lines.map((line) => JSON.parse(line) as Record<string, unknown>)).toEqual([
      expect.objectContaining({ event: "CLOCK_SKEW_EXCEEDED", skew_ms: 10_000 }),
    ]);
    const behind = guard({ maxSkewMs: 2_000, date: "Tue, 15 Sep 2026 09:59:50 GMT" });
    await behind.fetch("https://authority.decionis.example/v1");
    expect(behind.exceeded).toEqual([-10_000]);
  });

  it("leaves a response with no usable date alone, and never changes the answer", async () => {
    const none = guard({ date: null });
    const response = await none.fetch("https://authority.decionis.example/v1");
    expect(await response.text()).toBe("{}");
    expect(none.observed).toEqual([]);
    expect(none.exceeded).toEqual([]);
    const nonsense = guard({ date: "whenever" });
    expect((await nonsense.fetch("https://authority.decionis.example/v1")).status).toBe(200);
    expect(nonsense.observed).toEqual([]);
    const failing = clockSkewGuard(
      (async () => {
        throw new Error("ECONNREFUSED");
      }) as unknown as typeof fetch,
      {
        maxSkewMs: 2_000,
        events: collectedEvents(),
        onExceeded: () => undefined,
      },
    );
    await expect(failing("https://authority.decionis.example/v1")).rejects.toThrow("ECONNREFUSED");
    expect(vi.isMockFunction(failing)).toBe(false);
  });
});
