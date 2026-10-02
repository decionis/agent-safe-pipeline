import { describe, expect, it } from "vitest";
import { usagePeriod } from "../../src/edge/UsagePeriod.js";
import { emptyUsage, UsageTally, type UsageLine } from "../../src/edge/UsageTally.js";

const hash = (n: number): string => `sha256:${n.toString(16).padStart(64, "0")}`;

function line(seq: number, overrides: Partial<UsageLine> = {}): UsageLine {
  return {
    at: "2026-09-10T10:00:00.000Z",
    mode: "ENFORCEMENT",
    verdict: "ALLOW",
    delegated: false,
    jti: "jti-1",
    seq,
    hash: hash(seq),
    ...overrides,
  };
}

describe("UsageTally", () => {
  it("counts each decision by mode and verdict, delegated ones separately, with the range", () => {
    const tally = new UsageTally();
    expect(tally.add(line(3))).toBe("2026-09");
    expect(tally.add(line(5, { verdict: "ESCALATE", delegated: true, jti: "jti-2" }))).toBe(
      "2026-09",
    );
    expect(tally.add(line(9, { mode: "SHADOW", verdict: "BLOCK", jti: "jti-0" }))).toBe("2026-09");
    expect(tally.usage("2026-09")).toEqual({
      counts: {
        by_mode: { ENFORCEMENT: 2, SHADOW: 1 },
        by_verdict: { ALLOW: 1, ESCALATE: 1, BLOCK: 1 },
        total: 3,
      },
      delegated: 1,
      first_seq: 3,
      first_hash: hash(3),
      last_seq: 9,
      last_hash: hash(9),
      bundles: ["jti-0", "jti-1", "jti-2"],
    });
  });

  it("counts a bundle once however many decisions were made on it", () => {
    const tally = new UsageTally();
    tally.add(line(1));
    tally.add(line(2));
    expect(tally.usage("2026-09").bundles).toEqual(["jti-1"]);
  });

  it("puts each line in the month its time falls in", () => {
    const tally = new UsageTally();
    expect(tally.add(line(1, { at: "2026-09-30T23:59:59.999Z" }))).toBe("2026-09");
    expect(tally.add(line(2, { at: "2026-10-01T00:00:00.000Z" }))).toBe("2026-10");
    expect(tally.counted()).toEqual(["2026-09", "2026-10"]);
    expect(tally.usage("2026-10")).toMatchObject({ first_seq: 2, last_seq: 2 });
    expect(tally.usage("2026-09").counts.total).toBe(1);
  });

  it("counts only inside the period it is asked for", () => {
    const tally = new UsageTally();
    const september = usagePeriod("2026-09") ?? undefined;
    expect(tally.add(line(1, { at: "2026-10-01T00:00:00.000Z" }), september)).toBeNull();
    expect(tally.add(line(2, { at: "2026-08-31T23:59:59.999Z" }), september)).toBeNull();
    expect(tally.add(line(3, { at: "2026-09-01T00:00:00.000Z" }), september)).toBe("2026-09");
    expect(tally.counted()).toEqual(["2026-09"]);
  });

  it("refuses a line that is not a countable decision", () => {
    const tally = new UsageTally();
    for (const overrides of [
      { at: "not a time" },
      { mode: "ADVISORY" },
      { mode: undefined },
      { verdict: "MAYBE" },
      { verdict: null },
      { delegated: "false" },
      { jti: 7 },
    ] as Partial<UsageLine>[]) {
      expect(tally.add(line(1, overrides)), JSON.stringify(overrides)).toBeNull();
    }
    expect(tally.counted()).toEqual([]);
  });

  it("answers the empty usage for a period it never counted, and forgets one", () => {
    const tally = new UsageTally();
    expect(tally.usage("2026-09")).toEqual(emptyUsage());
    tally.add(line(1));
    tally.forget("2026-09");
    expect(tally.usage("2026-09")).toEqual(emptyUsage());
  });

  it("round-trips through its snapshot, oldest period first", () => {
    const tally = new UsageTally();
    tally.add(line(2, { at: "2026-10-02T00:00:00.000Z" }));
    tally.add(line(1));
    const restored = new UsageTally(JSON.parse(JSON.stringify(tally.snapshot())));
    expect(restored.counted()).toEqual(["2026-09", "2026-10"]);
    expect(restored.usage("2026-10")).toEqual(tally.usage("2026-10"));
    restored.add(line(3, { at: "2026-10-03T00:00:00.000Z" }));
    expect(restored.usage("2026-10")).toMatchObject({ first_seq: 2, last_seq: 3 });
  });

  it("has an empty usage of zeros and no range", () => {
    expect(emptyUsage()).toEqual({
      counts: {
        by_mode: { ENFORCEMENT: 0, SHADOW: 0 },
        by_verdict: { ALLOW: 0, ESCALATE: 0, BLOCK: 0 },
        total: 0,
      },
      delegated: 0,
      first_seq: null,
      first_hash: null,
      last_seq: null,
      last_hash: null,
      bundles: [],
    });
  });
});
