import { describe, expect, it } from "vitest";
import {
  inPeriod,
  periodOf,
  previousPeriod,
  reportDueAt,
  usagePeriod,
} from "../../src/edge/UsagePeriod.js";

const at = (iso: string): number => Date.parse(iso);

describe("usage periods", () => {
  it("names a UTC calendar month by its first instant and the next month's", () => {
    expect(usagePeriod("2026-09")).toEqual({
      period: "2026-09",
      start: at("2026-09-01T00:00:00.000Z"),
      end: at("2026-10-01T00:00:00.000Z"),
    });
    expect(usagePeriod("2026-12")).toEqual({
      period: "2026-12",
      start: at("2026-12-01T00:00:00.000Z"),
      end: at("2027-01-01T00:00:00.000Z"),
    });
    expect(usagePeriod("2028-02")?.end).toBe(at("2028-03-01T00:00:00.000Z"));
    expect(usagePeriod("2000-01")?.start).toBe(at("2000-01-01T00:00:00.000Z"));
    expect(usagePeriod("2999-12")?.start).toBe(at("2999-12-01T00:00:00.000Z"));
  });

  it("refuses anything that is not YYYY-MM in years 2000 to 2999", () => {
    for (const text of [
      "",
      "2026-9",
      "2026-00",
      "2026-13",
      "1999-12",
      "3000-01",
      "0099-01",
      "2026-09-01",
      " 2026-09",
      "2026-09 ",
      "x2026-09",
    ]) {
      expect(usagePeriod(text), text).toBeNull();
    }
  });

  it("places an instant in its month, at both edges", () => {
    expect(periodOf(at("2026-09-01T00:00:00.000Z")).period).toBe("2026-09");
    expect(periodOf(at("2026-09-30T23:59:59.999Z")).period).toBe("2026-09");
    expect(periodOf(at("2026-10-01T00:00:00.000Z")).period).toBe("2026-10");
    expect(periodOf(at("2026-01-15T12:00:00.000Z")).period).toBe("2026-01");
  });

  it("steps back one month, across a year", () => {
    expect(previousPeriod(usagePeriod("2026-01") ?? periodOf(0)).period).toBe("2025-12");
    expect(previousPeriod(usagePeriod("2026-10") ?? periodOf(0)).period).toBe("2026-09");
  });

  it("holds an instant from the start, inclusive, to the end, exclusive", () => {
    const period = usagePeriod("2026-09") ?? periodOf(0);
    expect(inPeriod(period, period.start)).toBe(true);
    expect(inPeriod(period, period.start - 1)).toBe(false);
    expect(inPeriod(period, period.end - 1)).toBe(true);
    expect(inPeriod(period, period.end)).toBe(false);
  });

  it("makes a report due a number of days after the period ends", () => {
    const period = usagePeriod("2026-09") ?? periodOf(0);
    expect(reportDueAt(period, 35)).toBe(at("2026-11-05T00:00:00.000Z"));
    expect(reportDueAt(period, 0)).toBe(period.end);
  });
});
