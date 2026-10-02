/**
 * A usage period: one calendar month in UTC, written `YYYY-MM`. Its start is
 * the first instant of the month and its end the first instant of the next,
 * so a line belongs to exactly one period: `start <= at < end`.
 */
export interface UsagePeriod {
  readonly period: string;
  /** Milliseconds since the epoch, inclusive. */
  readonly start: number;
  /** Milliseconds since the epoch, exclusive: the next period's start. */
  readonly end: number;
}

/** Years 2000 to 2999: `Date.UTC` reads a two-digit year as the 1900s, so none is accepted. */
const PERIOD = /^(2\d{3})-(0[1-9]|1[0-2])$/;
const DAY_MS = 86_400_000;

/** The period `period` names, or null when it is not one. */
export function usagePeriod(period: string): UsagePeriod | null {
  const match = PERIOD.exec(period);
  if (match === null) return null;
  const year = Number(match[1]);
  const month = Number(match[2]) - 1;
  return { period, start: Date.UTC(year, month, 1), end: Date.UTC(year, month + 1, 1) };
}

/** The period an instant falls in. */
export function periodOf(instant: number): UsagePeriod {
  const date = new Date(instant);
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  return usagePeriod(`${String(date.getUTCFullYear())}-${month}`) as UsagePeriod;
}

/** The period before `period`. */
export function previousPeriod(period: UsagePeriod): UsagePeriod {
  return periodOf(period.start - 1);
}

/** Whether `instant` lies inside the period. */
export function inPeriod(period: UsagePeriod, instant: number): boolean {
  return instant >= period.start && instant < period.end;
}

/** When the report for `period` is due: `dueDays` days after it ends. */
export function reportDueAt(period: UsagePeriod, dueDays: number): number {
  return period.end + dueDays * DAY_MS;
}
