import { inPeriod, periodOf, type UsagePeriod } from "./UsagePeriod.js";

export const USAGE_MODES = ["ENFORCEMENT", "SHADOW"] as const;
export const USAGE_VERDICTS = ["ALLOW", "ESCALATE", "BLOCK"] as const;

export type UsageMode = (typeof USAGE_MODES)[number];
export type UsageVerdict = (typeof USAGE_VERDICTS)[number];

/** One `EDGE_DECISION` line, as linked on the evidence chain. */
export interface UsageLine {
  readonly at: string;
  readonly mode: unknown;
  readonly verdict: unknown;
  readonly delegated: unknown;
  readonly jti: unknown;
  readonly seq: number;
  readonly hash: string;
}

/** The chain range a period's counts were taken from; all null when nothing was counted. */
export interface UsageRange {
  readonly first_seq: number | null;
  readonly first_hash: string | null;
  readonly last_seq: number | null;
  readonly last_hash: string | null;
}

/** What one period counted: the usage report's `counts`, `delegated`, range and `bundles`. */
export interface PeriodUsage extends UsageRange {
  readonly counts: {
    readonly by_mode: Readonly<Record<UsageMode, number>>;
    readonly by_verdict: Readonly<Record<UsageVerdict, number>>;
    readonly total: number;
  };
  /** Decisions handed to Decionis (an enforcement `ESCALATE`), which Decionis meters itself. */
  readonly delegated: number;
  /** The bundle `jti`s decided on, sorted, each once. */
  readonly bundles: readonly string[];
}

/** A period with nothing counted. */
export function emptyUsage(): PeriodUsage {
  return {
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
  };
}

function isMember<T extends string>(values: readonly T[], value: unknown): value is T {
  return (values as readonly unknown[]).includes(value);
}

/**
 * The count of `EDGE_DECISION` lines per UTC month, the same count whether
 * it is kept as lines are written or recounted later from the chain. A line
 * is counted in the period its `at` falls in; lines arrive in chain order,
 * so the first and last counted lines are the period's range. Every edge
 * decision is counted once in `total`; the delegated ones are also counted
 * in `delegated`, which Decionis subtracts because it meters those itself.
 */
export class UsageTally {
  private readonly periods = new Map<string, PeriodUsage>();

  public constructor(initial: Readonly<Record<string, PeriodUsage>> = {}) {
    for (const [period, usage] of Object.entries(initial)) this.periods.set(period, usage);
  }

  /**
   * Counts `line` in its period and returns that period, or null for a line
   * that is not a countable decision: an unknown mode or verdict, a
   * `delegated` that is not a boolean, a `jti` that is not a string, an `at`
   * that is not a time. A line outside `only`, when given, is not counted.
   */
  public add(line: UsageLine, only?: UsagePeriod): string | null {
    const at = Date.parse(line.at);
    if (
      Number.isNaN(at) ||
      !isMember(USAGE_MODES, line.mode) ||
      !isMember(USAGE_VERDICTS, line.verdict) ||
      typeof line.delegated !== "boolean" ||
      typeof line.jti !== "string" ||
      (only !== undefined && !inPeriod(only, at))
    ) {
      return null;
    }
    const period = periodOf(at).period;
    const usage = this.usage(period);
    this.periods.set(period, {
      counts: {
        by_mode: { ...usage.counts.by_mode, [line.mode]: usage.counts.by_mode[line.mode] + 1 },
        by_verdict: {
          ...usage.counts.by_verdict,
          [line.verdict]: usage.counts.by_verdict[line.verdict] + 1,
        },
        total: usage.counts.total + 1,
      },
      delegated: usage.delegated + (line.delegated ? 1 : 0),
      first_seq: usage.first_seq ?? line.seq,
      first_hash: usage.first_hash ?? line.hash,
      last_seq: line.seq,
      last_hash: line.hash,
      bundles: [...new Set([...usage.bundles, line.jti])].sort(),
    });
    return period;
  }

  /** What `period` counted; the empty usage when it counted nothing. */
  public usage(period: string): PeriodUsage {
    return this.periods.get(period) ?? emptyUsage();
  }

  /** The periods that counted anything, oldest first. */
  public counted(): readonly string[] {
    return [...this.periods.keys()].sort();
  }

  /** Forgets `period`, once its report is delivered and it is old enough to need no recount. */
  public forget(period: string): void {
    this.periods.delete(period);
  }

  public snapshot(): Readonly<Record<string, PeriodUsage>> {
    return Object.fromEntries(this.periods);
  }
}
