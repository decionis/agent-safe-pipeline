/**
 * A deadline that a change to the wall clock cannot move. Dispatch bounds
 * are read from `process.hrtime.bigint()`, so an operator correcting the
 * clock, or an authority whose time differs, cannot extend the window in
 * which a provider may be called.
 */
export class MonotonicDeadline {
  private constructor(
    private readonly startedAt: bigint,
    public readonly budgetMs: number,
    private readonly now: () => bigint,
  ) {}

  public static after(
    budgetMs: number,
    now: () => bigint = process.hrtime.bigint,
  ): MonotonicDeadline {
    return new MonotonicDeadline(now(), Math.max(Math.trunc(budgetMs), 0), now);
  }

  public get elapsedMs(): number {
    return Number((this.now() - this.startedAt) / 1_000_000n);
  }

  public get remainingMs(): number {
    return Math.max(this.budgetMs - this.elapsedMs, 0);
  }

  public get expired(): boolean {
    return this.remainingMs === 0;
  }

  /** A signal that aborts when the remaining budget runs out. */
  public signal(): AbortSignal {
    return AbortSignal.timeout(this.remainingMs);
  }
}

/**
 * The budget for one dispatch: the smaller of what the configuration allows
 * and what is left of the grant. A provider is never called with more time
 * than the authorization has, so a slow call cannot outlive the permission
 * it was made under.
 */
export function dispatchBudgetMs(
  timeoutMs: number,
  expiresAt: string,
  now: () => number = () => Date.now(),
): number {
  const untilExpiry = Date.parse(expiresAt) - now();
  if (!Number.isFinite(untilExpiry)) return timeoutMs;
  return Math.max(Math.min(timeoutMs, untilExpiry), 0);
}
