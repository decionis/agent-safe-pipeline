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
 * The budget for one dispatch: the smallest of what the configuration
 * allows, what is left of the grant, and what is left of the authority's
 * claim lease when it named one.
 *
 * A provider is never called with more time than the authorization has, so a
 * slow call cannot outlive the permission it was made under. The lease is
 * the tighter bound and the one that matters more: a commit the authority
 * will no longer record leaves an outcome nobody can reconcile from the
 * record, however successful the dispatch was. A window that has already
 * closed is a budget of zero, so the dispatch is refused rather than started.
 */
export function dispatchBudgetMs(
  timeoutMs: number,
  authorization: { readonly expiresAt: string; readonly leaseExpiresAt?: string },
  now: () => number = () => Date.now(),
): number {
  const windows = [authorization.expiresAt, authorization.leaseExpiresAt]
    .filter((at): at is string => at !== undefined)
    .map((at) => Date.parse(at) - now())
    .filter((remaining) => Number.isFinite(remaining));
  return Math.max(Math.min(timeoutMs, ...windows), 0);
}
