/** How many refusals a gateway writes one line each in a window. */
export const REFUSAL_LINES_PER_WINDOW = 10;
/** The window those lines are counted in. */
export const REFUSAL_WINDOW_MS = 60_000;

/**
 * What a flood of refused requests may cost a chained, retained stream. The
 * first `limit` refusals in a window are written one line each, as they
 * happen; the rest are counted by code, and each count is written once when
 * the window closes. However many requests arrive, and from however many
 * addresses, a window holds at most `limit` lines and one count per code,
 * so the stream grows with time and not with a caller's rate. A window
 * opens at the first refusal after the last one closed, and closes on a
 * timer that never holds the process open, or when the owner flushes it.
 */
export class RefusalSampler<Code extends string> {
  private written = 0;
  private readonly suppressed = new Map<Code, number>();
  private timer: ReturnType<typeof setTimeout> | null = null;

  public constructor(
    private readonly write: (code: Code) => void,
    private readonly summarize: (code: Code, count: number) => void,
    private readonly limit: number = REFUSAL_LINES_PER_WINDOW,
    private readonly windowMs: number = REFUSAL_WINDOW_MS,
  ) {}

  public refuse(code: Code): void {
    if (this.timer === null) {
      this.timer = setTimeout(() => this.flush(), this.windowMs);
      this.timer.unref();
    }
    if (this.written < this.limit) {
      this.written += 1;
      this.write(code);
      return;
    }
    this.suppressed.set(code, (this.suppressed.get(code) ?? 0) + 1);
  }

  /** Closes the window now: each count is written, and the next refusal opens another. */
  public flush(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    this.written = 0;
    for (const [code, count] of this.suppressed) this.summarize(code, count);
    this.suppressed.clear();
  }
}
