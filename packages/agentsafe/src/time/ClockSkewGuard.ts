import type { FetchLike } from "../handlers/HandlerRegistration.js";
import type { SecurityEvents } from "../incident/SecurityEvents.js";

export interface ClockSkewGuardOptions {
  readonly maxSkewMs: number;
  readonly events: SecurityEvents;
  /** Called when the skew is past the bound; the halt switch, in the process. */
  readonly onExceeded: (skewMs: number) => void;
  /** Where the observed skew is recorded, for the exposition. */
  readonly observe?: (skewMs: number) => void;
  readonly now?: () => number;
}

/**
 * The authority's clock against this host's. Every answer from the
 * authority carries a `Date`, and a boundary that binds short-lived grants
 * cannot afford to disagree with the party issuing them: a host running
 * behind would accept a grant the authority considers expired, and one
 * running ahead would refuse grants that are still good. Past the bound the
 * executor halts rather than guess which clock is right.
 *
 * The skew is measured, not corrected. Nothing here changes a timestamp,
 * and the round trip's own latency is inside the measurement, which is why
 * the bound is a couple of seconds rather than milliseconds.
 */
export function clockSkewGuard(fetchImpl: FetchLike, options: ClockSkewGuardOptions): FetchLike {
  const now = options.now ?? ((): number => Date.now());
  return async (input, init) => {
    const response = await fetchImpl(input, init);
    const header = response.headers.get("date");
    if (header === null) return response;
    const theirs = Date.parse(header);
    if (!Number.isFinite(theirs)) return response;
    // An HTTP date has one-second resolution, so a sub-second difference is
    // the format, not the clock.
    const skew = theirs - now();
    const magnitude = Math.max(Math.abs(skew) - 1_000, 0);
    options.observe?.(skew);
    if (magnitude > options.maxSkewMs) {
      options.events.emit({ event: "CLOCK_SKEW_EXCEEDED", skew_ms: Math.trunc(skew) });
      options.onExceeded(Math.trunc(skew));
    }
    return response;
  };
}
