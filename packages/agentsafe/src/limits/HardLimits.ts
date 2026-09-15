import type { JsonObject } from "@decionis/agent-safe-pipeline";

export type HardLimitCode =
  | "HARD_LIMIT_EXCEEDED"
  | "HARD_LIMIT_CURRENCY_UNKNOWN"
  | "HARD_LIMIT_AMOUNT_INVALID"
  | "HARD_LIMIT_WINDOW_COUNT_EXCEEDED"
  | "HARD_LIMIT_WINDOW_SUM_EXCEEDED";

export interface HardLimitSettings {
  /** The most one action may move, per ISO 4217 code, in minor units. */
  readonly singleMinor: ReadonlyMap<string, bigint>;
  readonly windowSeconds: number;
  readonly windowCount: number | null;
  readonly windowSumMinor: bigint | null;
}

/** What the limits read off an action: an amount in minor units and its currency. */
export interface MonetaryValue {
  readonly currency: string;
  readonly amountMinor: bigint;
}

export type LimitCheck =
  { readonly allowed: true } | { readonly allowed: false; readonly code: HardLimitCode };

const ALLOWED = { allowed: true } as const;

/**
 * The host's own ceilings, above whatever the authority decides. They only
 * ever refuse: a policy that would allow more is still bounded here, and a
 * limit can never widen what the authority narrowed. The check runs before
 * the authority is asked, so nothing that this process would refuse costs a
 * dossier or a grant; the commit runs after an `ALLOW` and before the
 * executor runs, so a refusal consumes no grant and the window cannot be
 * crossed by two requests racing between check and dispatch.
 *
 * The window is process memory: a restart forgets it, and two replicas each
 * keep their own. That is stated rather than hidden, and it is why these are
 * a backstop against a policy mistake, not a treasury control.
 */
export class HardLimits {
  private readonly counts: number[] = [];
  private readonly sums: { readonly at: number; readonly minor: bigint }[] = [];

  public constructor(
    public readonly settings: HardLimitSettings,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  /** `CHF:2500000000,EUR:1000000`: the ceiling per currency, in minor units. */
  public static parseCeilings(text: string, key: string): ReadonlyMap<string, bigint> {
    const ceilings = new Map<string, bigint>();
    for (const entry of text.split(",")) {
      const match = /^([A-Z]{3}):(\d{1,30})$/.exec(entry.trim());
      if (match === null) {
        throw new Error(`CONFIG_INVALID: ${key} (expected <CURRENCY>:<minor units> per entry)`);
      }
      const currency = match[1] as string;
      if (ceilings.has(currency)) throw new Error(`CONFIG_INVALID: ${key} (${currency} twice)`);
      const minor = BigInt(match[2] as string);
      if (minor <= 0n) throw new Error(`CONFIG_INVALID: ${key} (${currency} must be positive)`);
      ceilings.set(currency, minor);
    }
    if (ceilings.size === 0) throw new Error(`CONFIG_INVALID: ${key}`);
    return ceilings;
  }

  /**
   * The monetary value an action carries, when it carries one: an integer
   * `amountMinor` and a three-letter `currency` among the intent's
   * parameters. An action with neither is not a payment and is bounded by
   * the count window alone; an action with one and not the other is refused,
   * because a half-stated amount is not something to guess at.
   */
  public static monetaryValue(parameters: JsonObject): MonetaryValue | null | "INVALID" {
    const currency = parameters["currency"];
    const amount = parameters["amountMinor"];
    if (currency === undefined && amount === undefined) return null;
    if (typeof currency !== "string" || !/^[A-Z]{3}$/.test(currency)) return "INVALID";
    if (typeof amount !== "number" || !Number.isSafeInteger(amount) || amount < 0) return "INVALID";
    return { currency, amountMinor: BigInt(amount) };
  }

  /** Whether this action is inside every ceiling right now; it takes nothing. */
  public check(parameters: JsonObject): LimitCheck {
    const value = HardLimits.monetaryValue(parameters);
    if (value === "INVALID") return { allowed: false, code: "HARD_LIMIT_AMOUNT_INVALID" };
    if (value !== null) {
      const ceiling = this.settings.singleMinor.get(value.currency);
      if (ceiling === undefined) return { allowed: false, code: "HARD_LIMIT_CURRENCY_UNKNOWN" };
      if (value.amountMinor > ceiling) return { allowed: false, code: "HARD_LIMIT_EXCEEDED" };
    }
    const count = this.settings.windowCount;
    if (count !== null && this.recentCounts().length >= count) {
      return { allowed: false, code: "HARD_LIMIT_WINDOW_COUNT_EXCEEDED" };
    }
    const sum = this.settings.windowSumMinor;
    if (sum !== null && value !== null && this.recentSum() + value.amountMinor > sum) {
      return { allowed: false, code: "HARD_LIMIT_WINDOW_SUM_EXCEEDED" };
    }
    return ALLOWED;
  }

  /** Takes this action's place in the windows, after the check and before it runs. */
  public commit(parameters: JsonObject): LimitCheck {
    const decision = this.check(parameters);
    if (!decision.allowed) return decision;
    const now = this.clock();
    this.recentCounts().push(now);
    const value = HardLimits.monetaryValue(parameters);
    if (value !== null && value !== "INVALID")
      this.sums.push({ at: now, minor: value.amountMinor });
    return ALLOWED;
  }

  private recentCounts(): number[] {
    const floor = this.clock() - this.settings.windowSeconds * 1_000;
    const kept = this.counts.filter((at) => at > floor);
    this.counts.length = 0;
    this.counts.push(...kept);
    return this.counts;
  }

  private recentSum(): bigint {
    const floor = this.clock() - this.settings.windowSeconds * 1_000;
    const kept = this.sums.filter((entry) => entry.at > floor);
    this.sums.length = 0;
    this.sums.push(...kept);
    return kept.reduce((total, entry) => total + entry.minor, 0n);
  }
}
