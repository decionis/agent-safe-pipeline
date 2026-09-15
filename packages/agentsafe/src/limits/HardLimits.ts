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
/** One committed action's place in the window: when, and what it moved. */
interface WindowEntry {
  readonly at: number;
  readonly minor: bigint | null;
}

export class HardLimits {
  /**
   * One window, in the order the actions happened: when each was committed,
   * and what it moved when it moved anything. The count and the sum are both
   * derived from it, so there is no second list to keep in step.
   */
  private readonly window: WindowEntry[] = [];

  public constructor(
    public readonly settings: HardLimitSettings,
    private readonly clock: () => number,
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
    // No `size === 0` case: splitting any string yields at least one entry,
    // and an entry either parses into the map or throws above.
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
    // The `typeof` on the currency is not redundant with the pattern: a
    // regular expression coerces, so `["CHF"]` would match a pattern the
    // string never saw, and a caller sends whatever JSON allows. The amount
    // needs no such guard, because `Number.isSafeInteger` coerces nothing.
    if (typeof currency !== "string" || !/^[A-Z]{3}$/.test(currency)) return "INVALID";
    if (!Number.isSafeInteger(amount) || (amount as number) < 0) return "INVALID";
    return { currency, amountMinor: BigInt(amount as number) };
  }

  /** Whether this action is inside every ceiling right now; it takes nothing. */
  public check(parameters: JsonObject): LimitCheck {
    return this.evaluate(parameters).decision;
  }

  /**
   * The decision and the value it was made about, together, so `commit` does
   * not read the parameters a second time and an invalid amount never
   * escapes this method: it is a refusal here, and what leaves is either a
   * value or nothing.
   */
  private evaluate(parameters: JsonObject): {
    readonly decision: LimitCheck;
    readonly value: MonetaryValue | null;
  } {
    const value = HardLimits.monetaryValue(parameters);
    if (value === "INVALID") {
      return { decision: { allowed: false, code: "HARD_LIMIT_AMOUNT_INVALID" }, value: null };
    }
    return { decision: this.within(value), value };
  }

  private within(value: MonetaryValue | null): LimitCheck {
    if (value !== null) {
      const ceiling = this.settings.singleMinor.get(value.currency);
      if (ceiling === undefined) return { allowed: false, code: "HARD_LIMIT_CURRENCY_UNKNOWN" };
      if (value.amountMinor > ceiling) return { allowed: false, code: "HARD_LIMIT_EXCEEDED" };
    }
    const count = this.settings.windowCount;
    if (count !== null && this.recent().length >= count) {
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
    const { decision, value } = this.evaluate(parameters);
    if (!decision.allowed) return decision;
    this.recent().push({ at: this.clock(), minor: value === null ? null : value.amountMinor });
    return ALLOWED;
  }

  /**
   * The window, pruned. Entries are pushed in the order the clock gave them,
   * so the old ones are at the front and dropping them is a walk from there
   * rather than a pass over the whole list. A clock that went backwards
   * stops the walk early and keeps an entry a moment longer, which refuses
   * more rather than less.
   */
  private recent(): WindowEntry[] {
    const floor = this.clock() - this.settings.windowSeconds * 1_000;
    let oldest = this.window[0];
    while (oldest !== undefined && oldest.at <= floor) {
      this.window.shift();
      oldest = this.window[0];
    }
    return this.window;
  }

  private recentSum(): bigint {
    return this.recent().reduce((total, entry) => total + (entry.minor ?? 0n), 0n);
  }
}
