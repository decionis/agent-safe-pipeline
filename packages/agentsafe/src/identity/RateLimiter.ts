export interface RateLimitRule {
  readonly count: number;
  readonly windowSeconds: number;
}

export interface LockoutRule {
  readonly failures: number;
  readonly windowSeconds: number;
  readonly lockSeconds: number;
}

const RULE = /^([1-9]\d{0,5})\/([1-9]\d{0,4})$/;
const LOCKOUT = /^(\d{1,6})\/([1-9]\d{0,4})\/([1-9]\d{0,5})$/;

/**
 * Sliding windows keyed by principal id, plus one key for requests that
 * never became a principal. Memory is bounded by the registry: a key holds
 * at most its rule's count of timestamps, and there is no key a caller can
 * invent. A lockout engages when a principal's authentication failures reach
 * the rule inside its window, and ends only when the lock expires or the
 * process restarts.
 */
export class RateLimiter {
  private readonly hits = new Map<string, number[]>();
  private readonly failures = new Map<string, number[]>();
  private readonly locks = new Map<string, number>();

  public constructor(private readonly clock: () => number = () => Date.now()) {}

  /** `<count>/<seconds>`; a refusal names the variable. */
  public static parseRule(text: string, key: string): RateLimitRule {
    const match = RULE.exec(text.trim());
    if (match === null) throw new Error(`CONFIG_INVALID: ${key} (expected <count>/<seconds>)`);
    return { count: Number(match[1]), windowSeconds: Number(match[2]) };
  }

  /** `<failures>/<seconds>/<lock seconds>`; zero failures disables the lockout. */
  public static parseLockout(text: string, key: string): LockoutRule | null {
    const match = LOCKOUT.exec(text.trim());
    if (match === null) {
      throw new Error(`CONFIG_INVALID: ${key} (expected <failures>/<seconds>/<lock seconds>)`);
    }
    const failures = Number(match[1]);
    if (failures === 0) return null;
    return { failures, windowSeconds: Number(match[2]), lockSeconds: Number(match[3]) };
  }

  /** Whether the key has room under the rule right now, without taking any. */
  public exhausted(key: string, rule: RateLimitRule): boolean {
    return this.recent(this.hits, key, rule.windowSeconds).length >= rule.count;
  }

  /** Takes one request from the key's window; false when the window is full. */
  public allow(key: string, rule: RateLimitRule): boolean {
    const now = this.clock();
    const window = this.recent(this.hits, key, rule.windowSeconds);
    if (window.length >= rule.count) return false;
    window.push(now);
    return true;
  }

  /** Records an authentication failure; true when this one engaged the lock. */
  public recordFailure(key: string, rule: LockoutRule | null): boolean {
    if (rule === null) return false;
    const now = this.clock();
    const window = this.recent(this.failures, key, rule.windowSeconds);
    window.push(now);
    if (window.length < rule.failures) return false;
    this.failures.delete(key);
    this.locks.set(key, now + rule.lockSeconds * 1_000);
    return true;
  }

  public locked(key: string): boolean {
    const until = this.locks.get(key);
    if (until === undefined) return false;
    if (until > this.clock()) return true;
    this.locks.delete(key);
    return false;
  }

  private recent(store: Map<string, number[]>, key: string, windowSeconds: number): number[] {
    const floor = this.clock() - windowSeconds * 1_000;
    const kept = (store.get(key) ?? []).filter((at) => at > floor);
    store.set(key, kept);
    return kept;
  }
}
