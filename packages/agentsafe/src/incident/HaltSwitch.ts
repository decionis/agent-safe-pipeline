import { statSync, watch, type FSWatcher } from "node:fs";
import { dirname } from "node:path";
import { RateLimiter, type RateLimitRule } from "../identity/RateLimiter.js";
import type { SecurityEvents } from "./SecurityEvents.js";

/** Why the executor stopped taking new work. */
export type HaltTrigger =
  | "OPERATOR"
  | "HALT_FILE"
  | "POSTURE_DRIFT"
  | "AUTH_FAILURE_SPIKE"
  | "EGRESS_REFUSAL_SPIKE"
  | "CLOCK_SKEW"
  | "AUDIT_CHAIN_BROKEN";

export interface HaltState {
  readonly halted: boolean;
  readonly trigger: HaltTrigger | null;
  /** An operator's words, or the trigger's own code; never anything from a request. */
  readonly reason: string | null;
  readonly since: string | null;
}

export interface HaltSwitchOptions {
  readonly events: SecurityEvents;
  /** A file whose presence halts the executor, watched and polled; none when null. */
  readonly haltFile?: string | null;
  /** `<count>/<seconds>`: how many door refusals in a window halt the executor. */
  readonly authFailures?: RateLimitRule | null;
  readonly egressRefusals?: RateLimitRule | null;
  readonly posture?: { readonly degraded: boolean };
  readonly clock?: () => Date;
  readonly fileExists?: (path: string) => boolean;
  readonly pollSeconds?: number;
}

const POLL_SECONDS = 5;

/**
 * The stop. It is deliberately easy to reach and deliberately hard to
 * leave: an operator halts with a reason, a file halts by existing, and a
 * spike of refusals at the door, a refused outbound request, a posture
 * drift, a clock that cannot be trusted or a broken evidence chain halt on
 * their own. While halted, the executor takes no new work; what is already
 * in flight finishes and is journaled, because abandoning a dispatch is how
 * an outcome becomes unknown.
 *
 * Resuming is an operator's act with a reason, and it is refused while the
 * cause still stands: the halt file still there, a posture drift still
 * standing. A process that starts with the halt file present starts halted.
 *
 * A spike threshold is reachable from the agent zone by design: a
 * compromised caller that floods the door with bad credentials stops the
 * executor rather than being ignored. That is the fail-closed choice, and
 * the threshold is configurable for institutions that would rather not.
 */
export class HaltSwitch {
  private state: HaltState;
  private readonly limits: RateLimiter;
  private readonly clock: () => Date;
  private readonly exists: (path: string) => boolean;
  private watcher: FSWatcher | null = null;
  private poll: ReturnType<typeof setInterval> | null = null;

  public constructor(private readonly options: HaltSwitchOptions) {
    this.clock = options.clock ?? (() => new Date());
    this.exists = options.fileExists ?? HaltSwitch.regularFileExists;
    this.limits = new RateLimiter(() => this.clock().getTime());
    this.state = { halted: false, trigger: null, reason: null, since: null };
  }

  public get current(): HaltState {
    return this.state;
  }

  public get halted(): boolean {
    return this.state.halted;
  }

  /** The halt file decides the starting state, so a restart does not undo a halt. */
  public assertAtStartup(): HaltState {
    if (this.haltFilePresent()) this.halt("HALT_FILE", "the halt file was present at start");
    return this.state;
  }

  /** Follows the halt file while running: created halts, removed only allows a resume. */
  public start(): () => void {
    this.stop();
    const file = this.options.haltFile;
    if (file !== null && file !== undefined) {
      try {
        this.watcher = watch(dirname(file), { persistent: false }, () => this.check());
        this.watcher.on("error", () => undefined);
      } catch {
        this.watcher = null;
      }
      const poll = setInterval(
        () => this.check(),
        (this.options.pollSeconds ?? POLL_SECONDS) * 1_000,
      );
      poll.unref();
      this.poll = poll;
    }
    return () => this.stop();
  }

  public stop(): void {
    this.watcher?.close();
    this.watcher = null;
    if (this.poll !== null) clearInterval(this.poll);
    this.poll = null;
  }

  /** One look at the halt file; for the interval, the watcher, and tests. */
  public check(): void {
    if (this.haltFilePresent() && !this.state.halted) {
      this.halt("HALT_FILE", "the halt file appeared");
    }
  }

  public halt(trigger: HaltTrigger, reason: string): HaltState {
    if (this.state.halted) return this.state;
    this.state = {
      halted: true,
      trigger,
      reason: reason.slice(0, 200),
      since: this.clock().toISOString(),
    };
    this.options.events.emit({ event: "HALTED", trigger, reason: this.state.reason ?? "" });
    return this.state;
  }

  /**
   * Lets work through again, on an operator's word and with a reason. It is
   * refused while the cause stands: the code says which cause, so the
   * operator fixes that rather than retrying.
   */
  public resume(reason: string): { readonly resumed: boolean; readonly code: string | null } {
    if (!this.state.halted) return { resumed: false, code: "NOT_HALTED" };
    if (this.haltFilePresent()) return { resumed: false, code: "HALT_CAUSE_PERSISTS" };
    if (this.options.posture?.degraded === true) {
      return { resumed: false, code: "HALT_CAUSE_PERSISTS" };
    }
    const from = this.state.trigger;
    this.state = { halted: false, trigger: null, reason: null, since: null };
    this.options.events.emit({
      event: "RESUMED",
      trigger: from ?? "OPERATOR",
      reason: reason.slice(0, 200),
    });
    return { resumed: true, code: null };
  }

  /** One refusal at the door; the window's threshold halts the executor. */
  public recordAuthFailure(): void {
    this.recordSpike("auth", this.options.authFailures, "AUTH_FAILURE_SPIKE");
  }

  /** One outbound request the egress policy refused; the window's threshold halts. */
  public recordEgressRefusal(): void {
    this.recordSpike("egress", this.options.egressRefusals, "EGRESS_REFUSAL_SPIKE");
  }

  private recordSpike(
    key: string,
    rule: RateLimitRule | null | undefined,
    trigger: HaltTrigger,
  ): void {
    if (rule === null || rule === undefined || this.state.halted) return;
    // The rule reads as it is written: `50/60` halts on the fiftieth refusal
    // inside a minute, so this one is counted and then the window is asked
    // whether it is now full.
    this.limits.allow(key, rule);
    if (this.limits.exhausted(key, rule)) {
      this.halt(trigger, `${rule.count} in ${rule.windowSeconds}s`);
    }
  }

  private haltFilePresent(): boolean {
    const file = this.options.haltFile;
    if (file === null || file === undefined) return false;
    return this.exists(file);
  }

  private static regularFileExists(path: string): boolean {
    try {
      return statSync(path).isFile();
    } catch {
      return false;
    }
  }
}
