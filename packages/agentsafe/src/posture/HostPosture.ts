import type { SecurityEvents } from "../incident/SecurityEvents.js";
import {
  DRIFT_CHECKS,
  WAIVABLE_CHECKS,
  evaluate,
  processFacts,
  type PostureCheckId,
  type PostureConfig,
  type PostureFacts,
  type PostureFinding,
} from "./PostureChecks.js";

export type PostureMode = "ENFORCED" | "DEVELOPMENT";

export interface PostureReport {
  readonly mode: PostureMode;
  readonly findings: readonly PostureFinding[];
  /** Failed and not waived: what refuses the start. */
  readonly failed: readonly PostureFinding[];
  /** Failed and waived under development posture. */
  readonly waived: readonly PostureFinding[];
}

/** A refusal to start: the check, never a value. */
export class PostureError extends Error {
  public constructor(
    public readonly check: PostureCheckId,
    public readonly subject?: string,
  ) {
    super(`POSTURE_${check}${subject === undefined ? "" : ` (${subject})`}`);
    this.name = "PostureError";
  }
}

/** What the service consults per request: whether a drift is standing. */
export interface PostureState {
  readonly degraded: boolean;
}

export interface HostPostureOptions {
  readonly mode: PostureMode;
  readonly intervalSeconds: number;
  readonly config: PostureConfig;
  readonly facts?: PostureFacts;
}

/**
 * What this process can verify about the host it runs on, and the refusal
 * to run when it does not hold. It cannot create isolation: the container
 * runtime, Pod Security Admission, and the network policy do that. It can
 * see that it is not root, that its root filesystem and working directory
 * are not writable, that no service-account token was mounted, that no
 * proxy, extra trust anchor, key log, inspector, or option injection sits in
 * its environment, that every secret file is where and how it should be,
 * and that Node's permission model denies writes, child processes, and
 * workers. Under development posture the host-specific checks are waived
 * and said so; the ones that would make the process a different process are
 * never waived. A regression while running is drift.
 */
export class HostPosture implements PostureState {
  private readonly facts: PostureFacts;
  private timer: ReturnType<typeof setInterval> | null = null;
  private drifted = false;
  private last: PostureReport | null = null;

  public constructor(
    private readonly options: HostPostureOptions,
    private readonly events: SecurityEvents,
  ) {
    this.facts = options.facts ?? processFacts();
  }

  public get degraded(): boolean {
    return this.drifted;
  }

  public get report(): PostureReport | null {
    return this.last;
  }

  /** Every check once; the first non-waived failure refuses the start. */
  public assertAtStartup(): PostureReport {
    const report = this.evaluate();
    const failure = report.failed[0];
    if (failure !== undefined) throw new PostureError(failure.id, failure.subject);
    for (const waived of report.waived) {
      this.events.emit({ event: "POSTURE_WAIVED", check: waived.id });
    }
    this.events.emit({
      event: "POSTURE_VERIFIED",
      checks: report.findings.length,
      waived: report.waived.length,
    });
    this.last = report;
    return report;
  }

  /** Repeats the drift subset on the interval; a regression degrades, a recovery restores. */
  public start(): () => void {
    this.stop();
    const timer = setInterval(() => this.tick(), this.options.intervalSeconds * 1_000);
    timer.unref();
    this.timer = timer;
    return () => this.stop();
  }

  public stop(): void {
    if (this.timer !== null) clearInterval(this.timer);
    this.timer = null;
  }

  /** One drift evaluation, for the interval and for tests. */
  public tick(): PostureReport {
    const report = this.evaluate();
    const drift = report.failed.filter((finding) => DRIFT_CHECKS.has(finding.id));
    if (drift.length > 0) {
      if (!this.drifted) {
        for (const finding of drift)
          this.events.emit({ event: "POSTURE_DRIFT", check: finding.id });
      }
      this.drifted = true;
    } else if (this.drifted) {
      this.drifted = false;
      this.events.emit({ event: "POSTURE_RESTORED" });
    }
    this.last = report;
    return report;
  }

  private evaluate(): PostureReport {
    const findings = evaluate(this.options.config, this.facts);
    const failures = findings.filter((finding) => !finding.ok);
    const waivable = (finding: PostureFinding): boolean =>
      this.options.mode === "DEVELOPMENT" && WAIVABLE_CHECKS.has(finding.id);
    return {
      mode: this.options.mode,
      findings,
      failed: failures.filter((finding) => !waivable(finding)),
      waived: failures.filter(waivable),
    };
  }
}
