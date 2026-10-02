import { randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import type { HashChain } from "../audit/HashChain.js";
import type { FetchLike } from "../handlers/HandlerRegistration.js";
import type { SecurityEvents } from "../incident/SecurityEvents.js";
import { withoutTrailingSlash } from "./Entitlement.js";
import { periodOf, previousPeriod, usagePeriod, type UsagePeriod } from "./UsagePeriod.js";
import { signUsageReport, usageReportClaims, type UsageSigningKey } from "./UsageReport.js";
import { UsageTally, type UsageLine } from "./UsageTally.js";

/** How many completed periods back a report is still made for. */
const LOOKBACK_PERIODS = 12;

/** Where a signed report goes: Decionis, or a directory an operator uploads from. */
export interface UsageDelivery {
  readonly kind: "url" | "file";
  /** `DELIVERED`, or a code saying why not; never throws. */
  deliver(period: string, installationId: string, report: string): Promise<string>;
}

/** The refusal code Decionis answered with, when it is one of the usage report's own. */
async function refusalOf(response: Response): Promise<string | null> {
  try {
    const body = (await response.json()) as { error?: unknown };
    return typeof body.error === "string" && /^USAGE_REPORT_[A-Z_]{1,50}$/.test(body.error)
      ? body.error
      : null;
  } catch {
    return null;
  }
}

/**
 * `POST /v1/edge/usage-reports` (`{"report": "<compact JWS>"}`) with the
 * organisation's key. A `USAGE_REPORT_DUPLICATE` conflict means Decionis
 * already holds this period's report at the same or a later chain position,
 * so the report is delivered; any other refusal is returned by its code.
 */
export class UrlUsageDelivery implements UsageDelivery {
  public readonly kind = "url";

  public constructor(
    private readonly options: {
      readonly baseUrl: string;
      readonly apiKey: () => string;
      readonly fetch: FetchLike;
    },
  ) {}

  public async deliver(_period: string, _installation: string, report: string): Promise<string> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    try {
      const response = await this.options.fetch(
        `${withoutTrailingSlash(this.options.baseUrl)}/v1/edge/usage-reports`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${this.options.apiKey()}`,
            "content-type": "application/json",
            accept: "application/json",
          },
          body: JSON.stringify({ report }),
          signal: controller.signal,
        },
      );
      if (response.ok) {
        await response.body?.cancel().catch(() => undefined);
        return "DELIVERED";
      }
      const refusal = await refusalOf(response);
      if (refusal === "USAGE_REPORT_DUPLICATE") return "DELIVERED";
      return refusal ?? `USAGE_HTTP_${response.status}`;
    } catch {
      return "USAGE_SEND_FAILED";
    } finally {
      clearTimeout(timeout);
    }
  }
}

/** The air-gapped form: `usage-<period>-<installation>.jws` in a directory, written atomically. */
export class FileUsageDelivery implements UsageDelivery {
  public readonly kind = "file";

  public constructor(private readonly directory: string) {}

  public async deliver(period: string, installationId: string, report: string): Promise<string> {
    const name = `usage-${period}-${installationId.replace(/[^\w.-]/g, "_")}.jws`;
    const path = join(this.directory, name);
    try {
      mkdirSync(this.directory, { recursive: true, mode: 0o700 });
      writeFileSync(`${path}.tmp`, `${report}\n`, { mode: 0o600 });
      renameSync(`${path}.tmp`, path);
      return "DELIVERED";
    } catch {
      return "USAGE_WRITE_FAILED";
    }
  }
}

const PeriodUsageSchema = z.strictObject({
  counts: z.strictObject({
    by_mode: z.strictObject({ ENFORCEMENT: z.number(), SHADOW: z.number() }),
    by_verdict: z.strictObject({ ALLOW: z.number(), ESCALATE: z.number(), BLOCK: z.number() }),
    total: z.number(),
  }),
  delegated: z.number(),
  first_seq: z.number().nullable(),
  first_hash: z.string().nullable(),
  last_seq: z.number().nullable(),
  last_hash: z.string().nullable(),
  bundles: z.array(z.string()),
});

const MeterStateSchema = z.strictObject({
  version: z.literal(1),
  installation_id: z.string().min(1).max(200),
  since: z.number(),
  head: z.strictObject({ seq: z.number(), hash: z.string() }),
  periods: z.record(z.string(), PeriodUsageSchema),
  delivered: z.array(z.string()),
});

export interface UsageMeterOptions {
  readonly orgId: string;
  readonly chain: HashChain;
  /** The installation id the operator chose; generated and kept with the tally when null. */
  readonly installationId: string | null;
  /** Where the tally persists (`<journal>/edge`); in memory only when null. */
  readonly stateDir: string | null;
  /** How many evidence links between persisted tallies: the chain journal's cadence. */
  readonly checkpointLines: number;
  readonly events: SecurityEvents;
  /** Reads the usage-report key; without one nothing is reported, and the licence check warns. */
  readonly key: (() => UsageSigningKey) | null;
  readonly delivery: UsageDelivery | null;
  readonly clock: () => number;
}

/**
 * The live count of this installation's edge decisions, and the monthly
 * reports made from it. The tally is persisted with the evidence chain's
 * head, at the journal's cadence and on stop, so it resumes exactly where
 * the chain resumes; a tally whose head is not the chain's restored head
 * belongs to a chain that is gone, and is dropped with a warning (the
 * month can be recounted from the collected log with
 * `agentsafe edge usage-report`).
 */
export class UsageMeter {
  public readonly installationId: string;
  private readonly tally: UsageTally;
  private readonly delivered: Set<string>;
  private readonly since: number;
  private readonly unsubscribe: () => void;

  public constructor(private readonly options: UsageMeterOptions) {
    const restored = this.restore();
    const head = options.chain.head;
    const resumes =
      restored !== null &&
      restored.head.seq === head.seq &&
      restored.head.hash === head.hash &&
      (options.installationId === null || options.installationId === restored.installation_id);
    if (restored !== null && !resumes) {
      options.events.emit({ event: "EDGE_USAGE_TALLY_RESET", head: head.seq });
    }
    this.installationId =
      options.installationId ?? (resumes ? restored.installation_id : `inst_${randomUUID()}`);
    this.tally = new UsageTally(resumes ? restored.periods : {});
    this.delivered = new Set(resumes ? restored.delivered : []);
    this.since = resumes ? restored.since : options.clock();
    let links = 0;
    this.unsubscribe = options.chain.onLink(() => {
      links += 1;
      if (links < options.checkpointLines) return;
      links = 0;
      this.persist();
    });
  }

  /** Counts one `EDGE_DECISION` line, as it was linked. */
  public observe(line: UsageLine): void {
    this.tally.add(line);
  }

  /** Governed actions this installation counted in the current month: decisions not delegated. */
  public governed(): number {
    const usage = this.tally.usage(periodOf(this.options.clock()).period);
    return usage.counts.total - usage.delegated;
  }

  /** Whether a usage-report key is configured. */
  public get reporting(): boolean {
    return this.options.key !== null;
  }

  /** Completed periods since this installation began whose report has not been delivered. */
  public undelivered(): readonly string[] {
    const periods: string[] = [];
    let period = previousPeriod(periodOf(this.options.clock()));
    for (let back = 0; back < LOOKBACK_PERIODS && period.end > this.since; back += 1) {
      if (!this.delivered.has(period.period)) periods.push(period.period);
      period = previousPeriod(period);
    }
    return periods.reverse();
  }

  /**
   * Signs and delivers every undelivered completed period's report, oldest
   * first. Never throws: a report that cannot be signed or delivered is an
   * `EDGE_USAGE_REPORT_FAILED` line and is tried again on the next round.
   */
  public async report(): Promise<void> {
    const { delivery } = this.options;
    const key = this.options.key;
    if (key === null || delivery === null) return;
    for (const name of this.undelivered()) {
      const period = usagePeriod(name) as UsagePeriod;
      let report: string;
      try {
        report = await signUsageReport(
          usageReportClaims({
            installationId: this.installationId,
            orgId: this.options.orgId,
            period,
            usage: this.tally.usage(name),
            stream: this.options.chain.stream,
            now: this.options.clock(),
          }),
          key(),
        );
      } catch {
        this.options.events.emit({
          event: "EDGE_USAGE_REPORT_FAILED",
          period: name,
          code: "USAGE_SIGN_FAILED",
        });
        continue;
      }
      const code = await delivery.deliver(name, this.installationId, report);
      if (code !== "DELIVERED") {
        this.options.events.emit({ event: "EDGE_USAGE_REPORT_FAILED", period: name, code });
        continue;
      }
      this.delivered.add(name);
      this.options.events.emit({
        event: "EDGE_USAGE_REPORTED",
        period: name,
        destination: delivery.kind,
        total: this.tally.usage(name).counts.total,
      });
      this.tally.forget(name);
    }
    this.persist();
  }

  /** Stops following the chain and persists the tally once more. */
  public stop(): void {
    this.unsubscribe();
    this.persist();
  }

  private path(): string | null {
    return this.options.stateDir === null ? null : join(this.options.stateDir, "usage.json");
  }

  private restore(): z.infer<typeof MeterStateSchema> | null {
    const path = this.path();
    if (path === null) return null;
    try {
      const parsed = MeterStateSchema.safeParse(JSON.parse(readFileSync(path, "utf8")));
      return parsed.success ? parsed.data : null;
    } catch {
      return null;
    }
  }

  private persist(): void {
    const path = this.path();
    if (path === null || this.options.stateDir === null) return;
    // Only the window a report can still be made for is kept.
    const windowStart = this.windowStart();
    const old = (period: string): boolean =>
      (usagePeriod(period) as UsagePeriod).end <= windowStart;
    for (const period of this.tally.counted()) if (old(period)) this.tally.forget(period);
    const state = {
      version: 1,
      installation_id: this.installationId,
      since: this.since,
      head: { ...this.options.chain.head },
      periods: { ...this.tally.snapshot() },
      delivered: [...this.delivered].filter((period) => !old(period)),
    };
    try {
      mkdirSync(this.options.stateDir, { recursive: true, mode: 0o700 });
      writeFileSync(`${path}.tmp`, JSON.stringify(state), { mode: 0o600 });
      renameSync(`${path}.tmp`, path);
    } catch {
      this.options.events.emit({ event: "EDGE_USAGE_PERSIST_FAILED" });
    }
  }

  /** The start of the oldest period a report is still made for. */
  private windowStart(): number {
    let period = periodOf(this.options.clock());
    for (let back = 0; back < LOOKBACK_PERIODS; back += 1) period = previousPeriod(period);
    return period.start;
  }
}
