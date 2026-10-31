/**
 * The gateway's side of an acceptance run
 * ([ADR 0009](../../../../docs/architecture/decisions/0009-acceptance-run-on-named-targets.md)):
 * one run open at a time, the plan checked against the gateway's own routes,
 * a prohibited write decided in shadow before it may be sent, each tagged
 * request matched to the write the plan names, and the report assembled from
 * what the gateway itself observed, then signed.
 *
 * What it establishes: that the requests the gateway reports on are the ones
 * the plan names, and what the gateway did with each. What it does not: the
 * zone's findings are the zone's word, carried as reported, and judged by the
 * same rules but never checked here.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { JsonValue } from "@decionis/agent-safe-pipeline";
import type { ChainFields } from "../audit/HashChain.js";
import type { DeploymentFingerprint } from "../posture/DeploymentFingerprint.js";
import type { InterceptionReport } from "../gateway/GatewayReport.js";
import type { AcceptancePlanError } from "./AcceptancePlan.js";
import {
  parseAcceptancePlan,
  planDigest,
  splitTarget,
  writeBody,
  type AcceptancePlan,
  type PlanWrite,
  type ProhibitedWrite,
} from "./AcceptancePlan.js";
import {
  ACCEPTANCE_REPORT_VERSION,
  ACCEPTANCE_SCOPE,
  AcceptanceReportSchema,
  STATED_NOT_RUN,
  acceptanceVerdict,
  judgeOutage,
  judgePermitted,
  judgeProhibited,
  type AcceptanceReport,
  type CaseLine,
  type Coverage,
  type GovernedOutcome,
  type OutageCase,
  type PermittedCase,
  type ProhibitedCase,
  type TargetObservation,
} from "./AcceptanceReport.js";
import { zoneFindingsSchema } from "./ZoneProbes.js";

/** The header a run's request carries: `<run id>:<write name>`. Never forwarded. */
export const ACCEPTANCE_RUN_HEADER = "agentsafe-acceptance-run";

/** How long a run stays open before it is discarded unsigned. */
export const RUN_TTL_MS = 15 * 60 * 1_000;

/** The longest the close waits for the gateway's reports on what was sent. */
export const CLOSE_WAIT_MS = 30_000;

/** How the gateway routes one write. */
export interface RouteFacts {
  /** Decided by the authority in enforcement, failing closed or open. */
  readonly enforced: boolean;
  readonly action: string | null;
  /** Whether the write's profile operation names a read of its target. */
  readonly targetRead: boolean;
}

export interface ShadowOutcome {
  readonly verdict: "ALLOW" | "BLOCK" | "ESCALATE" | null;
  readonly reason_codes: readonly string[];
  readonly decision_id: string | null;
  readonly dossier_id: string | null;
}

export interface OutageOutcome {
  readonly status: number | null;
  readonly execution: string | null;
  readonly reason_codes: readonly string[];
  /** Requests other than reads that reached the second gateway's recording upstream. */
  readonly upstreamWrites: number;
}

/** What the gateway lends a run. */
export interface AcceptanceHost {
  readonly boundaryId: string;
  readonly fingerprint: DeploymentFingerprint;
  readonly failurePolicy: "FAIL_CLOSED" | "FAIL_OPEN";
  readonly coverage: Coverage;
  route(write: PlanWrite): RouteFacts;
  /** The write decided in shadow, captured as its route captures it; nothing read or forwarded. */
  decide(write: PlanWrite): Promise<ShadowOutcome>;
  /** The write through a second gateway whose authority is down and whose upstream records. */
  outage(write: PlanWrite): Promise<OutageOutcome>;
  /** Settles once every read after a refusal still due has been made. */
  settled(): Promise<void>;
  /** One line on the gateway's chain, and where it went. */
  link(fields: ChainFields): CaseLine;
  sign(report: AcceptanceReport): Promise<string>;
  clock(): number;
}

/** What an endpoint answers. */
export interface RunAnswer {
  readonly status: number;
  readonly body: Readonly<Record<string, JsonValue>>;
}

/** A request carrying the run header: tracked as one write, refused, or the header absent. */
export type Admission =
  | { readonly kind: "NONE" }
  | { readonly kind: "REFUSE"; readonly code: string }
  | { readonly kind: "TRACK"; readonly name: string };

interface Sent {
  report: InterceptionReport | null;
  answered: { readonly state: string | null; readonly execution: string | null } | null;
  intentId: string | null;
  readonly lines: CaseLine[];
  observation: TargetObservation | null;
  reported: () => void;
  readonly settled: Promise<void>;
}

interface OpenRun {
  readonly id: string;
  /** The run as the chain and the report name it: never the id, which admits requests. */
  readonly publicId: string;
  readonly plan: AcceptancePlan;
  readonly digest: string;
  readonly openedAt: number;
  readonly writes: ReadonlyMap<
    string,
    { readonly kind: "permitted" | "prohibited"; readonly write: PlanWrite }
  >;
  readonly shadow: Map<string, ShadowOutcome>;
  readonly sent: Map<string, Sent>;
  /** Each tracked write by the intent it was captured as; keyed by whatever a line names. */
  readonly intents: Map<unknown, Sent>;
  closing: boolean;
}

/** A write's path and query, as the listener reads them. */
function targetOf(path: string): string {
  const { path: pathname, search } = splitTarget(path);
  return `${pathname}${search}`;
}

function refused(status: number, code: string, detail?: string): RunAnswer {
  return { status, body: detail === undefined ? { code } : { code, detail } };
}

function sameSecret(presented: string, expected: string): boolean {
  const a = createHash("sha256").update(presented).digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b);
}

export class AcceptanceRuns {
  private run: OpenRun | null = null;

  public constructor(
    private readonly host: AcceptanceHost,
    private readonly random: () => string = () => randomBytes(32).toString("base64url"),
  ) {}

  /** The open run: none once its time is up, unless it is already closing. */
  private current(): OpenRun | null {
    const run = this.run;
    return run !== null && (run.closing || this.host.clock() - run.openedAt < RUN_TTL_MS)
      ? run
      : null;
  }

  private named(runId: string): OpenRun | null {
    const run = this.current();
    return run !== null && sameSecret(runId, run.id) ? run : null;
  }

  /**
   * Opens a run for a plan, once the plan's writes are all writes this gateway
   * decides in enforcement, and each prohibited one reads its target. A run
   * already open refuses another until it closes or its time is up.
   */
  public open(body: unknown): RunAnswer {
    if (this.current() !== null) return refused(409, "ACCEPTANCE_RUN_OPEN");
    let plan: AcceptancePlan;
    try {
      plan = parseAcceptancePlan(body);
    } catch (error) {
      return refused(400, "ACCEPTANCE_PLAN_INVALID", (error as AcceptancePlanError).detail);
    }
    const writes = new Map<
      string,
      { readonly kind: "permitted" | "prohibited"; readonly write: PlanWrite }
    >();
    const routes: JsonValue[] = [];
    for (const [kind, list] of [
      ["permitted", plan.permitted],
      ["prohibited", plan.prohibited],
    ] as const) {
      for (const write of list) {
        const route = this.host.route(write);
        if (!route.enforced) return refused(422, "ACCEPTANCE_WRITE_NOT_ENFORCED", write.name);
        if (kind === "prohibited" && !route.targetRead) {
          return refused(422, "ACCEPTANCE_WRITE_NOT_OBSERVABLE", write.name);
        }
        writes.set(write.name, { kind, write });
        routes.push({ name: write.name, kind, action: route.action });
      }
    }
    const id = this.random();
    const digest = planDigest(plan);
    const publicId = createHash("sha256").update(id).digest("hex").slice(0, 32);
    this.run = {
      id,
      publicId,
      plan,
      digest,
      openedAt: this.host.clock(),
      writes,
      shadow: new Map(),
      sent: new Map(),
      intents: new Map(),
      closing: false,
    };
    this.host.link({
      event: "ACCEPTANCE_RUN_OPENED",
      run_id: publicId,
      plan_digest: digest,
      fingerprint: this.host.fingerprint.digest,
    });
    return {
      status: 201,
      body: {
        run_id: id,
        plan_digest: digest,
        expires_at: new Date(this.host.clock() + RUN_TTL_MS).toISOString(),
        fingerprint: this.host.fingerprint.digest,
        coverage: this.host.coverage as unknown as JsonValue,
        writes: routes,
      },
    };
  }

  /**
   * A prohibited write the open run names, decided in shadow: nothing read,
   * nothing forwarded, the decision on the chain. Only a write the plan names
   * as prohibited is decided, once; the endpoint answers nothing else.
   */
  public async decide(runId: string, name: string): Promise<RunAnswer> {
    const run = this.named(runId);
    if (run === null) return refused(404, "ACCEPTANCE_RUN_UNKNOWN");
    const entry = run.writes.get(name);
    if (entry?.kind !== "prohibited") return refused(404, "ACCEPTANCE_WRITE_UNKNOWN");
    if (run.shadow.has(name)) return refused(409, "ACCEPTANCE_WRITE_DECIDED");
    const outcome = await this.host.decide(entry.write);
    run.shadow.set(name, outcome);
    this.host.link({
      event: "ACCEPTANCE_SHADOW_DECIDED",
      run_id: run.publicId,
      write: name,
      verdict: outcome.verdict,
      decision_id: outcome.decision_id,
    });
    return {
      status: 200,
      body: {
        write: name,
        verdict: outcome.verdict,
        reason_codes: [...outcome.reason_codes],
        decision_id: outcome.decision_id,
        dossier_id: outcome.dossier_id,
      },
    };
  }

  /**
   * Whether a request carrying the run header is a write the open run names,
   * sent as the plan wrote it, once, and, when prohibited, only after a shadow
   * BLOCK or ESCALATE. Anything else carrying the header is refused before
   * the authority is asked, so a run never sends what its plan did not name.
   */
  public admit(
    tag: string | undefined,
    request: {
      readonly method: string;
      readonly path: string;
      readonly search: string;
      readonly body: Buffer;
    },
  ): Admission {
    if (tag === undefined) return { kind: "NONE" };
    const at = tag.lastIndexOf(":");
    const run = at === -1 ? null : this.named(tag.slice(0, at));
    if (run === null || run.closing) return { kind: "REFUSE", code: "ACCEPTANCE_RUN_UNKNOWN" };
    const name = tag.slice(at + 1);
    const entry = run.writes.get(name);
    if (entry === undefined) return { kind: "REFUSE", code: "ACCEPTANCE_WRITE_UNKNOWN" };
    const { write } = entry;
    if (
      request.method.toUpperCase() !== write.method ||
      `${request.path}${request.search}` !== targetOf(write.path) ||
      !request.body.equals(writeBody(write))
    ) {
      return { kind: "REFUSE", code: "ACCEPTANCE_WRITE_DIFFERS" };
    }
    if (run.sent.has(name)) return { kind: "REFUSE", code: "ACCEPTANCE_WRITE_REPEATED" };
    if (entry.kind === "prohibited") {
      const verdict = run.shadow.get(name)?.verdict;
      if (verdict !== "BLOCK" && verdict !== "ESCALATE") {
        return { kind: "REFUSE", code: "ACCEPTANCE_SHADOW_REFUSAL_REQUIRED" };
      }
    }
    let reported = (): void => undefined;
    const settled = new Promise<void>((resolve) => {
      reported = resolve;
    });
    run.sent.set(name, {
      report: null,
      answered: null,
      intentId: null,
      lines: [],
      observation: null,
      reported,
      settled,
    });
    return { kind: "TRACK", name };
  }

  /** The intent a tracked write was captured as. */
  public captured(name: string, intentId: string): void {
    const run = this.run;
    if (run === null) return;
    const sent = run.sent.get(name);
    if (sent === undefined) return;
    sent.intentId = intentId;
    run.intents.set(intentId, sent);
  }

  /** The gateway's answer to a tracked write, for one refused before it was captured. */
  public answered(name: string, state: string | null, execution: string | null): void {
    const sent = this.run?.sent.get(name);
    if (sent === undefined) return;
    sent.answered = { state, execution };
    if (sent.intentId === null) sent.reported();
  }

  /** What the gateway reported of a tracked write. */
  public intercepted(report: InterceptionReport): void {
    const sent = this.run?.intents.get(report.intent_id);
    if (sent === undefined) return;
    sent.report = report;
    sent.reported();
  }

  /** A line the gateway chained about a tracked write. */
  public linked(fields: ChainFields, line: CaseLine): void {
    const sent = this.run?.intents.get(fields["intent_id"]);
    if (sent === undefined) return;
    if (sent.lines.length < 16) sent.lines.push(line);
    if (fields["event"] === "REFUSAL_OBSERVATION") {
      const text = (key: string): string | null => {
        const value = fields[key];
        return typeof value === "string" ? value : null;
      };
      sent.observation = {
        outcome: fields["outcome"] as TargetObservation["outcome"],
        version_before: text("version_before"),
        version_after: text("version_after"),
        read_before_at: text("read_before_at"),
        read_after_at: text("read_after_at"),
      };
    }
  }

  /**
   * Closes the run: the zone's findings taken as reported, the outage case
   * run on the second gateway, every read after a refusal awaited, the report
   * assembled from what the gateway observed, signed, and its digest chained.
   */
  public async close(runId: string, findings: unknown): Promise<RunAnswer> {
    const run = this.named(runId);
    if (run === null || run.closing) return refused(404, "ACCEPTANCE_RUN_UNKNOWN");
    const zone = zoneFindingsSchema.safeParse(findings);
    if (!zone.success) return refused(400, "ACCEPTANCE_ZONE_FINDINGS_INVALID");
    run.closing = true;
    try {
      const outage: OutageCase[] = [];
      for (const { write } of run.writes.values()) outage.push(await this.outageCase(write));
      await Promise.race([
        Promise.all([...run.sent.values()].map((sent) => sent.settled)),
        new Promise<void>((resolve) => setTimeout(resolve, CLOSE_WAIT_MS).unref()),
      ]);
      await this.host.settled();
      const permitted = run.plan.permitted.map((write) => this.permittedCase(run, write));
      const prohibited = run.plan.prohibited.map((write) => this.prohibitedCase(run, write));
      const issuedAt = this.host.clock();
      const cases = { permitted, prohibited, outage, zone: zone.data };
      const report: AcceptanceReport = {
        report: ACCEPTANCE_REPORT_VERSION,
        run_id: run.publicId,
        boundary_id: this.host.boundaryId,
        issued_at: new Date(issuedAt).toISOString(),
        expires_at: run.plan.expires_at,
        plan_digest: run.digest,
        fingerprint: {
          digest: this.host.fingerprint.digest,
          document: this.host.fingerprint.document as unknown as Record<string, JsonValue>,
        },
        coverage: this.host.coverage,
        ...cases,
        stated: STATED_NOT_RUN.map((item) => ({ ...item })),
        ...acceptanceVerdict(cases),
        scope: ACCEPTANCE_SCOPE,
      };
      // A report a verifier would refuse is never signed: what the gateway
      // observed must fit the contract it signs it under.
      if (!AcceptanceReportSchema.safeParse(report).success) {
        return refused(500, "ACCEPTANCE_REPORT_INVALID");
      }
      const token = await this.host.sign(report);
      this.host.link({
        event: "ACCEPTANCE_SIGNED",
        run_id: report.run_id,
        report_digest: `sha256:${createHash("sha256").update(token).digest("hex")}`,
        verdict: report.verdict,
      });
      return { status: 200, body: { report: token, verdict: report.verdict } };
    } finally {
      this.run = null;
    }
  }

  private outcomeOf(sent: Sent | undefined): GovernedOutcome {
    const report = sent?.report ?? null;
    if (report !== null) {
      return {
        upstream_status: report.upstream_status,
        state: report.state,
        verdict: report.verdict,
        execution: report.execution,
        intent_id: report.intent_id,
        decision_id: report.decision_id,
        dossier_id: report.dossier_id,
        reason_codes: [...report.reason_codes],
      };
    }
    return {
      upstream_status: null,
      state: sent?.answered?.state ?? null,
      verdict: null,
      execution: sent?.answered?.execution ?? null,
      intent_id: sent?.intentId ?? null,
      decision_id: null,
      dossier_id: null,
      reason_codes: [],
    };
  }

  private permittedCase(run: OpenRun, write: PlanWrite): PermittedCase {
    const sent = run.sent.get(write.name);
    const outcome = this.outcomeOf(sent);
    const effect = sent?.report?.effect ?? null;
    const judged =
      sent === undefined ? { passed: false, failure: "NOT_SENT" } : judgePermitted(outcome, effect);
    return {
      name: write.name,
      method: write.method,
      path: write.path,
      action: this.host.route(write).action,
      observed_by: "GATEWAY",
      ...outcome,
      effect: effect === null ? null : { ...effect, reason_codes: [...effect.reason_codes] },
      lines: [...(sent?.lines ?? [])],
      ...judged,
    };
  }

  private prohibitedCase(run: OpenRun, write: ProhibitedWrite): ProhibitedCase {
    const sent = run.sent.get(write.name);
    const shadow = run.shadow.get(write.name) ?? null;
    const outcome = this.outcomeOf(sent);
    const observation = sent?.observation ?? null;
    return {
      name: write.name,
      method: write.method,
      path: write.path,
      action: this.host.route(write).action,
      canary: write.canary,
      observed_by: "GATEWAY",
      shadow: {
        verdict: shadow?.verdict ?? null,
        reason_codes: [...(shadow?.reason_codes ?? [])],
        decision_id: shadow?.decision_id ?? null,
        dossier_id: shadow?.dossier_id ?? null,
      },
      sent: sent !== undefined,
      ...outcome,
      observation,
      lines: [...(sent?.lines ?? [])],
      ...judgeProhibited({
        shadow: shadow?.verdict ?? null,
        sent: sent !== undefined,
        outcome,
        observation,
      }),
    };
  }

  private async outageCase(write: PlanWrite): Promise<OutageCase> {
    const base = {
      name: write.name,
      method: write.method,
      path: write.path,
      action: this.host.route(write).action,
      observed_by: "GATEWAY" as const,
    };
    if (this.host.failurePolicy === "FAIL_OPEN") {
      return {
        ...base,
        skipped: "FAIL_OPEN",
        status: null,
        execution: null,
        reason_codes: [],
        upstream_writes: 0,
        passed: true,
        failure: null,
      };
    }
    const outcome = await this.host.outage(write);
    return {
      ...base,
      skipped: null,
      status: outcome.status,
      execution: outcome.execution,
      reason_codes: [...outcome.reason_codes],
      upstream_writes: outcome.upstreamWrites,
      ...judgeOutage({
        status: outcome.status,
        execution: outcome.execution,
        upstreamWrites: outcome.upstreamWrites,
      }),
    };
  }
}
