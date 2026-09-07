import type { AuditRecorder } from "../audit/AuditRecorder.js";
import type {
  DecisionAuthority,
  DecisionVerdict,
  GateDecision,
} from "../decision/DecisionAuthority.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";

export type ShadowObservationStatus =
  "OBSERVED" | "UNAVAILABLE" | "TIMED_OUT" | "INVALID" | "ABORTED";

/**
 * Non-authoritative record of what the authority would have decided.
 *
 * The shape deliberately has no `authorization` or `failClosed` field, so it
 * is not structurally assignable to `GateDecision`, and it carries explicit
 * `mode: "SHADOW"` and `authority: "OBSERVATIONAL"` markers that
 * `SafeExecutor` rejects at runtime after any cast or JSON round trip.
 */
export interface ShadowObservation {
  readonly mode: "SHADOW";
  readonly authority: "OBSERVATIONAL";
  readonly status: ShadowObservationStatus;
  readonly intentHash: string;
  /** Policy verdict when the authority answered; `null` when it did not or failed closed. */
  readonly verdict: DecisionVerdict | null;
  readonly decisionId: string | null;
  readonly dossierId: string | null;
  readonly reasonCodes: readonly string[];
  /** `true` when the authority returned a grant that this pipeline discarded. */
  readonly grantDiscarded: boolean;
  readonly durationMs: number;
}

export type ShadowProductionOutcome<TResult> =
  | { readonly status: "COMPLETED"; readonly result: TResult }
  | { readonly status: "FAILED"; readonly error: unknown };

/** Production outcome available immediately; the observation settles on its own bound. */
export interface ShadowRun<TResult> {
  readonly mode: "SHADOW";
  readonly production: ShadowProductionOutcome<TResult>;
  readonly observation: Promise<ShadowObservation>;
}

export interface ShadowComparison<TResult> {
  readonly mode: "SHADOW";
  readonly production: ShadowProductionOutcome<TResult>;
  readonly observation: ShadowObservation;
}

export interface ShadowPipelineOptions {
  /** Optional recorder; every observation is emitted as an `OBSERVATIONAL` `SHADOW_EVALUATED` event. */
  readonly audit?: AuditRecorder;
  /** Independent bound on the hypothetical evaluation. Default 2000 ms, clamped to [1, 15000]. */
  readonly timeoutMs?: number;
  /** Injectable epoch-millisecond clock for deterministic duration tests. */
  readonly clock?: () => number;
}

export interface ShadowObserveOptions {
  /** Cancels the observation only; production execution is never cancelled by this pipeline. */
  readonly signal?: AbortSignal;
}

const DEFAULT_TIMEOUT_MS = 2_000;
const MAX_TIMEOUT_MS = 15_000;
const MAX_REASON_CODES = 50;
const MAX_IDENTIFIER_LENGTH = 200;
const VERDICTS = new Set<DecisionVerdict>(["ALLOW", "ESCALATE", "BLOCK"]);

type Classified = Pick<
  ShadowObservation,
  "status" | "verdict" | "decisionId" | "dossierId" | "reasonCodes" | "grantDiscarded"
>;

/**
 * Runs an existing production execution unchanged while asking an authority
 * what it would have decided. The observation is failure-isolated, bounded,
 * and never carries execution authority.
 */
export class ShadowPipeline {
  private readonly audit: AuditRecorder | undefined;
  private readonly timeoutMs: number;
  private readonly clock: () => number;

  public constructor(
    private readonly authority: DecisionAuthority,
    options: ShadowPipelineOptions = {},
  ) {
    if (authority.evaluationMode === "ENFORCEMENT") {
      throw new Error("SHADOW_AUTHORITY_MUST_BE_OBSERVATIONAL");
    }
    if (options.timeoutMs !== undefined && !Number.isFinite(options.timeoutMs)) {
      throw new Error("SHADOW_TIMEOUT_INVALID");
    }
    this.audit = options.audit;
    this.timeoutMs = Math.min(Math.max(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, 1), MAX_TIMEOUT_MS);
    this.clock = options.clock ?? Date.now;
  }

  /**
   * Invokes `existingExecution` exactly once and returns as soon as it settles.
   * Its result or thrown error is preserved verbatim. The observation promise
   * never rejects and never delays production.
   */
  public async observe<TResult>(
    captured: CapturedIntent,
    existingExecution: () => Promise<TResult> | TResult,
    options: ShadowObserveOptions = {},
  ): Promise<ShadowRun<TResult>> {
    const observation = this.evaluate(captured, options.signal);
    let production: ShadowProductionOutcome<TResult>;
    try {
      production = { status: "COMPLETED", result: await existingExecution() };
    } catch (error) {
      production = { status: "FAILED", error };
    }
    return Object.freeze({ mode: "SHADOW", production: Object.freeze(production), observation });
  }

  /** `observe`, then wait for the bounded observation so both sides can be compared inline. */
  public async compare<TResult>(
    captured: CapturedIntent,
    existingExecution: () => Promise<TResult> | TResult,
    options: ShadowObserveOptions = {},
  ): Promise<ShadowComparison<TResult>> {
    const run = await this.observe(captured, existingExecution, options);
    return Object.freeze({
      mode: "SHADOW",
      production: run.production,
      observation: await run.observation,
    });
  }

  private evaluate(captured: CapturedIntent, signal?: AbortSignal): Promise<ShadowObservation> {
    const startedAt = this.clock();
    const settled = new Promise<Classified>((resolve) => {
      let done = false;
      const finish = (classified: Classified): void => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        resolve(classified);
      };
      const onAbort = (): void => finish(ShadowPipeline.empty("ABORTED"));
      const timer = setTimeout(() => finish(ShadowPipeline.empty("TIMED_OUT")), this.timeoutMs);
      if (signal?.aborted === true) {
        onAbort();
        return;
      }
      signal?.addEventListener("abort", onAbort, { once: true });
      // Promise.resolve().then isolates a synchronously throwing authority.
      void Promise.resolve()
        .then(async () => await this.authority.evaluate(captured))
        .then(
          (decision) => finish(ShadowPipeline.classify(captured, decision)),
          () => finish(ShadowPipeline.empty("UNAVAILABLE")),
        );
    });
    return settled.then(async (classified) => {
      const observation: ShadowObservation = Object.freeze({
        mode: "SHADOW",
        authority: "OBSERVATIONAL",
        intentHash: captured.intentHash,
        ...classified,
        reasonCodes: Object.freeze([...classified.reasonCodes]),
        durationMs: Math.max(0, this.clock() - startedAt),
      });
      await this.record(captured, observation);
      return observation;
    });
  }

  private async record(captured: CapturedIntent, observation: ShadowObservation): Promise<void> {
    if (this.audit === undefined) return;
    await this.audit.record({
      eventType: "SHADOW_EVALUATED",
      authority: "OBSERVATIONAL",
      captured,
      ...(observation.verdict === null ? {} : { verdict: observation.verdict }),
      ...(observation.decisionId === null ? {} : { decisionId: observation.decisionId }),
      ...(observation.dossierId === null ? {} : { dossierId: observation.dossierId }),
      reasonCodes: [`SHADOW_${observation.status}`, ...observation.reasonCodes].slice(
        0,
        MAX_REASON_CODES,
      ),
      durationMs: observation.durationMs,
    });
  }

  private static empty(status: ShadowObservationStatus, reasonCodes: string[] = []): Classified {
    return {
      status,
      verdict: null,
      decisionId: null,
      dossierId: null,
      reasonCodes,
      grantDiscarded: false,
    };
  }

  /** Validates a decision from any authority; the grant, if any, is discarded and reported. */
  private static classify(captured: CapturedIntent, decision: GateDecision): Classified {
    const candidate = decision as Partial<GateDecision> | null | undefined;
    if (
      candidate === null ||
      typeof candidate !== "object" ||
      typeof candidate.verdict !== "string" ||
      !VERDICTS.has(candidate.verdict) ||
      !ShadowPipeline.isBoundedIdentifier(candidate.decisionId) ||
      !(candidate.dossierId === null || ShadowPipeline.isBoundedIdentifier(candidate.dossierId)) ||
      !Array.isArray(candidate.reasonCodes) ||
      candidate.reasonCodes.length > MAX_REASON_CODES ||
      !candidate.reasonCodes.every((code) => ShadowPipeline.isBoundedIdentifier(code))
    ) {
      return ShadowPipeline.empty("INVALID", ["SHADOW_DECISION_MALFORMED"]);
    }
    if (candidate.intentHash !== captured.intentHash) {
      return ShadowPipeline.empty("INVALID", ["SHADOW_BINDING_MISMATCH"]);
    }
    const grantDiscarded =
      candidate.authorization !== null && typeof candidate.authorization === "object";
    if (candidate.failClosed === true) {
      // The authority did not answer the policy question; report unavailability, not a verdict.
      return {
        status: "UNAVAILABLE",
        verdict: null,
        decisionId: candidate.decisionId,
        dossierId: candidate.dossierId,
        reasonCodes: [...candidate.reasonCodes],
        grantDiscarded,
      };
    }
    return {
      status: "OBSERVED",
      verdict: candidate.verdict,
      decisionId: candidate.decisionId,
      dossierId: candidate.dossierId,
      reasonCodes: [...candidate.reasonCodes],
      grantDiscarded,
    };
  }

  private static isBoundedIdentifier(value: unknown): value is string {
    if (typeof value !== "string" || value.length < 1 || value.length > MAX_IDENTIFIER_LENGTH) {
      return false;
    }
    for (let index = 0; index < value.length; index += 1) {
      const codeUnit = value.charCodeAt(index);
      if (codeUnit <= 0x1f || codeUnit === 0x7f) return false;
    }
    return true;
  }
}
