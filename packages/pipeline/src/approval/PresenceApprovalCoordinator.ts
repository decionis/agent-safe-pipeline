import type { GateResult, HumanApprovalGate } from "@decionis/presence-node";
import type {
  DecisionAuthority,
  GateDecision,
  HumanApprovalEvidence,
} from "../decision/DecisionAuthority.js";
import { FailClosedDecision } from "../decision/DecisionAuthority.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";

export type PresenceGateResult = GateResult;
export type PresenceApprovalClient = Pick<HumanApprovalGate, "gate" | "outcome">;

export interface PresenceApprovalCoordinatorOptions {
  /** Maximum number of outcome lookups after Presence returns HUMAN_REQUIRED. */
  readonly maxAttempts?: number;
  /** Initial exponential-backoff delay in milliseconds. */
  readonly initialDelayMs?: number;
  /** Maximum exponential-backoff delay in milliseconds. */
  readonly maxDelayMs?: number;
  /** Maximum wall-clock duration spent waiting for a terminal Presence outcome. */
  readonly deadlineMs?: number;
  /** Injectable epoch-millisecond clock for deterministic tests. */
  readonly clock?: () => number;
  /** Injectable abort-aware sleeper for deterministic tests. */
  readonly sleep?: (delayMs: number, signal?: AbortSignal) => Promise<void>;
  /** Injectable [0, 1] jitter source for deterministic tests. */
  readonly random?: () => number;
}

export interface PresenceResolutionOptions {
  readonly signal?: AbortSignal;
}

interface PollingConfiguration {
  readonly maxAttempts: number;
  readonly initialDelayMs: number;
  readonly maxDelayMs: number;
  readonly deadlineMs: number;
  readonly clock: () => number;
  readonly sleep: (delayMs: number, signal?: AbortSignal) => Promise<void>;
  readonly random: () => number;
}

type TerminalResolution =
  | { readonly result: PresenceGateResult; readonly reasonCode?: never }
  | { readonly result?: never; readonly reasonCode: string };

type BoundedResult<T> =
  | { readonly value: T; readonly reasonCode?: never }
  | { readonly value?: never; readonly reasonCode: string };

const DEFAULT_MAX_ATTEMPTS = 20;
const DEFAULT_INITIAL_DELAY_MS = 250;
const DEFAULT_MAX_DELAY_MS = 2_000;
const DEFAULT_DEADLINE_MS = 60_000;
const MAX_ATTEMPTS_LIMIT = 100;
const MAX_DELAY_LIMIT_MS = 60_000;
const MAX_DEADLINE_LIMIT_MS = 300_000;

/**
 * Coordinates a Presence human-approval flow and deliberately returns the
 * terminal receipt to Decionis for a fresh authorization decision.
 *
 * A Presence PROCEED result is evidence, not executable authority.
 */
export class PresenceApprovalCoordinator {
  private readonly polling: PollingConfiguration;

  public constructor(
    private readonly presence: PresenceApprovalClient,
    private readonly authority: DecisionAuthority,
    private readonly organization: string,
    private readonly approverId: string,
    options: PresenceApprovalCoordinatorOptions = {},
  ) {
    this.polling = PresenceApprovalCoordinator.pollingConfiguration(options);
  }

  public async request(captured: CapturedIntent): Promise<PresenceGateResult> {
    try {
      const result = await this.presence.gate(
        {
          action: {
            intent: captured.intent.action,
            target: captured.intent.target,
            surface: "agent_safe_pipeline",
          },
          agent: {
            id: captured.intent.actor.id,
            display: captured.intent.actor.id,
            role: captured.intent.actor.type,
          },
          approver: { id: this.approverId },
          organization: this.organization,
          presentation: {
            title: `Approve ${captured.intent.action}`,
            description: `Authorize this exact action against ${captured.intent.target}.`,
            displayFields: [
              { key: "action", label: "Action", value: captured.intent.action },
              { key: "target", label: "Target", value: captured.intent.target },
              { key: "intent_hash", label: "Intent hash", value: captured.intentHash },
            ],
          },
        },
        `presence:${captured.intent.idempotencyKey}`,
      );

      const verdict = this.verdictOf(result);
      if (verdict === null || (verdict === "HUMAN_REQUIRED" && this.requestIdOf(result) === null)) {
        throw new Error("Presence returned an invalid gate response");
      }

      return result;
    } catch {
      throw new Error("PRESENCE_REQUEST_FAILED");
    }
  }

  public async resolveAndReauthorize(
    captured: CapturedIntent,
    result: PresenceGateResult,
    options: PresenceResolutionOptions = {},
  ): Promise<GateDecision> {
    const initialBoundaryFailure = this.boundaryFailure(captured, options.signal);
    if (initialBoundaryFailure !== null) {
      return FailClosedDecision.create(captured.intentHash, initialBoundaryFailure);
    }

    const resolution = await this.terminalResult(captured, result, options.signal);
    if (resolution.reasonCode !== undefined) {
      return FailClosedDecision.create(captured.intentHash, resolution.reasonCode);
    }

    const verdict = this.verdictOf(resolution.result);
    if (verdict === null) {
      return FailClosedDecision.create(captured.intentHash, "PRESENCE_RESPONSE_INVALID");
    }

    if (verdict !== "PROCEED") {
      return FailClosedDecision.create(captured.intentHash, `PRESENCE_${verdict}`);
    }

    const evidence = this.evidenceOf(resolution.result);
    if (evidence === null) {
      return FailClosedDecision.create(captured.intentHash, "PRESENCE_PROOF_MISSING");
    }

    const preAuthorizationFailure = this.boundaryFailure(captured, options.signal);
    if (preAuthorizationFailure !== null) {
      return FailClosedDecision.create(captured.intentHash, preAuthorizationFailure);
    }

    const evaluation = await this.evaluateAuthority(captured, evidence, options.signal);
    if (evaluation.reasonCode !== undefined) {
      return FailClosedDecision.create(captured.intentHash, evaluation.reasonCode);
    }

    const postAuthorizationFailure = this.boundaryFailure(captured, options.signal);
    return postAuthorizationFailure === null
      ? evaluation.value
      : FailClosedDecision.create(captured.intentHash, postAuthorizationFailure);
  }

  private async terminalResult(
    captured: CapturedIntent,
    initialResult: PresenceGateResult,
    signal?: AbortSignal,
  ): Promise<TerminalResolution> {
    const initialVerdict = this.verdictOf(initialResult);
    if (initialVerdict === null) {
      return { reasonCode: "PRESENCE_RESPONSE_INVALID" };
    }

    if (initialVerdict !== "HUMAN_REQUIRED") {
      return { result: initialResult };
    }

    const requestId = this.requestIdOf(initialResult);
    if (requestId === null) {
      return { reasonCode: "PRESENCE_RESPONSE_INVALID" };
    }

    const startedAt = this.clockNow();
    const intentExpiresAt = Date.parse(captured.intent.expiresAt);
    if (startedAt === null || !Number.isFinite(intentExpiresAt)) {
      return { reasonCode: "PRESENCE_CLOCK_INVALID" };
    }
    const pollingDeadline = Math.min(startedAt + this.polling.deadlineMs, intentExpiresAt);
    const deadlineReason =
      intentExpiresAt <= startedAt + this.polling.deadlineMs
        ? "PRESENCE_INTENT_EXPIRED"
        : "PRESENCE_TIMEOUT";

    for (let attempt = 1; attempt <= this.polling.maxAttempts; attempt += 1) {
      const boundaryFailure = this.pollingBoundaryFailure(captured, pollingDeadline, signal);
      if (boundaryFailure !== null) {
        return { reasonCode: boundaryFailure };
      }

      const lookup = await this.lookupOutcome(requestId, pollingDeadline, deadlineReason, signal);
      if (lookup.reasonCode !== undefined) {
        return { reasonCode: lookup.reasonCode };
      }

      const verdict = this.verdictOf(lookup.value);
      if (verdict === null) {
        return { reasonCode: "PRESENCE_RESPONSE_INVALID" };
      }

      if (verdict !== "HUMAN_REQUIRED") {
        if (verdict === "PROCEED" && this.requestIdOf(lookup.value) !== requestId) {
          return { reasonCode: "PRESENCE_RESPONSE_INVALID" };
        }
        return { result: lookup.value };
      }

      if (this.requestIdOf(lookup.value) !== requestId) {
        return { reasonCode: "PRESENCE_RESPONSE_INVALID" };
      }

      if (attempt === this.polling.maxAttempts) {
        return { reasonCode: "PRESENCE_TIMEOUT" };
      }

      const delayMs = this.backoffDelay(attempt);
      if (delayMs === null) {
        return { reasonCode: "PRESENCE_POLLING_RANDOM_INVALID" };
      }

      const now = this.clockNow();
      if (now === null) {
        return { reasonCode: "PRESENCE_CLOCK_INVALID" };
      }
      const remainingMs = pollingDeadline - now;
      if (remainingMs <= 0) {
        const reasonCode = this.pollingBoundaryFailure(captured, pollingDeadline, signal);
        return { reasonCode: reasonCode ?? "PRESENCE_TIMEOUT" };
      }

      const backoff = await this.boundedOperation(
        async () => await this.polling.sleep(Math.min(delayMs, remainingMs), signal),
        remainingMs,
        deadlineReason,
        "PRESENCE_UNAVAILABLE",
        signal,
      );
      if (backoff.reasonCode !== undefined) {
        return { reasonCode: backoff.reasonCode };
      }
    }

    return { reasonCode: "PRESENCE_TIMEOUT" };
  }

  private async lookupOutcome(
    requestId: string,
    pollingDeadline: number,
    deadlineReason: "PRESENCE_INTENT_EXPIRED" | "PRESENCE_TIMEOUT",
    signal?: AbortSignal,
  ): Promise<BoundedResult<PresenceGateResult>> {
    const now = this.clockNow();
    if (now === null) return { reasonCode: "PRESENCE_CLOCK_INVALID" };
    return await this.boundedOperation(
      async () => await this.presence.outcome(requestId),
      pollingDeadline - now,
      deadlineReason,
      "PRESENCE_UNAVAILABLE",
      signal,
    );
  }

  private async evaluateAuthority(
    captured: CapturedIntent,
    evidence: HumanApprovalEvidence,
    signal?: AbortSignal,
  ): Promise<BoundedResult<GateDecision>> {
    const boundaryFailure = this.boundaryFailure(captured, signal);
    if (boundaryFailure !== null) {
      return { reasonCode: boundaryFailure };
    }

    const now = this.clockNow();
    if (now === null) return { reasonCode: "PRESENCE_CLOCK_INVALID" };
    return await this.boundedOperation(
      async () => await this.authority.evaluate(captured, { humanApproval: evidence }),
      Date.parse(captured.intent.expiresAt) - now,
      "PRESENCE_INTENT_EXPIRED",
      "AUTHORITY_UNAVAILABLE",
      signal,
    );
  }

  private async boundedOperation<T>(
    operation: () => Promise<T>,
    timeoutMs: number,
    timeoutReason: string,
    failureReason: string,
    signal?: AbortSignal,
  ): Promise<BoundedResult<T>> {
    if (signal?.aborted === true) return { reasonCode: "PRESENCE_ABORTED" };
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) return { reasonCode: timeoutReason };

    return await new Promise<BoundedResult<T>>((resolve) => {
      let settled = false;
      const settle = (value: BoundedResult<T>): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        resolve(value);
      };
      const onAbort = (): void => settle({ reasonCode: "PRESENCE_ABORTED" });
      const timer = setTimeout(() => settle({ reasonCode: timeoutReason }), timeoutMs);

      signal?.addEventListener("abort", onAbort, { once: true });
      void Promise.resolve()
        .then(operation)
        .then(
          (value) => settle({ value }),
          () => settle({ reasonCode: failureReason }),
        );
    });
  }

  private pollingBoundaryFailure(
    captured: CapturedIntent,
    pollingDeadline: number,
    signal?: AbortSignal,
  ): string | null {
    const generalFailure = this.boundaryFailure(captured, signal);
    if (generalFailure !== null) return generalFailure;
    const now = this.clockNow();
    if (now === null) return "PRESENCE_CLOCK_INVALID";
    return now >= pollingDeadline ? "PRESENCE_TIMEOUT" : null;
  }

  private boundaryFailure(captured: CapturedIntent, signal?: AbortSignal): string | null {
    if (signal?.aborted === true) return "PRESENCE_ABORTED";
    const now = this.clockNow();
    const intentExpiresAt = Date.parse(captured.intent.expiresAt);
    if (now === null || !Number.isFinite(intentExpiresAt)) return "PRESENCE_CLOCK_INVALID";
    return now >= intentExpiresAt ? "PRESENCE_INTENT_EXPIRED" : null;
  }

  private backoffDelay(attempt: number): number | null {
    let random: number;
    try {
      random = this.polling.random();
    } catch {
      return null;
    }
    if (!Number.isFinite(random) || random < 0 || random > 1) return null;

    const exponentialDelay = this.polling.initialDelayMs * 2 ** Math.min(attempt - 1, 30);
    const cappedDelay = Math.min(exponentialDelay, this.polling.maxDelayMs);
    return Math.max(1, Math.floor(cappedDelay * (0.5 + random * 0.5)));
  }

  private clockNow(): number | null {
    try {
      const now = this.polling.clock();
      return Number.isFinite(now) ? now : null;
    } catch {
      return null;
    }
  }

  private verdictOf(result: unknown): "PROCEED" | "HUMAN_REQUIRED" | "DENIED" | "ESCALATED" | null {
    if (!this.isRecord(result)) return null;
    const verdict = result["verdict"];
    return verdict === "PROCEED" ||
      verdict === "HUMAN_REQUIRED" ||
      verdict === "DENIED" ||
      verdict === "ESCALATED"
      ? verdict
      : null;
  }

  private requestIdOf(result: unknown): string | null {
    if (!this.isRecord(result)) return null;
    const requestId = result["request_id"];
    return this.boundedIdentifier(requestId) ? requestId : null;
  }

  private evidenceOf(result: unknown): HumanApprovalEvidence | null {
    if (!this.isRecord(result)) return null;
    const requestId = result["request_id"];
    const receiptDossierId = result["receipt_dossier_id"];
    if (!this.boundedIdentifier(requestId) || !this.boundedIdentifier(receiptDossierId))
      return null;
    return { provider: "presence", requestId, receiptDossierId };
  }

  private boundedIdentifier(value: unknown): value is string {
    return typeof value === "string" && value.length > 0 && value.length <= 200;
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
  }

  private static pollingConfiguration(
    options: PresenceApprovalCoordinatorOptions,
  ): PollingConfiguration {
    const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    const initialDelayMs = options.initialDelayMs ?? DEFAULT_INITIAL_DELAY_MS;
    const maxDelayMs = options.maxDelayMs ?? DEFAULT_MAX_DELAY_MS;
    const deadlineMs = options.deadlineMs ?? DEFAULT_DEADLINE_MS;

    if (
      !Number.isInteger(maxAttempts) ||
      maxAttempts < 1 ||
      maxAttempts > MAX_ATTEMPTS_LIMIT ||
      !Number.isInteger(initialDelayMs) ||
      initialDelayMs < 1 ||
      initialDelayMs > MAX_DELAY_LIMIT_MS ||
      !Number.isInteger(maxDelayMs) ||
      maxDelayMs < initialDelayMs ||
      maxDelayMs > MAX_DELAY_LIMIT_MS ||
      !Number.isInteger(deadlineMs) ||
      deadlineMs < 1 ||
      deadlineMs > MAX_DEADLINE_LIMIT_MS ||
      (options.clock !== undefined && typeof options.clock !== "function") ||
      (options.sleep !== undefined && typeof options.sleep !== "function") ||
      (options.random !== undefined && typeof options.random !== "function")
    ) {
      throw new Error("PRESENCE_POLLING_OPTIONS_INVALID");
    }

    return {
      maxAttempts,
      initialDelayMs,
      maxDelayMs,
      deadlineMs,
      clock: options.clock ?? Date.now,
      sleep: options.sleep ?? PresenceApprovalCoordinator.sleep,
      random: options.random ?? Math.random,
    };
  }

  private static async sleep(delayMs: number, signal?: AbortSignal): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      if (signal?.aborted === true) {
        reject(new Error("PRESENCE_ABORTED"));
        return;
      }

      const onAbort = (): void => {
        clearTimeout(timer);
        reject(new Error("PRESENCE_ABORTED"));
      };
      const timer = setTimeout(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      }, delayMs);
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }
}
