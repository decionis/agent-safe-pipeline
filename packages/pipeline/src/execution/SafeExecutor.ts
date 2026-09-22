import type { GateDecision } from "../decision/DecisionAuthority.js";
import type { AuditEventType, AuditRecorder } from "../audit/AuditRecorder.js";
import { CanonicalIntentHasher } from "../intent/CanonicalIntentHasher.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import { boundaryOf } from "../intent/ExecutionSignals.js";
import type { ActionRegistry } from "./ActionRegistry.js";
import type {
  AuthorizationVerifier,
  ExecutionCommitOutcome,
  ExecutionFinalization,
  VerifiedAuthorization,
} from "./AuthorizationVerifier.js";

export type ExecutionBlockReason =
  | "DECISION_NOT_AUTHORITATIVE"
  | "DECISION_NOT_ALLOW"
  | "INTENT_BINDING_MISMATCH"
  | "INTENT_CONFORMANCE_FAILED"
  | "AUTHORIZATION_MISSING"
  | "AUTHORIZATION_INVALID"
  | "RECOVERY_BINDING_MISMATCH"
  | "BOUNDARY_MISMATCH"
  | "AUDIT_UNAVAILABLE";

/**
 * What this executor is, beyond the registry and the verifier it was given.
 *
 * `boundaryId` names the enforcement boundary this process is. When it is
 * set, an intent is executable here only if it was captured here: an
 * authority issued through one boundary cannot be presented at another, and
 * an intent that names no boundary at all is not executable by a boundary
 * that expects to be named. Leaving it unset is the existing behaviour
 * exactly, which is what a deployment with one gateway wants.
 */
export interface SafeExecutorOptions {
  readonly boundaryId?: string;
}

export type ExecutionPreDispatchFailureReason =
  "HANDLER_FAILED_BEFORE_DISPATCH" | "AUDIT_UNAVAILABLE";

/**
 * What a caller presents back to reconcile an attempt whose outcome was
 * lost. The fields are listed rather than inherited, because this is a
 * versioned wire object: a field that appears on `VerifiedAuthorization`
 * later must be added here deliberately or not at all.
 */
export interface ExecutionRecoveryReference {
  readonly version: "agent-safe.recovery/1";
  readonly decisionId: string;
  readonly dossierId: string;
  readonly grantId: string;
  readonly intentHash: string;
  readonly expiresAt: string;
  readonly idempotencyKey: string;
}

export interface ExecutionBlockedResult {
  readonly outcome: "BLOCKED";
  readonly executed: false;
  readonly reason: ExecutionBlockReason;
  readonly result: null;
  readonly authorization: null;
}

/**
 * The provider refused, definitively, after the dispatch boundary. The grant
 * was consumed and the request was sent, and nothing was effected: the
 * outcome is a fact, not an unknown, so there is nothing to reconcile and no
 * recovery reference to present. A caller that wants the action after all
 * needs a fresh decision and a fresh grant, because the refusal was about
 * this attempt.
 */
export interface ProviderRefusedResult {
  readonly outcome: "DEFINITELY_NOT_EXECUTED";
  readonly executed: false;
  readonly recovered: false;
  /** The provider's own reason, as the handler reported it. */
  readonly reason: string;
  readonly result: null;
  readonly authorization: VerifiedAuthorization;
}

export interface ProviderOutcomeUnknownResult {
  readonly outcome: "UNKNOWN_AFTER_DISPATCH";
  readonly executed: null;
  readonly reason: "PROVIDER_OUTCOME_UNKNOWN";
  readonly result: null;
  readonly authorization: VerifiedAuthorization;
  readonly recovery: ExecutionRecoveryReference;
}

/**
 * Every outcome that consumed a grant reports whether the attempt's commit
 * evidence reached the authority. Finalization is evidence, not authority;
 * it never changes `outcome` or `executed`.
 */
export type SafeExecutionResult<TResult = unknown> =
  | {
      readonly outcome: "COMPLETED";
      readonly executed: true;
      readonly recovered: false;
      readonly result: TResult;
      readonly authorization: VerifiedAuthorization;
      readonly finalization: ExecutionFinalization;
    }
  | ExecutionBlockedResult
  | {
      readonly outcome: "FAILED_BEFORE_DISPATCH";
      readonly executed: false;
      readonly reason: ExecutionPreDispatchFailureReason;
      readonly result: null;
      readonly authorization: VerifiedAuthorization;
      readonly finalization: ExecutionFinalization;
    }
  | (ProviderRefusedResult & { readonly finalization: ExecutionFinalization })
  | (ProviderOutcomeUnknownResult & { readonly finalization: ExecutionFinalization });

export type ExecutionReconciliationResult<TResult = unknown> =
  | {
      readonly outcome: "COMPLETED";
      readonly executed: true;
      readonly recovered: true;
      readonly result: TResult;
      readonly authorization: VerifiedAuthorization;
    }
  | {
      readonly outcome: "DEFINITELY_NOT_EXECUTED";
      readonly executed: false;
      readonly recovered: true;
      readonly reason: "PROVIDER_CONFIRMED_NOT_EXECUTED";
      readonly result: null;
      readonly authorization: VerifiedAuthorization;
    }
  | ExecutionBlockedResult
  | ProviderOutcomeUnknownResult;

export class SafeExecutor {
  private readonly hasher = new CanonicalIntentHasher();

  private readonly boundaryId: string | null;

  public constructor(
    private readonly registry: ActionRegistry,
    private readonly verifier: AuthorizationVerifier,
    private readonly audit?: AuditRecorder,
    options?: SafeExecutorOptions,
  ) {
    this.boundaryId = options?.boundaryId ?? null;
  }

  public async run<TResult = unknown>(
    captured: CapturedIntent,
    decision: GateDecision,
  ): Promise<SafeExecutionResult<TResult>> {
    const startedAt = Date.now();
    // Stryker disable next-line all: Audit payload mapping is covered by lifecycle event assertions.
    const intentRecorded = await this.record({ eventType: "INTENT_CAPTURED", captured });
    // An observational artifact (shadow observation, serialized audit event) is
    // rejected before it is recorded or inspected as if it were a decision.
    if (!SafeExecutor.isAuthoritativeDecision(decision)) {
      return await this.block(captured, undefined, "DECISION_NOT_AUTHORITATIVE", startedAt);
    }
    // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
    const decisionRecorded = await this.record({
      eventType: decision.failClosed ? "AUTHORITY_FAILED_CLOSED" : "AUTHORITY_DECISION",
      captured,
      decision,
    });
    // Stryker restore all
    if (
      this.audit?.requiresDeliveryBeforeExecution === true &&
      (!intentRecorded || !decisionRecorded)
    ) {
      return await this.block(captured, decision, "AUDIT_UNAVAILABLE", startedAt);
    }
    if (decision.verdict !== "ALLOW" || decision.failClosed) {
      return await this.block(captured, decision, "DECISION_NOT_ALLOW", startedAt);
    }
    if (decision.intentHash !== captured.intentHash) {
      return await this.block(captured, decision, "INTENT_BINDING_MISMATCH", startedAt);
    }
    if (decision.authorization === null || typeof decision.authorization !== "object") {
      return await this.block(captured, decision, "AUTHORIZATION_MISSING", startedAt);
    }
    if (!this.intentConforms(captured)) {
      return await this.block(captured, decision, "INTENT_CONFORMANCE_FAILED", startedAt);
    }
    // Before the grant is consumed, not after: a boundary that refuses an
    // intent must leave the authority intact for the boundary that owns it.
    if (!this.boundaryMatches(captured)) {
      return await this.block(captured, decision, "BOUNDARY_MISMATCH", startedAt);
    }
    this.registry.validate(captured);
    let authorization: VerifiedAuthorization | null;
    try {
      authorization = await this.verifier.verifyAndConsume(captured, decision);
    } catch {
      return await this.block(captured, decision, "AUTHORIZATION_INVALID", startedAt);
    }
    if (authorization === null) {
      return await this.block(captured, decision, "AUTHORIZATION_INVALID", startedAt);
    }
    const authorizationExpiry = Date.parse(authorization.expiresAt);
    if (
      authorization.decisionId !== decision.decisionId ||
      authorization.dossierId !== decision.dossierId ||
      authorization.grantId.length === 0 ||
      authorization.intentHash !== captured.intentHash ||
      Math.floor(authorizationExpiry / 1_000) !==
        Math.floor(Date.parse(decision.authorization.expiresAt) / 1_000) ||
      authorizationExpiry <= Date.now() ||
      authorizationExpiry > Date.parse(captured.intent.expiresAt)
    ) {
      return await this.block(captured, decision, "AUTHORIZATION_INVALID", startedAt);
    }
    if (!this.intentConforms(captured)) {
      return await this.block(captured, decision, "INTENT_CONFORMANCE_FAILED", startedAt);
    }
    // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
    const grantRecorded = await this.record({
      eventType: "GRANT_CONSUMED",
      captured,
      decision,
      authorization,
      durationMs: Date.now() - startedAt,
    });
    // Stryker restore all
    if (this.audit?.requiresDeliveryBeforeExecution === true && !grantRecorded) {
      return await this.failedBeforeDispatch(
        captured,
        decision,
        authorization,
        "AUDIT_UNAVAILABLE",
        startedAt,
      );
    }
    // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
    const executionRecorded = await this.record({
      eventType: "EXECUTION_STARTED",
      captured,
      decision,
      authorization,
      durationMs: Date.now() - startedAt,
    });
    // Stryker restore all
    if (this.audit?.requiresDeliveryBeforeExecution === true && !executionRecorded) {
      return await this.failedBeforeDispatch(
        captured,
        decision,
        authorization,
        "AUDIT_UNAVAILABLE",
        startedAt,
      );
    }
    const attempt = await this.registry.executeTracked(captured, authorization);
    if (attempt.status === "FAILED_BEFORE_DISPATCH") {
      return await this.failedBeforeDispatch(
        captured,
        decision,
        authorization,
        "HANDLER_FAILED_BEFORE_DISPATCH",
        startedAt,
      );
    }
    if (attempt.status === "REFUSED_AFTER_DISPATCH") {
      // The provider said no. That is an outcome, so it is finalized `FAILED`
      // rather than left indeterminate, and `executed` is false rather than
      // null: nothing about it is unknown.
      const finalization = await this.finalize(
        captured,
        decision,
        authorization,
        "FAILED",
        attempt.receipt,
      );
      const result: SafeExecutionResult<TResult> = {
        outcome: "DEFINITELY_NOT_EXECUTED",
        executed: false,
        recovered: false,
        reason: attempt.reason,
        result: null,
        authorization,
        finalization,
      };
      // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
      await this.record({
        eventType: "EXECUTION_REFUSED_AFTER_DISPATCH",
        captured,
        decision,
        authorization,
        reasonCodes: [attempt.reason, SafeExecutor.finalizationCode(finalization)],
        durationMs: Date.now() - startedAt,
      });
      // Stryker restore all
      return result;
    }
    if (attempt.status === "UNKNOWN_AFTER_DISPATCH") {
      const finalization = await this.finalize(
        captured,
        decision,
        authorization,
        "INDETERMINATE",
        attempt.receipt,
      );
      const result: SafeExecutionResult<TResult> = {
        outcome: "UNKNOWN_AFTER_DISPATCH",
        executed: null,
        reason: "PROVIDER_OUTCOME_UNKNOWN",
        result: null,
        authorization,
        recovery: SafeExecutor.recoveryReference(captured, authorization),
        finalization,
      };
      // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
      await this.record({
        eventType: "EXECUTION_OUTCOME_UNKNOWN",
        captured,
        decision,
        authorization,
        reasonCodes: [result.reason, SafeExecutor.finalizationCode(finalization)],
        durationMs: Date.now() - startedAt,
      });
      // Stryker restore all
      return result;
    }
    const finalization = await this.finalize(
      captured,
      decision,
      authorization,
      "COMMITTED",
      attempt.receipt,
    );
    const result: SafeExecutionResult<TResult> = {
      outcome: "COMPLETED",
      executed: true,
      recovered: false,
      result: attempt.result as TResult,
      authorization,
      finalization,
    };
    // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
    await this.record({
      eventType: "EXECUTION_COMPLETED",
      captured,
      decision,
      authorization,
      reasonCodes: [SafeExecutor.finalizationCode(finalization)],
      durationMs: Date.now() - startedAt,
    });
    // Stryker restore all
    return result;
  }

  /**
   * Reports the attempt outcome to the verifier's authority, with the
   * provider's effect receipt when the attempt brought one back. A missing,
   * failing, or malformed finalization can never alter the execution result.
   */
  private async finalize(
    captured: CapturedIntent,
    decision: GateDecision,
    authorization: VerifiedAuthorization,
    outcome: ExecutionCommitOutcome,
    receipt: string | null = null,
  ): Promise<ExecutionFinalization> {
    const finalize = this.verifier.finalize;
    if (finalize === undefined) return "UNSUPPORTED";
    try {
      const status = await finalize.call(this.verifier, {
        captured,
        decision,
        authorization,
        outcome,
        ...(receipt === null ? {} : { effectReceipt: receipt }),
      });
      return status === "RECORDED" ? "RECORDED" : "PENDING";
    } catch {
      return "PENDING";
    }
  }

  private static finalizationCode(finalization: ExecutionFinalization): string {
    return `COMMIT_FINALIZATION_${finalization}`;
  }

  public async reconcile<TResult = unknown>(
    captured: CapturedIntent,
    recovery: ExecutionRecoveryReference,
  ): Promise<ExecutionReconciliationResult<TResult>> {
    const startedAt = Date.now();
    if (
      recovery.version !== "agent-safe.recovery/1" ||
      recovery.intentHash !== captured.intentHash ||
      recovery.idempotencyKey !== captured.intent.idempotencyKey ||
      !this.intentConforms(captured)
    ) {
      return await this.block(captured, undefined, "RECOVERY_BINDING_MISMATCH", startedAt);
    }

    const reconciliation = await this.registry.reconcile(captured, recovery.idempotencyKey);
    const authorization = SafeExecutor.authorizationFrom(recovery);
    if (reconciliation.status === "COMPLETED") {
      const result: ExecutionReconciliationResult<TResult> = {
        outcome: "COMPLETED",
        executed: true,
        recovered: true,
        result: reconciliation.result as TResult,
        authorization,
      };
      // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
      await this.record({
        eventType: "RECONCILIATION_COMPLETED",
        captured,
        authorization,
        durationMs: Date.now() - startedAt,
      });
      // Stryker restore all
      return result;
    }
    if (reconciliation.status === "NOT_EXECUTED") {
      const result: ExecutionReconciliationResult<TResult> = {
        outcome: "DEFINITELY_NOT_EXECUTED",
        executed: false,
        recovered: true,
        reason: "PROVIDER_CONFIRMED_NOT_EXECUTED",
        result: null,
        authorization,
      };
      // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
      await this.record({
        eventType: "RECONCILIATION_NOT_EXECUTED",
        captured,
        authorization,
        reasonCodes: [result.reason],
        durationMs: Date.now() - startedAt,
      });
      // Stryker restore all
      return result;
    }
    const result: ExecutionReconciliationResult<TResult> = {
      outcome: "UNKNOWN_AFTER_DISPATCH",
      executed: null,
      reason: "PROVIDER_OUTCOME_UNKNOWN",
      result: null,
      authorization,
      recovery,
    };
    // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
    await this.record({
      eventType: "RECONCILIATION_UNKNOWN",
      captured,
      authorization,
      reasonCodes: [result.reason],
      durationMs: Date.now() - startedAt,
    });
    // Stryker restore all
    return result;
  }

  /**
   * Observational artifacts carry an explicit non-authoritative marker. They
   * must never be interpreted as a `GateDecision`, even after an unsafe cast
   * or a JSON round trip.
   */
  private static isAuthoritativeDecision(decision: GateDecision): boolean {
    const candidate = decision as unknown as {
      readonly authority?: unknown;
      readonly mode?: unknown;
    };
    return candidate.authority !== "OBSERVATIONAL" && candidate.mode !== "SHADOW";
  }

  /**
   * Whether this boundary is the one the intent was captured through. The
   * boundary is read back out of the hashed context, so an intent whose
   * boundary was edited after capture fails conformance before it reaches
   * here, and one that never named a boundary cannot acquire one now.
   */
  private boundaryMatches(captured: CapturedIntent): boolean {
    if (this.boundaryId === null) return true;
    return boundaryOf(captured.intent.context)?.boundary_id === this.boundaryId;
  }

  private intentConforms(captured: CapturedIntent): boolean {
    let recomputed: CapturedIntent | null = null;
    try {
      recomputed = this.hasher.capture(captured.intent);
    } catch {
      // Malformed runtime objects are non-conformant.
    }
    return (
      recomputed !== null &&
      recomputed.intentHash === captured.intentHash &&
      recomputed.canonicalIntent === captured.canonicalIntent &&
      recomputed.byteLength === captured.byteLength
    );
  }

  private async block(
    captured: CapturedIntent,
    decision: GateDecision | undefined,
    reason: ExecutionBlockReason,
    startedAt: number,
  ): Promise<ExecutionBlockedResult> {
    // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
    await this.record({
      eventType: "EXECUTION_BLOCKED",
      captured,
      ...(decision === undefined ? {} : { decision }),
      reasonCodes: [reason],
      durationMs: Date.now() - startedAt,
    });
    // Stryker restore all
    return { outcome: "BLOCKED", executed: false, reason, result: null, authorization: null };
  }

  private async failedBeforeDispatch(
    captured: CapturedIntent,
    decision: GateDecision,
    authorization: VerifiedAuthorization,
    reason: ExecutionPreDispatchFailureReason,
    startedAt: number,
  ): Promise<Extract<SafeExecutionResult<never>, { outcome: "FAILED_BEFORE_DISPATCH" }>> {
    // The grant was consumed but no side effect was attempted.
    const finalization = await this.finalize(captured, decision, authorization, "FAILED");
    // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
    await this.record({
      eventType: "EXECUTION_FAILED_BEFORE_DISPATCH",
      captured,
      decision,
      authorization,
      reasonCodes: [reason, SafeExecutor.finalizationCode(finalization)],
      durationMs: Date.now() - startedAt,
    });
    // Stryker restore all
    return {
      outcome: "FAILED_BEFORE_DISPATCH",
      executed: false,
      reason,
      result: null,
      authorization,
      finalization,
    };
  }

  private async record(
    input: Parameters<AuditRecorder["record"]>[0] & { readonly eventType: AuditEventType },
  ): Promise<boolean> {
    // Stryker disable next-line BooleanLiteral: The value is irrelevant when no audit policy exists.
    return this.audit === undefined ? true : await this.audit.record(input);
  }

  private static recoveryReference(
    captured: CapturedIntent,
    authorization: VerifiedAuthorization,
  ): ExecutionRecoveryReference {
    // Named field by field rather than spread: `agent-safe.recovery/1` is a
    // wire object a caller presents back, so a field added to the
    // authorization must not appear here by accident. The claim lease in
    // particular has no business being here — it is the window this attempt
    // had, and it has certainly closed by the time anyone reconciles.
    return Object.freeze({
      version: "agent-safe.recovery/1",
      decisionId: authorization.decisionId,
      dossierId: authorization.dossierId,
      grantId: authorization.grantId,
      intentHash: authorization.intentHash,
      expiresAt: authorization.expiresAt,
      idempotencyKey: captured.intent.idempotencyKey,
    });
  }

  private static authorizationFrom(recovery: ExecutionRecoveryReference): VerifiedAuthorization {
    return Object.freeze({
      decisionId: recovery.decisionId,
      dossierId: recovery.dossierId,
      grantId: recovery.grantId,
      intentHash: recovery.intentHash,
      expiresAt: recovery.expiresAt,
    });
  }
}
