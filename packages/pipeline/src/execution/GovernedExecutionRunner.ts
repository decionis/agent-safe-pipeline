import type { AuditAuthority, AuditEventType, AuditRecorder } from "../audit/AuditRecorder.js";
import {
  FailClosedDecision,
  type DecisionAuthority,
  type DecisionEvidence,
  type DecisionGate,
} from "../decision/DecisionAuthority.js";
import { AuthorityPaths } from "../http/AuthorityPaths.js";
import { CanonicalIntentHasher } from "../intent/CanonicalIntentHasher.js";
import type { CapturedIntent, IntentActor, PolicyProjection } from "../intent/ExecutionIntent.js";
import { boundaryOf, workloadOf } from "../intent/ExecutionSignals.js";
import { IntentCapture } from "../intent/IntentCapture.js";
import { TargetPreconditionSchema, type TargetPrecondition } from "../intent/TargetPrecondition.js";
import type { JsonObject, JsonValue } from "../intent/JsonValue.js";
import { PreDispatchRefusal, ProviderRefusal, type ProviderDispatch } from "./ActionRegistry.js";
import type {
  AuthorityEffectEvidence,
  AuthorizationVerifier,
  ExecutionCommitOutcome,
  ExecutionFinalization,
  VerifiedAuthorization,
} from "./AuthorizationVerifier.js";
import { dispatchBudgetMs, MonotonicDeadline } from "./ExecutionDeadline.js";
import { JournalError, type ExecutionJournal, type JournalRecord } from "./ExecutionJournal.js";
import type {
  DispatchedAttempts,
  ExecutionBlockedResult,
  ExecutionBlockReason,
  ExecutionHeldResult,
  ExecutionOutcome,
  ExecutionPreDispatchFailureReason,
  ExecutionReconciliationResult,
  ExecutionRecoveryReference,
  ExecutionSettlement,
  FailedBeforeDispatchResult,
  HeldClaimResult,
  HeldExecution,
  PermitHeldResult,
  PermitPresentationResult,
  SafeExecutionResult,
} from "./ExecutionOutcome.js";
import {
  STRICT_POSTURE,
  unavailableDisposition,
  type ExecutionPosture,
  type UnavailableDisposition,
} from "./ExecutionPosture.js";
import {
  EXECUTOR_EVIDENCE_VERSION,
  evidenceScope,
  type EvidenceStage,
  type ExecutorEvidenceLine,
  type ExecutorEvidenceSink,
} from "./ExecutorEvidence.js";
import {
  NATIVE_EXECUTOR_CONTRACT,
  type EffectObservation,
  type ExecutionPermit,
  type ExecutorScope,
  type NativeExecutor,
  type PreparedAction,
} from "./NativeExecutor.js";

/** Any native executor, as the runner holds it: it never reads the action or the receipt itself. */
type AnyExecutor = NativeExecutor<unknown, unknown, unknown>;

export interface GovernedExecutionRunnerOptions {
  /** Claims, finalization and reconciliation reports: the authority, through its verifier. */
  readonly verifier: AuthorizationVerifier;
  readonly audit?: AuditRecorder | undefined;
  /** Who decides, for `submit`; a run handed a decision never asks it. */
  readonly authority?: DecisionAuthority;
  /** How `submit` captures intents; a fresh `IntentCapture` by default. */
  readonly capture?: IntentCapture;
  /** Durable claims and single-use idempotency keys. Absent, the runner journals nothing. */
  readonly journal?: ExecutionJournal;
  /** Where `agent-safe.executor-evidence/1` lines go. */
  readonly evidence?: ExecutorEvidenceSink;
  /** What a surface does when the authority cannot be reached; strict by default. */
  readonly posture?: ExecutionPosture;
  /**
   * The enforcement boundary this process is. When it is set, an intent is
   * executable here only if it was captured here.
   */
  readonly boundaryId?: string;
  /** The digest of the workload this process runs as; an intent another artifact proposed is refused. */
  readonly workloadDigest?: string;
  /**
   * This process's own record of the attempts it dispatched, which a
   * recovery reference is held against. Defaults to the journal, when there
   * is one.
   */
  readonly attempts?: DispatchedAttempts;
  /** The configured dispatch timeout; the deadline is the smallest of this, the grant and the lease. */
  readonly timeoutMs?: number;
  /**
   * Refuse a dispatch whose window has already closed, before the executor is
   * called. On by default. The `SafeExecutor` facade turns it off because its
   * handlers bound their own dispatch, exactly as they did before the runner.
   */
  readonly enforceDispatchWindow?: boolean;
  /**
   * Report a proven reconciliation to the authority through the verifier.
   * On by default; the `SafeExecutor` facade turns it off so that a facade
   * caller sees exactly the authority traffic it saw before.
   */
  readonly reportReconciliations?: boolean;
  readonly clock?: () => number;
}

/** A run handed an existing decision. */
export interface RunRequest<TAction> {
  readonly captured: CapturedIntent;
  readonly decision: DecisionGate;
  readonly action: TAction;
  readonly scope?: ExecutorScope | null;
}

/** A run from the action alone: prepare, capture, decide, then run or hold. */
export interface SubmitRequest<TAction> {
  readonly action: TAction;
  readonly scope: ExecutorScope;
  /** Who is acting; never the agent's own claim about itself. */
  readonly actor: IntentActor;
  readonly evidence?: DecisionEvidence;
  readonly correlationId?: string;
}

export interface ReconcileRequest<TAction> {
  readonly captured: CapturedIntent;
  readonly recovery: ExecutionRecoveryReference;
  readonly action: TAction;
  readonly scope?: ExecutorScope | null;
}

export type GovernedRunResult<TResult = unknown> =
  SafeExecutionResult<TResult> | ExecutionHeldResult | PermitHeldResult;

export interface SubmitResult<TResult = unknown> {
  readonly captured: CapturedIntent;
  readonly decision: DecisionGate;
  readonly result: GovernedRunResult<TResult>;
}

/** A settlement input: the outcome a caller observed, or the native receipt for the executor to read. */
export type SettlementInput<TReceipt> =
  | { readonly outcome: ExecutionCommitOutcome; readonly signedReceipt?: string | null }
  | { readonly receipt: TReceipt; readonly signedReceipt?: string | null };

/** A decision that passed every check before consumption, so its grant is present. */
type AdmittedDecision = DecisionGate & {
  readonly authorization: NonNullable<DecisionGate["authorization"]>;
};

/** What the runner remembers about one execution between its steps. */
interface ExecutionContext {
  readonly executor: AnyExecutor;
  readonly action: unknown;
  readonly scope: ExecutorScope | null;
  readonly prepared: PreparedAction;
}

interface HeldState extends ExecutionContext {
  readonly decision: AdmittedDecision;
}

/** A claim adopted from another process has not been prepared here; it is prepared when a receipt needs it. */
interface ClaimState extends Omit<ExecutionContext, "prepared"> {
  readonly prepared: PreparedAction | null;
  readonly authorization: VerifiedAuthorization;
}

/** What admission hands the rest of a run: the executor's preparation and the dossier it was decided under. */
interface Admission {
  readonly prepared: PreparedAction;
  readonly dossierId: string;
}

/** Every result a step can end in, as the journal and the evidence line summarize it. */
type Concluded = SafeExecutionResult<unknown> | Exclude<HeldClaimResult, { outcome: "CLAIMED" }>;

interface StepSummary {
  readonly outcome: ExecutionOutcome | "CLAIMED";
  readonly executed: boolean | null;
  readonly reason: string | null;
  readonly code: string | null;
  readonly grantId: string | null;
  readonly governed: boolean;
  readonly finalization: ExecutionFinalization | null;
}

/** A write that never left the process, and why, when the executor said. */
class NotDispatched {
  public constructor(public readonly code: string | undefined) {}
}

/** The verdicts that admit an execution: ALLOW, and Commerce's PROCEED, which means the same. */
const ADMITTED_VERDICTS: ReadonlySet<string> = new Set(["ALLOW", "PROCEED"]);

const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * The one implementation of everything around a native write. Every executor,
 * on every platform, runs through it, and none of them does any of this
 * itself:
 *
 * - **admission**: an authoritative ALLOW (or PROCEED) only, never after a
 *   fail-closed gate, only with a dossier, only for the intent that was
 *   decided, at the boundary and by the workload that captured it, and only
 *   through a capability the connection has;
 * - **authority calls**, through the `DecisionAuthority` and
 *   `AuthorizationVerifier` seams: the decision, one single-use claim, the
 *   receipt (finalization), and the reconciliation;
 * - **execution control**: the dispatch deadline, the journal's durable claim
 *   and single-use idempotency key, and reconciliation after an outcome
 *   nobody knows;
 * - **failure posture** when the authority cannot be reached;
 * - **evidence**: the audit trail and the `agent-safe.executor-evidence/1`
 *   line, and the six outcomes every run ends in.
 *
 * Dispatch-style executors write inside the dispatch the runner opens. A
 * permit-style executor's grant is held at admission; the native boundary
 * presents the permit, which claims the grant once, and a later receipt
 * settles it.
 */
export class GovernedExecutionRunner {
  private readonly hasher = new CanonicalIntentHasher();
  private readonly verifier: AuthorizationVerifier;
  private readonly audit: AuditRecorder | undefined;
  private readonly authority: DecisionAuthority | undefined;
  private readonly capture: IntentCapture;
  private readonly journal: ExecutionJournal | null;
  private readonly evidence: ExecutorEvidenceSink | null;
  private readonly posture: ExecutionPosture;
  private readonly boundaryId: string | null;
  private readonly workloadDigest: string | null;
  private readonly attempts: DispatchedAttempts | null;
  private readonly timeoutMs: number;
  private readonly enforceDispatchWindow: boolean;
  private readonly reportReconciliations: boolean;
  private readonly clock: () => number;
  /** The holds this runner issued and nobody has claimed, keyed by the frozen handle. */
  private readonly holds = new WeakMap<HeldExecution, HeldState>();
  /** The holds claimed and not yet settled, with the authorization each one consumed. */
  private readonly claims = new WeakMap<HeldExecution, ClaimState>();
  /** The holds already settled, so a second receipt is told so rather than "never presented". */
  private readonly settled = new WeakSet<HeldExecution>();

  public constructor(options: GovernedExecutionRunnerOptions) {
    this.verifier = options.verifier;
    this.audit = options.audit;
    this.authority = options.authority;
    this.capture = options.capture ?? new IntentCapture();
    this.journal = options.journal ?? null;
    this.evidence = options.evidence ?? null;
    this.posture = options.posture ?? STRICT_POSTURE;
    this.boundaryId = options.boundaryId ?? null;
    this.workloadDigest = options.workloadDigest ?? null;
    this.attempts = options.attempts ?? GovernedExecutionRunner.journalAttempts(this.journal);
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.enforceDispatchWindow = options.enforceDispatchWindow ?? true;
    this.reportReconciliations = options.reportReconciliations ?? true;
    this.clock = options.clock ?? Date.now;
  }

  /**
   * The whole path from an action: the executor prepares it, the runner
   * captures the intent and asks the authority, then runs it (dispatch) or
   * holds it for the boundary (permit). An authority that throws is a
   * fail-closed decision, never an authorization.
   */
  public async submit<TAction, TResult = unknown>(
    executor: NativeExecutor<TAction, unknown, TResult>,
    request: SubmitRequest<TAction>,
  ): Promise<SubmitResult<TResult>> {
    if (this.authority === undefined) throw new Error("RUNNER_AUTHORITY_MISSING");
    const prepared = await executor.prepare(request.action, request.scope);
    const precondition = await GovernedExecutionRunner.readState(executor, request, prepared);
    const captured = this.capture.capture(prepared.proposal, {
      tenantId: request.scope.orgId,
      actor: request.actor,
      downstreamTarget: prepared.downstreamTarget,
      context: prepared.facts,
      idempotencyKey: prepared.idempotencyKey,
      ...(prepared.expectedEffectDigest === null
        ? {}
        : { expectedEffectDigest: prepared.expectedEffectDigest }),
      ...(prepared.policyProjection === undefined
        ? {}
        : { policyProjection: prepared.policyProjection }),
      ...(precondition === null ? {} : { precondition }),
      // Stryker disable next-line ConditionalExpression: the capture drops an undefined correlation itself; the condition only satisfies the strict optional type.
      ...(request.correlationId === undefined ? {} : { correlationId: request.correlationId }),
    });
    let decision: DecisionGate;
    try {
      decision = await this.authority.evaluate(captured, request.evidence);
    } catch {
      decision = FailClosedDecision.create(captured.intentHash, "AUTHORITY_UNAVAILABLE");
    }
    const result = await this.run(executor, {
      captured,
      decision,
      action: request.action,
      scope: request.scope,
    });
    return { captured, decision, result };
  }

  /**
   * The executor's read of the target's state version, when it makes one.
   * A read that throws, or answers anything but a precondition or null, is
   * refused here with one stable code, before anything is decided: an intent
   * captured without the version the executor said it would bind would carry
   * a grant no provider could hold to the state it was decided on.
   */
  private static async readState<TAction>(
    executor: NativeExecutor<TAction, unknown, unknown>,
    request: SubmitRequest<TAction>,
    prepared: PreparedAction,
  ): Promise<TargetPrecondition | null> {
    if (executor.readState === undefined) return null;
    let read: unknown;
    try {
      read = await executor.readState(request.action, prepared, request.scope);
    } catch {
      // A read that throws states nothing, and is refused below with any
      // other answer that is not a precondition: its error never leaves.
    }
    if (read === null) return null;
    const parsed = TargetPreconditionSchema.safeParse(read);
    if (!parsed.success) throw new Error("TARGET_STATE_UNREADABLE");
    return parsed.data;
  }

  /**
   * Runs a decided intent. A dispatch-style executor writes once, inside the
   * dispatch; a permit-style executor's grant is held instead, as `hold`
   * would, because the boundary performs its write.
   */
  public async run<TAction, TResult = unknown>(
    executor: NativeExecutor<TAction, unknown, TResult>,
    request: RunRequest<TAction>,
  ): Promise<GovernedRunResult<TResult>> {
    if (executor.style === "permit") return await this.hold(executor, request);
    return await this.dispatch(executor, request);
  }

  /** Runs a decided intent through a dispatch-style write, whatever the executor's style says. */
  public async dispatch<TAction, TResult = unknown>(
    executor: NativeExecutor<TAction, unknown, TResult>,
    request: RunRequest<TAction>,
  ): Promise<SafeExecutionResult<TResult>> {
    const startedAt = this.clock();
    const { captured, decision } = request;
    const scope = request.scope ?? null;
    const admitted = await this.admit(executor, request, startedAt, "RUN");
    if ("outcome" in admitted) return admitted;
    const context: ExecutionContext = {
      executor,
      action: request.action,
      scope,
      prepared: admitted.prepared,
    };
    const opened = await this.openAttempt(executor, request, admitted, startedAt);
    if (opened !== null) return opened;
    const claim = await this.consume(context, captured, decision as AdmittedDecision, startedAt);
    if (claim.outcome !== "CLAIMED") {
      await this.close(captured, claim);
      await this.emit(executor, context, "RUN", captured, decision, claim, startedAt);
      return claim;
    }
    const authorization = claim.authorization;
    const deadline = MonotonicDeadline.after(dispatchBudgetMs(this.timeoutMs, authorization));
    if (this.enforceDispatchWindow && deadline.budgetMs === 0) {
      const failed = await this.failedBeforeDispatch(
        captured,
        decision,
        authorization,
        "HANDLER_FAILED_BEFORE_DISPATCH",
        startedAt,
        "DISPATCH_WINDOW_CLOSED",
      );
      await this.close(captured, failed);
      await this.emit(executor, context, "RUN", captured, decision, failed, startedAt);
      return failed;
    }
    const observed = await this.write(executor, context, captured, authorization, deadline);
    const result =
      observed instanceof NotDispatched
        ? await this.failedBeforeDispatch(
            captured,
            decision,
            authorization,
            "HANDLER_FAILED_BEFORE_DISPATCH",
            startedAt,
            observed.code,
          )
        : await this.concluded<TResult>(
            captured,
            decision,
            authorization,
            observed as EffectObservation<TResult>,
            startedAt,
          );
    await this.close(captured, result);
    await this.emit(executor, context, "RUN", captured, decision, result, startedAt);
    return result;
  }

  /**
   * Admits a decision exactly as a run would and holds its grant instead of
   * consuming it. The intent, the decision and the hold are recorded; the
   * grant stays unclaimed until the boundary presents it, and an unclaimed
   * hold simply expires with its grant. A permit-style executor's hold
   * carries the permit the boundary presents.
   */
  public async hold<TAction, TResult = unknown>(
    executor: NativeExecutor<TAction, unknown, TResult>,
    request: RunRequest<TAction>,
  ): Promise<ExecutionHeldResult | PermitHeldResult | ExecutionBlockedResult> {
    return await this.holdWith(executor, request, []);
  }

  /**
   * Admits a hold this runner did not make: one another replica made, or
   * this process made before a restart, read back from a store the replicas
   * share. Every check a hold makes is made again on the way in, and the
   * record says the hold was adopted. Adoption adds no authority: the grant
   * is still the authority's to hand out once, so a hold claimed elsewhere is
   * refused at the claim by the authority, never admitted twice here.
   */
  public async adoptHold<TAction, TResult = unknown>(
    executor: NativeExecutor<TAction, unknown, TResult>,
    request: RunRequest<TAction>,
  ): Promise<ExecutionHeldResult | PermitHeldResult | ExecutionBlockedResult> {
    return await this.holdWith(executor, request, ["HOLD_ADOPTED"]);
  }

  /**
   * Registers a claim this runner did not make, so that `settle` can finalize
   * it here: the hold's intent and decision, and the authorization the claim
   * returned, as the store that shared them kept them. Nothing is consumed
   * and nothing is checked against the authority.
   */
  public adoptClaim<TAction>(
    executor: NativeExecutor<TAction, unknown, unknown>,
    request: RunRequest<TAction>,
    authorization: VerifiedAuthorization,
    material: JsonObject | null = null,
  ): HeldExecution {
    const { captured, decision } = request;
    if (
      !GovernedExecutionRunner.isAuthoritativeDecision(decision) ||
      decision.intentHash !== captured.intentHash ||
      authorization.intentHash !== captured.intentHash
    ) {
      throw new Error("CLAIM_ADOPTION_MISMATCH");
    }
    if (material !== null) {
      const adopt = this.verifier.adoptClaim;
      if (adopt === undefined || !adopt.call(this.verifier, authorization, material)) {
        throw new Error("CLAIM_MATERIAL_REFUSED");
      }
    }
    const held: HeldExecution = Object.freeze({
      captured,
      decision,
      expiresAt: authorization.expiresAt,
    });
    this.claims.set(held, {
      executor: executor as AnyExecutor,
      action: request.action,
      scope: request.scope ?? null,
      prepared: null,
      authorization,
    });
    return held;
  }

  /**
   * What another process needs to finalize a claim this runner's verifier
   * made, for a store the replicas share to keep sealed; null when the
   * verifier keeps its claims to itself or did not make this one.
   */
  public claimMaterial(authorization: VerifiedAuthorization): JsonObject | null {
    const material = this.verifier.claimMaterial;
    return material === undefined ? null : material.call(this.verifier, authorization);
  }

  /**
   * The boundary presents a held permit: the grant is claimed, once. The
   * handle is forgotten before the verifier is asked, so a second
   * presentation of the same hold, concurrent or later, is refused here
   * without reaching the authority; a handle this runner did not issue is
   * refused the same way. A permit-style executor then issues the claimed
   * permit the boundary writes with.
   */
  public async present(held: HeldExecution): Promise<PermitPresentationResult | HeldClaimResult> {
    const startedAt = this.clock();
    const state = this.holds.get(held);
    if (state === undefined) {
      return await this.block(held.captured, held.decision, "AUTHORIZATION_INVALID", startedAt);
    }
    this.holds.delete(held);
    const claim = await this.consume(state, held.captured, state.decision, startedAt);
    if (claim.outcome !== "CLAIMED") {
      await this.close(held.captured, claim);
      await this.emit(
        state.executor,
        state,
        "PRESENTATION",
        held.captured,
        held.decision,
        claim,
        startedAt,
      );
      return claim;
    }
    if (state.executor.style !== "permit") {
      this.claims.set(held, { ...state, authorization: claim.authorization });
      await this.emit(
        state.executor,
        state,
        "PRESENTATION",
        held.captured,
        held.decision,
        claim,
        startedAt,
      );
      return claim;
    }
    const permit = await this.issuePermit(state, held, claim.authorization);
    if (permit === null) {
      const failed = await this.failedBeforeDispatch(
        held.captured,
        held.decision,
        claim.authorization,
        "HANDLER_FAILED_BEFORE_DISPATCH",
        startedAt,
        "PERMIT_NOT_ISSUED",
      );
      await this.close(held.captured, failed);
      await this.emit(
        state.executor,
        state,
        "PRESENTATION",
        held.captured,
        held.decision,
        failed,
        startedAt,
      );
      return failed;
    }
    this.claims.set(held, { ...state, authorization: claim.authorization });
    const presented = { outcome: "CLAIMED" as const, authorization: claim.authorization, permit };
    await this.emit(
      state.executor,
      state,
      "PRESENTATION",
      held.captured,
      held.decision,
      presented,
      startedAt,
    );
    return presented;
  }

  /**
   * Settles a presented execution, once, from what the boundary reported:
   * the outcome it observed, or its native receipt for the executor to read.
   * `COMMITTED` when the effect happened, `FAILED` when it definitively did
   * not, `INDETERMINATE` when nobody can say. A second receipt is refused and
   * changes nothing that was recorded.
   */
  public async settle<TReceipt = unknown, TResult = unknown>(
    held: HeldExecution,
    input: SettlementInput<TReceipt>,
  ): Promise<ExecutionSettlement<TResult>> {
    const startedAt = this.clock();
    const state = this.claims.get(held);
    if (state === undefined) {
      return {
        status: "REFUSED",
        reason: this.settled.has(held) ? "RECEIPT_DUPLICATE" : "PERMIT_NOT_PRESENTED",
      };
    }
    this.claims.delete(held);
    this.settled.add(held);
    const observation =
      "outcome" in input
        ? GovernedExecutionRunner.observationOf<TResult>(input.outcome, input.signedReceipt ?? null)
        : await this.observeReceipt<TResult>(state, input.receipt, input.signedReceipt ?? null);
    const finalization = await this.finalize(
      held.captured,
      held.decision,
      state.authorization,
      observation.status,
      observation.signedReceipt ?? null,
      observation.evidence,
    );
    const eventType = GovernedExecutionRunner.settledEvent(observation.status);
    // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
    await this.record({
      eventType,
      captured: held.captured,
      decision: held.decision,
      authorization: state.authorization,
      reasonCodes: [GovernedExecutionRunner.finalizationCode(finalization)],
      durationMs: this.clock() - startedAt,
    });
    // Stryker restore all
    const outcome = GovernedExecutionRunner.outcomeOf(observation.status);
    const settlement: ExecutionSettlement<TResult> = {
      status: "SETTLED",
      outcome,
      executed:
        observation.status === "COMMITTED" ? true : observation.status === "FAILED" ? false : null,
      result: observation.status === "COMMITTED" ? observation.result : null,
      reason:
        observation.status === "FAILED"
          ? (observation.reason ?? "PROVIDER_REFUSED")
          : observation.status === "INDETERMINATE"
            ? "PROVIDER_OUTCOME_UNKNOWN"
            : null,
      authorization: state.authorization,
      finalization,
      ...(observation.status === "INDETERMINATE"
        ? {
            recovery: GovernedExecutionRunner.recoveryReference(held.captured, state.authorization),
          }
        : {}),
    };
    await this.appendQuietly({
      record: "ATTEMPT_CLOSED",
      at: new Date(this.clock()).toISOString(),
      intent_id: held.captured.intent.intentId,
      intent_hash: held.captured.intentHash,
      outcome,
      executed: settlement.executed,
      finalization,
    });
    await this.emitLine(state.executor, state, {
      stage: "SETTLEMENT",
      captured: held.captured,
      decision: held.decision,
      outcome,
      executed: settlement.executed,
      reason: settlement.reason,
      code: null,
      grantId: state.authorization.grantId,
      governed: true,
      disposition: null,
      finalization,
      startedAt,
    });
    return settlement;
  }

  /**
   * Resolves an attempt whose outcome was lost. The recovery reference is
   * the caller's claim until this runner's own record confirms it; the
   * executor is asked read-only, and nothing is ever dispatched again. A
   * proven answer is reported to the authority as evidence.
   */
  public async reconcile<TAction, TResult = unknown>(
    executor: NativeExecutor<TAction, unknown, TResult>,
    request: ReconcileRequest<TAction>,
  ): Promise<ExecutionReconciliationResult<TResult>> {
    const startedAt = this.clock();
    const { captured, recovery } = request;
    const scope = request.scope ?? null;
    if (
      recovery.version !== "agent-safe.recovery/1" ||
      recovery.intentHash !== captured.intentHash ||
      recovery.idempotencyKey !== captured.intent.idempotencyKey ||
      !this.intentConforms(captured)
    ) {
      return await this.block(captured, undefined, "RECOVERY_BINDING_MISMATCH", startedAt);
    }
    // The decision and grant are the caller's claim until the runner's own
    // record confirms them; the platform is not asked about a binding that
    // was never dispatched here.
    let authority: AuditAuthority = "NON_AUTHORITATIVE";
    if (this.attempts !== null) {
      const recorded = await this.attempts.authorizationsOf(captured);
      if (recorded.length === 0) {
        return await this.block(captured, undefined, "RECOVERY_ATTEMPT_UNKNOWN", startedAt);
      }
      if (!recorded.some((candidate) => GovernedExecutionRunner.sameBinding(candidate, recovery))) {
        return await this.block(captured, undefined, "RECOVERY_BINDING_MISMATCH", startedAt);
      }
      authority = "AUTHORITATIVE";
    }
    const authorization = GovernedExecutionRunner.authorizationFrom(recovery);
    const prepared = await executor.prepare(request.action, scope);
    const reconciliation = await executor.reconcile({
      intent: captured,
      prepared,
      idempotencyKey: recovery.idempotencyKey,
      scope,
      providerReference: null,
    });
    const context: ExecutionContext = { executor, action: request.action, scope, prepared };
    if (reconciliation.status === "COMPLETED") {
      const result: ExecutionReconciliationResult<TResult> = {
        outcome: "COMPLETED",
        executed: true,
        recovered: true,
        result: reconciliation.result,
        authorization,
      };
      // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
      await this.record({
        eventType: "RECONCILIATION_COMPLETED",
        captured,
        authorization,
        authority,
        durationMs: this.clock() - startedAt,
      });
      // Stryker restore all
      await this.reconciled(
        context,
        captured,
        authorization,
        result,
        "COMMITTED",
        reconciliation.evidence,
        startedAt,
      );
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
        authority,
        reasonCodes: [result.reason],
        durationMs: this.clock() - startedAt,
      });
      // Stryker restore all
      await this.reconciled(
        context,
        captured,
        authorization,
        result,
        "FAILED",
        reconciliation.evidence,
        startedAt,
      );
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
      authority,
      reasonCodes: [result.reason],
      durationMs: this.clock() - startedAt,
    });
    // Stryker restore all
    await this.reconciled(context, captured, authorization, result, null, undefined, startedAt);
    return result;
  }

  private async holdWith<TAction, TResult>(
    executor: NativeExecutor<TAction, unknown, TResult>,
    request: RunRequest<TAction>,
    reasonCodes: readonly string[],
  ): Promise<ExecutionHeldResult | PermitHeldResult | ExecutionBlockedResult> {
    const startedAt = this.clock();
    const { captured, decision } = request;
    const admittedRun = await this.admit(executor, request, startedAt, "RUN");
    if ("outcome" in admittedRun) return admittedRun;
    const admitted = decision as AdmittedDecision;
    const context: ExecutionContext = {
      executor,
      action: request.action,
      scope: request.scope ?? null,
      prepared: admittedRun.prepared,
    };
    // The attempt is open before the hold is recorded, so a journal that
    // refuses it leaves no hold behind in the record either.
    const opened = await this.openAttempt(executor, request, admittedRun, startedAt);
    if (opened !== null) return opened;
    // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
    const heldRecorded = await this.record({
      eventType: "GRANT_HELD",
      captured,
      decision,
      ...(reasonCodes.length === 0 ? {} : { reasonCodes: [...reasonCodes] }),
      durationMs: this.clock() - startedAt,
    });
    // Stryker restore all
    if (this.audit?.requiresDeliveryBeforeExecution === true && !heldRecorded) {
      const blocked = await this.block(captured, decision, "AUDIT_UNAVAILABLE", startedAt);
      await this.emit(executor, context, "RUN", captured, decision, blocked, startedAt);
      return blocked;
    }
    const held: HeldExecution = Object.freeze({
      captured,
      decision,
      expiresAt: admitted.authorization.expiresAt,
    });
    this.holds.set(held, { ...context, decision: admitted });
    const result: ExecutionHeldResult = {
      outcome: "HELD",
      executed: false,
      result: null,
      authorization: null,
      held,
    };
    await this.emit(executor, context, "RUN", captured, decision, result, startedAt);
    if (executor.style !== "permit") return result;
    return {
      ...result,
      permit: Object.freeze({
        permitId: AuthorityPaths.grantIdOf(admitted.authorization.token),
        intentHash: captured.intentHash,
        expiresAt: admitted.authorization.expiresAt,
      }),
    };
  }

  /**
   * Every check made before a grant may be consumed, with the evidence that
   * the intent was captured and decided. A refusal is recorded and returned.
   * The executor prepares the action last, so a malformed action is refused
   * the way it always was, after the decision's own checks.
   */
  private async admit<TAction>(
    executor: NativeExecutor<TAction, unknown, unknown>,
    request: RunRequest<TAction>,
    startedAt: number,
    stage: EvidenceStage,
  ): Promise<ExecutionBlockedResult | Admission> {
    const { captured, decision } = request;
    const scope = request.scope ?? null;
    // Stryker disable next-line all: Audit payload mapping is covered by lifecycle event assertions.
    const intentRecorded = await this.record({ eventType: "INTENT_CAPTURED", captured });
    // An observational artifact (shadow observation, serialized audit event) is
    // rejected before it is recorded or inspected as if it were a decision.
    if (!GovernedExecutionRunner.isAuthoritativeDecision(decision)) {
      return await this.block(captured, undefined, "DECISION_NOT_AUTHORITATIVE", startedAt);
    }
    // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
    const decisionRecorded = await this.record({
      eventType: decision.failClosed ? "AUTHORITY_FAILED_CLOSED" : "AUTHORITY_DECISION",
      captured,
      decision,
    });
    // Stryker restore all
    const refuse = async (
      reason: ExecutionBlockReason,
      code?: string,
    ): Promise<ExecutionBlockedResult> => {
      const blocked = await this.block(captured, decision, reason, startedAt, code);
      await this.emitAdmission(executor, request, stage, blocked, startedAt);
      return blocked;
    };
    if (
      this.audit?.requiresDeliveryBeforeExecution === true &&
      (!intentRecorded || !decisionRecorded)
    ) {
      return await refuse("AUDIT_UNAVAILABLE");
    }
    if (!ADMITTED_VERDICTS.has(decision.verdict) || decision.failClosed) {
      return await this.notAllowed(executor, request, stage, startedAt);
    }
    const dossierId = decision.dossierId;
    if (dossierId === null) return await refuse("DOSSIER_MISSING");
    if (decision.intentHash !== captured.intentHash) return await refuse("INTENT_BINDING_MISMATCH");
    if (decision.authorization === null || typeof decision.authorization !== "object") {
      return await refuse("AUTHORIZATION_MISSING");
    }
    if (!this.intentConforms(captured)) return await refuse("INTENT_CONFORMANCE_FAILED");
    // Before the grant is consumed, not after: a boundary that refuses an
    // intent must leave the authority intact for the boundary that owns it.
    if (!this.boundaryMatches(captured)) return await refuse("BOUNDARY_MISMATCH");
    if (!this.workloadMatches(captured)) return await refuse("WORKLOAD_MISMATCH");
    const prepared = await executor.prepare(request.action, scope);
    // What the executor would write must be exactly what was decided: an
    // executor whose own description of the action differs is refused before
    // a grant is spent on it.
    if (!this.preparedMatches(prepared, captured)) return await refuse("INTENT_BINDING_MISMATCH");
    if (scope !== null) {
      const gap = await GovernedExecutionRunner.capabilityGap(executor, scope, prepared);
      if (gap !== null) return await refuse("CAPABILITY_UNAVAILABLE", gap);
    }
    return { prepared, dossierId };
  }

  /**
   * A decision that is not an authoritative ALLOW. When it failed closed the
   * posture says what the surface may do; the runner refuses either way, and
   * never writes without a grant.
   */
  private async notAllowed<TAction>(
    executor: NativeExecutor<TAction, unknown, unknown>,
    request: RunRequest<TAction>,
    stage: EvidenceStage,
    startedAt: number,
  ): Promise<ExecutionBlockedResult> {
    const { captured, decision } = request;
    const blocked = await this.block(captured, decision, "DECISION_NOT_ALLOW", startedAt);
    if (!decision.failClosed || this.posture.posture === "STRICT") {
      await this.emitAdmission(executor, request, stage, blocked, startedAt);
      return blocked;
    }
    const disposition = unavailableDisposition(this.posture, { captured, decision });
    const result: ExecutionBlockedResult = {
      ...blocked,
      unavailable: { posture: this.posture.posture, disposition },
    };
    await this.emitAdmission(executor, request, stage, result, startedAt, disposition);
    return result;
  }

  /**
   * Opens the attempt in the journal, after admission and before anything is
   * consumed: a key already dispatched under, or a journal that cannot take
   * the record, is refused while the grant is still intact.
   */
  private async openAttempt<TAction>(
    executor: NativeExecutor<TAction, unknown, unknown>,
    request: RunRequest<TAction>,
    admission: Admission,
    startedAt: number,
  ): Promise<ExecutionBlockedResult | null> {
    const journal = this.journal;
    if (journal === null) return null;
    const { captured, decision } = request;
    const refuse = async (
      reason: ExecutionBlockReason,
      code?: string,
    ): Promise<ExecutionBlockedResult> => {
      const blocked = await this.block(captured, decision, reason, startedAt, code);
      await this.emitAdmission(executor, request, "RUN", blocked, startedAt);
      return blocked;
    };
    try {
      if (journal.dispatchedUnder !== undefined) {
        const earlier = await journal.dispatchedUnder(admission.prepared.idempotencyKey);
        if (earlier.length > 0) return await refuse("IDEMPOTENCY_KEY_DISPATCHED");
      }
      await journal.append({
        record: "ATTEMPT_OPENED",
        at: new Date(this.clock()).toISOString(),
        intent_id: captured.intent.intentId,
        intent_hash: captured.intentHash,
        idempotency_key: captured.intent.idempotencyKey,
        decision_id: decision.decisionId,
        dossier_id: admission.dossierId,
        caller_principal: null,
        intent: { ...captured.intent } as Record<string, unknown>,
      });
    } catch (error) {
      return await refuse("JOURNAL_UNAVAILABLE", GovernedExecutionRunner.journalCode(error));
    }
    return null;
  }

  /**
   * Consumes the grant through the verifier, checks what came back against
   * the decision and the intent, makes the claim durable, and records the
   * consumption and the start of execution. Nothing here dispatches.
   */
  private async consume(
    context: ExecutionContext,
    captured: CapturedIntent,
    decision: AdmittedDecision,
    startedAt: number,
  ): Promise<HeldClaimResult> {
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
      durationMs: this.clock() - startedAt,
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
    // The claim is durable before anything can be dispatched: a journal that
    // cannot take it, or that refuses a key already claimed, fails the
    // attempt before dispatch, and the authority is told it failed.
    if (this.journal !== null) {
      try {
        await this.journal.append({
          record: "GRANT_CLAIMED",
          at: new Date(this.clock()).toISOString(),
          intent_id: captured.intent.intentId,
          intent_hash: captured.intentHash,
          idempotency_key: captured.intent.idempotencyKey,
          grant_id: authorization.grantId,
          expires_at: authorization.expiresAt,
          request_digest: context.prepared.requestDigest,
        });
      } catch (error) {
        return await this.failedBeforeDispatch(
          captured,
          decision,
          authorization,
          "JOURNAL_UNAVAILABLE",
          startedAt,
          GovernedExecutionRunner.journalCode(error),
        );
      }
    }
    // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
    const executionRecorded = await this.record({
      eventType: "EXECUTION_STARTED",
      captured,
      decision,
      authorization,
      durationMs: this.clock() - startedAt,
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
    return { outcome: "CLAIMED", authorization };
  }

  /**
   * The write, inside the dispatch boundary the runner opens, and its
   * observation. Whatever the executor says, the boundary decides which side
   * of it an error fell: before it nothing was sent, after it a refusal is a
   * refusal only if the platform said so, and anything else is unknown. The
   * runner never moves "nobody knows" to "definitely not".
   */
  private async write(
    executor: AnyExecutor,
    context: ExecutionContext,
    captured: CapturedIntent,
    authorization: VerifiedAuthorization,
    deadline: MonotonicDeadline,
  ): Promise<EffectObservation<unknown> | NotDispatched> {
    const idempotencyKey = captured.intent.idempotencyKey;
    let dispatched = false;
    let signedReceipt: string | null = null;
    const dispatch: ProviderDispatch = Object.freeze({
      idempotencyKey,
      run: async <T>(operation: (key: string) => Promise<T> | T): Promise<T> => {
        // Stryker disable next-line StringLiteral: caught below as an error after the dispatch began; its text is never read.
        if (dispatched) throw new Error("PROVIDER_DISPATCH_ALREADY_STARTED");
        dispatched = true;
        return await operation(idempotencyKey);
      },
      receipt: (token: string): void => {
        // Stryker disable next-line StringLiteral: caught below as an error before the dispatch; its text is never read.
        if (!dispatched) throw new Error("PROVIDER_RECEIPT_BEFORE_DISPATCH");
        signedReceipt = token;
      },
    });
    const unknown = (): EffectObservation => ({
      status: "INDETERMINATE",
      reason: null,
      result: null,
      signedReceipt,
    });
    let effect: Awaited<ReturnType<AnyExecutor["execute"]>>;
    try {
      effect = await executor.execute({
        action: context.action,
        prepared: context.prepared,
        intent: captured,
        scope: context.scope,
        authorization,
        idempotencyKey,
        deadline,
        dispatch,
      });
    } catch (error) {
      if (dispatched && error instanceof ProviderRefusal) {
        return { status: "FAILED", reason: error.reason, result: null, signedReceipt };
      }
      if (dispatched) return unknown();
      return new NotDispatched(error instanceof PreDispatchRefusal ? error.code : undefined);
    }
    if (effect.kind === "NOT_DISPATCHED") {
      if (dispatched) return unknown();
      return new NotDispatched(
        effect.code === undefined ? undefined : new PreDispatchRefusal(effect.code).code,
      );
    }
    if (effect.kind === "PERMIT") {
      // A dispatch never yields a permit; one that does broke the contract,
      // and what it did is unknown once its dispatch began.
      if (dispatched) return unknown();
      return new NotDispatched("EXECUTOR_CONTRACT_VIOLATION");
    }
    try {
      const observation = await executor.observe(effect, context.prepared);
      return {
        ...observation,
        signedReceipt: observation.signedReceipt ?? effect.signedReceipt ?? signedReceipt,
      };
    } catch {
      return unknown();
    }
  }

  /** The permit a presented, claimed hold writes with; null when the executor issued none. */
  private async issuePermit(
    state: HeldState,
    held: HeldExecution,
    authorization: VerifiedAuthorization,
  ): Promise<ExecutionPermit | null> {
    const deadline = MonotonicDeadline.after(dispatchBudgetMs(this.timeoutMs, authorization));
    // A permit-style executor never writes: the boundary does. Either half of
    // the dispatch refuses, so an executor that tries is not issuing a permit.
    const refuse = (): never => {
      // Stryker disable next-line StringLiteral: caught below as no permit issued; its text is never read.
      throw new Error("PERMIT_EXECUTOR_CANNOT_DISPATCH");
    };
    try {
      const effect = await state.executor.execute({
        action: state.action,
        prepared: state.prepared,
        intent: held.captured,
        scope: state.scope,
        authorization,
        idempotencyKey: held.captured.intent.idempotencyKey,
        deadline,
        dispatch: Object.freeze({
          idempotencyKey: held.captured.intent.idempotencyKey,
          run: refuse,
          receipt: refuse,
        }),
      });
      if (effect.kind !== "PERMIT") return null;
      // The permit names this grant, this intent and the authority's proof of
      // the claim, whatever the executor's own description of it says.
      return Object.freeze({
        permitId: authorization.grantId,
        intentHash: held.captured.intentHash,
        expiresAt: authorization.expiresAt,
        ...(authorization.claimAttestation === undefined
          ? {}
          : { claimAttestation: authorization.claimAttestation }),
      });
    } catch {
      return null;
    }
  }

  /** What the executor reads a permit-style receipt as; a receipt it cannot read is unknown. */
  private async observeReceipt<TResult>(
    state: ClaimState,
    receipt: unknown,
    signedReceipt: string | null,
  ): Promise<EffectObservation<TResult>> {
    try {
      const prepared = state.prepared ?? (await state.executor.prepare(state.action, state.scope));
      const observation = (await state.executor.observe(
        { kind: "RECEIPT", receipt, signedReceipt },
        prepared,
      )) as EffectObservation<TResult>;
      return { ...observation, signedReceipt: observation.signedReceipt ?? signedReceipt };
    } catch {
      return { status: "INDETERMINATE", reason: null, result: null, signedReceipt };
    }
  }

  /** The terminal result of a dispatched write, finalized and recorded. */
  private async concluded<TResult>(
    captured: CapturedIntent,
    decision: DecisionGate,
    authorization: VerifiedAuthorization,
    observation: EffectObservation<TResult>,
    startedAt: number,
  ): Promise<SafeExecutionResult<TResult>> {
    const receipt = observation.signedReceipt ?? null;
    if (observation.status === "FAILED") {
      // The provider said no. That is an outcome, so it is finalized `FAILED`
      // rather than left indeterminate, and `executed` is false rather than
      // null: nothing about it is unknown.
      const finalization = await this.finalize(
        captured,
        decision,
        authorization,
        "FAILED",
        receipt,
        observation.evidence,
      );
      const reason = observation.reason ?? "PROVIDER_REFUSED";
      const result: SafeExecutionResult<TResult> = {
        outcome: "DEFINITELY_NOT_EXECUTED",
        executed: false,
        recovered: false,
        reason,
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
        reasonCodes: [reason, GovernedExecutionRunner.finalizationCode(finalization)],
        durationMs: this.clock() - startedAt,
      });
      // Stryker restore all
      return result;
    }
    if (observation.status === "INDETERMINATE") {
      const finalization = await this.finalize(
        captured,
        decision,
        authorization,
        "INDETERMINATE",
        receipt,
        observation.evidence,
      );
      const result: SafeExecutionResult<TResult> = {
        outcome: "UNKNOWN_AFTER_DISPATCH",
        executed: null,
        reason: "PROVIDER_OUTCOME_UNKNOWN",
        result: null,
        authorization,
        recovery: GovernedExecutionRunner.recoveryReference(captured, authorization),
        finalization,
      };
      // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
      await this.record({
        eventType: "EXECUTION_OUTCOME_UNKNOWN",
        captured,
        decision,
        authorization,
        reasonCodes: [result.reason, GovernedExecutionRunner.finalizationCode(finalization)],
        durationMs: this.clock() - startedAt,
      });
      // Stryker restore all
      return result;
    }
    const finalization = await this.finalize(
      captured,
      decision,
      authorization,
      "COMMITTED",
      receipt,
      observation.evidence,
    );
    const result: SafeExecutionResult<TResult> = {
      outcome: "COMPLETED",
      executed: true,
      recovered: false,
      result: observation.result as TResult,
      authorization,
      finalization,
    };
    // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
    await this.record({
      eventType: "EXECUTION_COMPLETED",
      captured,
      decision,
      authorization,
      reasonCodes: [GovernedExecutionRunner.finalizationCode(finalization)],
      durationMs: this.clock() - startedAt,
    });
    // Stryker restore all
    return result;
  }

  /**
   * Reports the attempt outcome to the verifier's authority, with the
   * provider's effect receipt and the executor's observation when the attempt
   * brought them back. A missing, failing, or malformed finalization can
   * never alter the execution result.
   */
  private async finalize(
    captured: CapturedIntent,
    decision: DecisionGate,
    authorization: VerifiedAuthorization,
    outcome: ExecutionCommitOutcome,
    receipt: string | null = null,
    evidence?: AuthorityEffectEvidence,
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
        ...(evidence === undefined ? {} : { effectEvidence: evidence }),
      });
      return status === "RECORDED" ? "RECORDED" : "PENDING";
    } catch {
      return "PENDING";
    }
  }

  /** The journal and the authority hear of a proven reconciliation; neither can change its result. */
  private async reconciled(
    context: ExecutionContext,
    captured: CapturedIntent,
    authorization: VerifiedAuthorization,
    result: Exclude<ExecutionReconciliationResult<unknown>, ExecutionBlockedResult>,
    proven: "COMMITTED" | "FAILED" | null,
    evidence: AuthorityEffectEvidence | undefined,
    startedAt: number,
  ): Promise<void> {
    await this.appendQuietly({
      record: "RECONCILED",
      at: new Date(this.clock()).toISOString(),
      intent_id: captured.intent.intentId,
      intent_hash: captured.intentHash,
      status: result.outcome,
      source: "CALLER",
    });
    let finalization: ExecutionFinalization | null = null;
    const report = this.verifier.reconcile;
    if (proven !== null && this.reportReconciliations) {
      if (report === undefined) {
        finalization = "UNSUPPORTED";
      } else {
        try {
          finalization =
            (await report.call(this.verifier, {
              captured,
              authorization,
              outcome: proven,
              ...(evidence === undefined ? {} : { effectEvidence: evidence }),
            })) === "RECORDED"
              ? "RECORDED"
              : "PENDING";
        } catch {
          finalization = "PENDING";
        }
      }
    }
    await this.emitLine(context.executor, context, {
      stage: "RECONCILIATION",
      captured,
      decision: null,
      ...GovernedExecutionRunner.summaryOf(result),
      disposition: null,
      finalization,
      startedAt,
    });
  }

  private static finalizationCode(finalization: ExecutionFinalization): string {
    return `COMMIT_FINALIZATION_${finalization}`;
  }

  private static settledEvent(outcome: ExecutionCommitOutcome): AuditEventType {
    if (outcome === "COMMITTED") return "EXECUTION_COMPLETED";
    if (outcome === "FAILED") return "EXECUTION_REFUSED_AFTER_DISPATCH";
    return "EXECUTION_OUTCOME_UNKNOWN";
  }

  private static outcomeOf(
    status: ExecutionCommitOutcome,
  ): "COMPLETED" | "DEFINITELY_NOT_EXECUTED" | "UNKNOWN_AFTER_DISPATCH" {
    if (status === "COMMITTED") return "COMPLETED";
    if (status === "FAILED") return "DEFINITELY_NOT_EXECUTED";
    return "UNKNOWN_AFTER_DISPATCH";
  }

  private static observationOf<TResult>(
    status: ExecutionCommitOutcome,
    signedReceipt: string | null,
  ): EffectObservation<TResult> {
    return { status, reason: null, result: null, signedReceipt };
  }

  /**
   * Observational artifacts carry an explicit non-authoritative marker. They
   * must never be interpreted as a `DecisionGate`, even after an unsafe cast
   * or a JSON round trip.
   */
  private static isAuthoritativeDecision(decision: DecisionGate): boolean {
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

  /**
   * Whether the workload that proposed the intent is the one running it. Like
   * the boundary, the digest is read back out of the hashed context.
   */
  private workloadMatches(captured: CapturedIntent): boolean {
    if (this.workloadDigest === null) return true;
    return workloadOf(captured.intent.context)?.digest === this.workloadDigest;
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

  /** The executor's description of the action, held to the decided intent field by field. */
  private preparedMatches(prepared: PreparedAction, captured: CapturedIntent): boolean {
    const intent = captured.intent;
    let parameters: string;
    // Stryker disable BlockStatement: parameters that cannot be canonicalized never match the intent; the explicit false only names that.
    try {
      parameters = CanonicalIntentHasher.stringify(prepared.proposal.parameters as JsonValue);
    } catch {
      return false;
    }
    // Stryker restore BlockStatement
    return (
      prepared.actionType === intent.action &&
      prepared.proposal.action === intent.action &&
      prepared.proposal.target === intent.target &&
      parameters === CanonicalIntentHasher.stringify(intent.parameters as JsonValue) &&
      prepared.downstreamTarget.system === intent.downstreamTarget.system &&
      prepared.downstreamTarget.operation === intent.downstreamTarget.operation &&
      prepared.idempotencyKey === intent.idempotencyKey &&
      (prepared.expectedEffectDigest ?? undefined) === intent.expectedEffectDigest &&
      GovernedExecutionRunner.sameProjection(prepared.policyProjection, intent.policyProjection)
    );
  }

  /**
   * Whether the executor describes the policy path the intent was decided on:
   * both absent, or the same four fields. A projection on one side only is
   * another policy path, never the same one.
   */
  private static sameProjection(
    prepared: PolicyProjection | undefined,
    decided: PolicyProjection | undefined,
  ): boolean {
    if (prepared === undefined || decided === undefined) return prepared === decided;
    return (
      prepared.decisionType === decided.decisionType &&
      prepared.transactionType === decided.transactionType &&
      prepared.workflowKey === decided.workflowKey &&
      prepared.channel === decided.channel
    );
  }

  /**
   * The connection must be able to take the write: connected, scope granted,
   * switched on, for this action type on this platform. The refusal names
   * what is missing in the Commerce executor's own words.
   */
  private static async capabilityGap(
    executor: AnyExecutor,
    scope: ExecutorScope,
    prepared: PreparedAction,
  ): Promise<string | null> {
    let capabilities: Awaited<ReturnType<AnyExecutor["capabilities"]>>;
    try {
      capabilities = await executor.capabilities(scope);
    } catch {
      return "CAPABILITY_UNREADABLE";
    }
    const capability = capabilities.find(
      (candidate) =>
        candidate.actionType === prepared.actionType && candidate.platform === executor.platform,
    );
    if (capability === undefined) return "UNSUPPORTED_ACTION";
    if (!capability.connected) return "NOT_CONNECTED";
    if (!capability.scopeGranted) return "SCOPE_NOT_GRANTED";
    if (!capability.enabled) return "CAPABILITY_DISABLED";
    return null;
  }

  private async block(
    captured: CapturedIntent,
    decision: DecisionGate | undefined,
    reason: ExecutionBlockReason,
    startedAt: number,
    code?: string,
  ): Promise<ExecutionBlockedResult> {
    // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
    await this.record({
      eventType: "EXECUTION_BLOCKED",
      captured,
      ...(decision === undefined ? {} : { decision }),
      reasonCodes: code === undefined ? [reason] : [reason, code],
      durationMs: this.clock() - startedAt,
    });
    // Stryker restore all
    return {
      outcome: "BLOCKED",
      executed: false,
      reason,
      ...(code === undefined ? {} : { code }),
      result: null,
      authorization: null,
    };
  }

  private async failedBeforeDispatch(
    captured: CapturedIntent,
    decision: DecisionGate,
    authorization: VerifiedAuthorization,
    reason: ExecutionPreDispatchFailureReason,
    startedAt: number,
    code?: string,
  ): Promise<FailedBeforeDispatchResult> {
    // The grant was consumed but no side effect was attempted.
    const finalization = await this.finalize(captured, decision, authorization, "FAILED");
    // Stryker disable all: Audit payload mapping is covered by lifecycle event assertions.
    await this.record({
      eventType: "EXECUTION_FAILED_BEFORE_DISPATCH",
      captured,
      decision,
      authorization,
      reasonCodes: [
        reason,
        ...(code === undefined ? [] : [code]),
        GovernedExecutionRunner.finalizationCode(finalization),
      ],
      durationMs: this.clock() - startedAt,
    });
    // Stryker restore all
    return {
      outcome: "FAILED_BEFORE_DISPATCH",
      executed: false,
      reason,
      ...(code === undefined ? {} : { code }),
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

  /** Closes the attempt in the journal; the outcome is already final, so a failure is left to the reconciler. */
  private async close(captured: CapturedIntent, result: Concluded): Promise<void> {
    const summary = GovernedExecutionRunner.summaryOf(result);
    await this.appendQuietly({
      record: "ATTEMPT_CLOSED",
      at: new Date(this.clock()).toISOString(),
      intent_id: captured.intent.intentId,
      intent_hash: captured.intentHash,
      outcome: result.outcome,
      executed: summary.executed,
      finalization: summary.finalization,
    });
  }

  private async appendQuietly(record: JournalRecord): Promise<void> {
    // Stryker disable next-line ConditionalExpression: without a journal the append below throws inside the try and is ignored; the guard only saves the attempt.
    if (this.journal === null) return;
    try {
      await this.journal.append(record);
    } catch {
      // An attempt that cannot be closed stays open, which the startup
      // reconciler resolves; it never changes the result already returned.
    }
  }

  private async emitAdmission<TAction>(
    executor: NativeExecutor<TAction, unknown, unknown>,
    request: RunRequest<TAction>,
    stage: EvidenceStage,
    blocked: ExecutionBlockedResult,
    startedAt: number,
    disposition: UnavailableDisposition | null = null,
  ): Promise<void> {
    await this.emitLine(executor, null, {
      stage,
      captured: request.captured,
      decision: request.decision,
      ...GovernedExecutionRunner.summaryOf(blocked),
      disposition: disposition ?? (request.decision.failClosed ? "NOT_FORWARDED" : null),
      startedAt,
      scope: request.scope ?? null,
    });
  }

  private async emit(
    executor: AnyExecutor,
    context: ExecutionContext,
    stage: EvidenceStage,
    captured: CapturedIntent,
    decision: DecisionGate,
    result: Concluded | ExecutionHeldResult | PermitPresentationResult | HeldClaimResult,
    startedAt: number,
  ): Promise<void> {
    await this.emitLine(executor, context, {
      stage,
      captured,
      decision,
      ...GovernedExecutionRunner.summaryOf(result),
      disposition: null,
      startedAt,
    });
  }

  /**
   * What a step's result says, in the fields an evidence line and a closing
   * journal record carry: one case per outcome, so no outcome is described by
   * another's fields.
   */
  private static summaryOf(
    result:
      | Concluded
      | ExecutionHeldResult
      | PermitPresentationResult
      | HeldClaimResult
      | Exclude<ExecutionReconciliationResult<unknown>, ExecutionBlockedResult>,
  ): StepSummary {
    switch (result.outcome) {
      case "CLAIMED":
        return {
          outcome: "CLAIMED",
          executed: null,
          reason: null,
          code: null,
          grantId: result.authorization.grantId,
          governed: true,
          finalization: null,
        };
      case "HELD":
        return {
          outcome: "HELD",
          executed: false,
          reason: null,
          code: null,
          grantId: null,
          governed: true,
          finalization: null,
        };
      case "BLOCKED":
        return {
          outcome: "BLOCKED",
          executed: false,
          reason: result.reason,
          code: result.code ?? null,
          grantId: null,
          governed: false,
          finalization: null,
        };
      case "FAILED_BEFORE_DISPATCH":
        return {
          outcome: "FAILED_BEFORE_DISPATCH",
          executed: false,
          reason: result.reason,
          code: result.code ?? null,
          grantId: result.authorization.grantId,
          governed: true,
          finalization: result.finalization,
        };
      case "COMPLETED":
        return {
          outcome: "COMPLETED",
          executed: true,
          reason: null,
          code: null,
          grantId: result.authorization.grantId,
          governed: true,
          finalization: "finalization" in result ? result.finalization : null,
        };
      case "DEFINITELY_NOT_EXECUTED":
        return {
          outcome: "DEFINITELY_NOT_EXECUTED",
          executed: false,
          reason: result.reason,
          code: null,
          grantId: result.authorization.grantId,
          governed: true,
          finalization: "finalization" in result ? result.finalization : null,
        };
      case "UNKNOWN_AFTER_DISPATCH":
        return {
          outcome: "UNKNOWN_AFTER_DISPATCH",
          executed: null,
          reason: result.reason,
          code: null,
          grantId: result.authorization.grantId,
          governed: true,
          finalization: "finalization" in result ? result.finalization : null,
        };
    }
  }

  private async emitLine(
    executor: AnyExecutor,
    context: { readonly scope: ExecutorScope | null } | null,
    line: {
      readonly stage: EvidenceStage;
      readonly captured: CapturedIntent;
      readonly decision: DecisionGate | null;
      readonly outcome: ExecutionOutcome | "CLAIMED";
      readonly executed: boolean | null;
      readonly reason: string | null;
      readonly code: string | null;
      readonly grantId: string | null;
      readonly governed: boolean;
      readonly disposition: UnavailableDisposition | null;
      readonly finalization: ExecutionFinalization | null;
      readonly startedAt: number;
      readonly scope?: ExecutorScope | null;
    },
  ): Promise<void> {
    const sink = this.evidence;
    // Stryker disable next-line ConditionalExpression: without a sink the line is built and the emit below throws inside the try; the guard only saves the work.
    if (sink === null) return;
    const decision = line.decision;
    const evidence: ExecutorEvidenceLine = {
      version: EXECUTOR_EVIDENCE_VERSION,
      contract: NATIVE_EXECUTOR_CONTRACT,
      at: new Date(this.clock()).toISOString(),
      stage: line.stage,
      executor: { platform: executor.platform, version: executor.version, style: executor.style },
      action_type: line.captured.intent.action,
      intent_id: line.captured.intent.intentId,
      intent_hash: line.captured.intentHash,
      decision_id: decision?.decisionId ?? null,
      dossier_id: decision?.dossierId ?? null,
      verdict: decision?.verdict ?? null,
      grant_id: line.grantId,
      outcome: line.outcome,
      executed: line.executed,
      reason: line.reason,
      code: line.code,
      governed: line.governed,
      authority_state: decision?.failClosed === true ? "AUTHORITY_UNAVAILABLE" : "DECIDED",
      posture: this.posture.posture,
      disposition: line.disposition,
      finalization: line.finalization,
      duration_ms: Math.max(this.clock() - line.startedAt, 0),
      scope: evidenceScope(line.scope ?? context?.scope ?? null),
    };
    try {
      await sink.emit(Object.freeze(evidence));
    } catch {
      // Evidence is not authority: a sink that fails changes no outcome.
    }
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

  private static sameBinding(
    recorded: VerifiedAuthorization,
    recovery: ExecutionRecoveryReference,
  ): boolean {
    return (
      recorded.decisionId === recovery.decisionId &&
      recorded.dossierId === recovery.dossierId &&
      recorded.grantId === recovery.grantId &&
      recorded.intentHash === recovery.intentHash &&
      recorded.expiresAt === recovery.expiresAt
    );
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

  /** The journal, read as the attempts a recovery reference is held against. */
  private static journalAttempts(journal: ExecutionJournal | null): DispatchedAttempts | null {
    if (journal === null) return null;
    return {
      authorizationsOf: async (captured) =>
        await journal.authorizationsOf(captured.intent.intentId),
    };
  }

  private static journalCode(error: unknown): string {
    return error instanceof JournalError ? error.code : "JOURNAL_WRITE_FAILED";
  }
}
