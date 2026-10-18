import type { DecisionGate } from "../decision/DecisionAuthority.js";
import type { AuditRecorder } from "../audit/AuditRecorder.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import type { JsonObject } from "../intent/JsonValue.js";
import type { ActionRegistry } from "./ActionRegistry.js";
import type {
  AuthorizationVerifier,
  ExecutionCommitOutcome,
  ExecutionFinalization,
  VerifiedAuthorization,
} from "./AuthorizationVerifier.js";
import type {
  DispatchedAttempts,
  ExecutionBlockedResult,
  ExecutionHeldResult,
  ExecutionReconciliationResult,
  ExecutionRecoveryReference,
  HeldClaimResult,
  HeldExecution,
  SafeExecutionResult,
} from "./ExecutionOutcome.js";
import { GovernedExecutionRunner } from "./GovernedExecutionRunner.js";
import { RegistryExecutor } from "./RegistryExecutor.js";

export type {
  DispatchedAttempts,
  ExecutionBlockedResult,
  ExecutionBlockReason,
  ExecutionHeldResult,
  ExecutionPreDispatchFailureReason,
  ExecutionReconciliationResult,
  ExecutionRecoveryReference,
  HeldClaimResult,
  HeldExecution,
  ProviderOutcomeUnknownResult,
  ProviderRefusedResult,
  SafeExecutionResult,
} from "./ExecutionOutcome.js";

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
  /**
   * The digest of the workload this executor runs as. When it is set, an
   * intent proposed by a different artifact is refused: authority granted to
   * one signed workload is not authority for the next one to reuse. Absent,
   * as it is wherever no runtime describes the artifact, nothing is checked —
   * a policy that requires provenance refuses at the authority instead.
   */
  readonly workloadDigest?: string;
  /**
   * This executor's own record of the attempts it dispatched. A recovery
   * reference is something a caller presents, so its decision and grant are
   * claims; with a record to hold them against, reconciliation proceeds only
   * for a binding this executor journaled before dispatch. Absent, the
   * lookup still runs, and its audit events say `NON_AUTHORITATIVE`, because
   * nothing here vouches for a binding it was only told about.
   */
  readonly attempts?: DispatchedAttempts;
}

/**
 * The registry-shaped face of `GovernedExecutionRunner`, kept so that every
 * caller written against it keeps its signatures and its outcomes exactly.
 * Each method is the runner's, with the registry as the executor: admission,
 * the claim, finalization, holds and reconciliation all happen in the
 * runner, and nothing here decides anything.
 *
 * Two runner behaviours stay off behind this face, because they did not
 * exist when it was written: the runner does not refuse a dispatch whose
 * window closed (the registry's handlers bound their own dispatch), and it
 * does not report reconciliations to the authority. Code that wants either
 * uses the runner, with a `NativeExecutor`, directly.
 */
export class SafeExecutor {
  private readonly runner: GovernedExecutionRunner;
  private readonly executor: RegistryExecutor;

  public constructor(
    registry: ActionRegistry,
    verifier: AuthorizationVerifier,
    audit?: AuditRecorder,
    options?: SafeExecutorOptions,
  ) {
    this.executor = new RegistryExecutor(registry);
    this.runner = new GovernedExecutionRunner({
      verifier,
      audit,
      ...(options?.boundaryId === undefined ? {} : { boundaryId: options.boundaryId }),
      ...(options?.workloadDigest === undefined ? {} : { workloadDigest: options.workloadDigest }),
      ...(options?.attempts === undefined ? {} : { attempts: options.attempts }),
      enforceDispatchWindow: false,
      reportReconciliations: false,
    });
  }

  public async run<TResult = unknown>(
    captured: CapturedIntent,
    decision: DecisionGate,
  ): Promise<SafeExecutionResult<TResult>> {
    return (await this.runner.dispatch(this.executor, {
      captured,
      decision,
      action: captured,
    })) as SafeExecutionResult<TResult>;
  }

  /**
   * Admits a decision exactly as `run` would and holds its grant instead of
   * consuming it. The intent, the decision and the hold are recorded; the
   * grant stays unclaimed until `claimHeld` is called with the handle, and an
   * unclaimed hold simply expires with its grant.
   */
  public async hold(
    captured: CapturedIntent,
    decision: DecisionGate,
  ): Promise<ExecutionHeldResult | ExecutionBlockedResult> {
    return await this.runner.hold(this.executor, { captured, decision, action: captured });
  }

  /**
   * Admits a hold this executor did not make: one another replica made, or
   * this process made before a restart, read back from a store the replicas
   * share. Every check `hold` makes is made again on the way in, and the
   * record says the hold was adopted.
   */
  public async adoptHold(
    captured: CapturedIntent,
    decision: DecisionGate,
  ): Promise<ExecutionHeldResult | ExecutionBlockedResult> {
    return await this.runner.adoptHold(this.executor, { captured, decision, action: captured });
  }

  /**
   * Registers a claim this executor did not make, so that `settleHeld` can
   * finalize it here. Nothing is consumed and nothing is checked against the
   * authority; the finalization is, as always, the authority's to accept or
   * refuse.
   */
  public adoptClaim(
    captured: CapturedIntent,
    decision: DecisionGate,
    authorization: VerifiedAuthorization,
    material: JsonObject | null = null,
  ): HeldExecution {
    return this.runner.adoptClaim(
      this.executor,
      { captured, decision, action: captured },
      authorization,
      material,
    );
  }

  /**
   * What another process needs to finalize a claim this executor's verifier
   * made, for a store the replicas share to keep sealed; null when the
   * verifier keeps its claims to itself or did not make this one.
   */
  public claimMaterial(authorization: VerifiedAuthorization): JsonObject | null {
    return this.runner.claimMaterial(authorization);
  }

  /**
   * Claims a held grant, once. A second claim of the same hold, concurrent or
   * later, is refused without reaching the authority; a handle this executor
   * did not issue is refused the same way.
   */
  public async claimHeld(held: HeldExecution): Promise<HeldClaimResult> {
    return (await this.runner.present(held)) as HeldClaimResult;
  }

  /**
   * Reports how a claimed hold ended, once: `COMMITTED` when the effect
   * happened, `FAILED` when it definitively did not, `INDETERMINATE` when
   * nobody can say. The terminal record names the outcome, as `run`'s do.
   */
  public async settleHeld(
    held: HeldExecution,
    outcome: ExecutionCommitOutcome,
    receipt: string | null = null,
  ): Promise<ExecutionFinalization> {
    const settlement = await this.runner.settle(held, { outcome, signedReceipt: receipt });
    if (settlement.status !== "SETTLED") throw new Error("HELD_EXECUTION_NOT_CLAIMED");
    return settlement.finalization;
  }

  public async reconcile<TResult = unknown>(
    captured: CapturedIntent,
    recovery: ExecutionRecoveryReference,
  ): Promise<ExecutionReconciliationResult<TResult>> {
    return (await this.runner.reconcile(this.executor, {
      captured,
      recovery,
      action: captured,
    })) as ExecutionReconciliationResult<TResult>;
  }
}
