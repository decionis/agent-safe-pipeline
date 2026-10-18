import { CanonicalIntentHasher } from "../intent/CanonicalIntentHasher.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import type { JsonValue } from "../intent/JsonValue.js";
import type { ActionExecutionAttempt, ActionRegistry } from "./ActionRegistry.js";
import type {
  ClaimedExecution,
  EffectObservation,
  ExecutionCapability,
  ExecutionEffect,
  NativeExecutor,
  PreparedAction,
  ReconcileContext,
  ReconcileResult,
} from "./NativeExecutor.js";
import { createHash } from "node:crypto";

/**
 * The dispatch-style executor an `ActionRegistry` already is: every
 * registered handler, run by intent, behind the contract. It is how
 * `SafeExecutor` and the runtime's registry reach `GovernedExecutionRunner`
 * without a change to a single handler: the registry keeps its dispatch
 * tracking, its refusals and its single-flight reconciliation, and this
 * class only reads what it reports into the contract's terms.
 *
 * The action it executes is the captured intent itself, so what it prepares
 * is exactly what was decided: there is no second description of the action
 * that could drift from the one the authority bound.
 */
export class RegistryExecutor implements NativeExecutor<
  CapturedIntent,
  ActionExecutionAttempt,
  unknown
> {
  public readonly platform: string;
  public readonly version = "registry/1";
  public readonly style = "dispatch" as const;
  public readonly actionTypes: readonly string[] = [];

  public constructor(
    private readonly registry: ActionRegistry,
    platform = "action-registry",
  ) {
    this.platform = platform;
  }

  /** The registry knows its handlers, not a connection; it states no capability to check. */
  public async capabilities(): Promise<readonly ExecutionCapability[]> {
    return await Promise.resolve([]);
  }

  /**
   * Refuses an unregistered action or parameters its handler's schema does
   * not accept, by throwing exactly as the registry's own validation does.
   */
  public async prepare(captured: CapturedIntent): Promise<PreparedAction> {
    this.registry.validate(captured);
    const intent = captured.intent;
    const canonical = CanonicalIntentHasher.stringify(intent.parameters as JsonValue);
    return await Promise.resolve({
      actionType: intent.action,
      proposal: { action: intent.action, target: intent.target, parameters: intent.parameters },
      downstreamTarget: intent.downstreamTarget,
      idempotencyKey: intent.idempotencyKey,
      expectedEffectDigest:
        intent.expectedEffectDigest === undefined
          ? null
          : (intent.expectedEffectDigest as `sha256:${string}`),
      requestDigest: `sha256:${createHash("sha256").update(canonical).digest("hex")}`,
      facts: {},
    });
  }

  /** The registry tracks its own dispatch boundary; what it reports is carried through verbatim. */
  public async execute(
    run: ClaimedExecution<CapturedIntent>,
  ): Promise<ExecutionEffect<ActionExecutionAttempt>> {
    const attempt = await this.registry.executeTracked(run.action, run.authorization);
    if (attempt.status === "FAILED_BEFORE_DISPATCH") {
      return { kind: "NOT_DISPATCHED", code: attempt.code };
    }
    return { kind: "DISPATCHED", receipt: attempt, signedReceipt: attempt.receipt };
  }

  public async observe(
    effect: ExecutionEffect<ActionExecutionAttempt>,
  ): Promise<EffectObservation<unknown>> {
    const attempt = effect.kind === "DISPATCHED" ? effect.receipt : null;
    if (attempt === null || attempt.status === "FAILED_BEFORE_DISPATCH") {
      return await Promise.resolve({ status: "INDETERMINATE", reason: null, result: null });
    }
    if (attempt.status === "COMPLETED") {
      return {
        status: "COMMITTED",
        reason: null,
        result: attempt.result,
        signedReceipt: attempt.receipt,
      };
    }
    if (attempt.status === "REFUSED_AFTER_DISPATCH") {
      return {
        status: "FAILED",
        reason: attempt.reason,
        result: null,
        signedReceipt: attempt.receipt,
      };
    }
    return { status: "INDETERMINATE", reason: null, result: null, signedReceipt: attempt.receipt };
  }

  public async reconcile(context: ReconcileContext): Promise<ReconcileResult<unknown>> {
    return await this.registry.reconcile(context.intent, context.idempotencyKey);
  }
}
