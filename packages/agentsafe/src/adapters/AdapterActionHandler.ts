import { ProviderRefusal } from "@decionis/agent-safe-pipeline";
import type {
  ActionExecutionContext,
  ActionHandler,
  ActionReconciliationContext,
  EffectPreparedAction,
  JsonObject,
  ProviderReconciliation,
} from "@decionis/agent-safe-pipeline";
import type { z } from "zod";
import { dispatchBudgetMs, MonotonicDeadline } from "../time/MonotonicClock.js";
import { IndeterminateOutcome, type EffectAdapter } from "./EffectAdapter.js";
import { EffectAdapterExecutor, type ActionDescription } from "./EffectAdapterExecutor.js";
import type { EffectEvidenceRegister, RegisteredEffect } from "./EffectEvidenceRegister.js";

/** What the executor reports about an adapter's attempt: statuses and digests only. */
export interface AdapterExecutionResult {
  readonly outcome: "COMMITTED" | "FAILED";
  readonly confirmation: "PENDING" | "CONFIRMED" | "NOT_EFFECTED" | "REVERSED" | "UNKNOWN";
  readonly comparison: "MATCH" | "MISMATCH" | "PENDING";
  readonly mismatchedFields: readonly string[];
  readonly observationMethod: string;
  readonly expectedEffectDigest: string;
  readonly observedEffectDigest: string | null;
  readonly responseDigest: string | null;
  readonly providerReference: string | null;
  readonly evidenceDigest: string;
  readonly reasonCodes: readonly string[];
  /** How the provider's receipt, when it gave one, relates to this account. */
  readonly receiptComparison: "MATCH" | "MISMATCH" | "SILENT" | "ABSENT";
  /** What the receipt said it did, when it gave one. */
  readonly receiptStatus: "EFFECTED" | "REFUSED" | "INDETERMINATE" | null;
}

export interface AdapterHandlerOptions<TAction> {
  readonly adapter: EffectAdapter<TAction>;
  readonly schema: z.ZodType<TAction>;
  readonly register: EffectEvidenceRegister;
  readonly timeoutMs: number;
  /** Told when an observation did not match what was authorised. */
  readonly onMismatch?: (mismatched: readonly string[]) => void;
  readonly clock?: () => Date;
}

export interface ExecutorHandlerOptions<TAction> {
  readonly schema: z.ZodType<TAction>;
  readonly register: EffectEvidenceRegister;
  readonly timeoutMs: number;
  /** Told when an observation did not match what was authorised. */
  readonly onMismatch?: (mismatched: readonly string[]) => void;
}

/**
 * The bridge from any `EffectAdapter` to the pipeline's `ActionHandler`: the
 * adapter as a dispatch-style `NativeExecutor` (`EffectAdapterExecutor`),
 * bridged by `executorActionHandler`. Kept so every registration written
 * against it keeps its signature.
 */
export function adapterActionHandler<TAction>(
  options: AdapterHandlerOptions<TAction>,
): ActionHandler<TAction, AdapterExecutionResult> {
  const executor = new EffectAdapterExecutor<TAction>({
    adapter: options.adapter,
    platform: options.adapter.id,
    describe: describeByEffect,
    ...(options.clock === undefined ? {} : { clock: options.clock }),
  });
  return executorActionHandler(executor, {
    schema: options.schema,
    register: options.register,
    timeoutMs: options.timeoutMs,
    ...(options.onMismatch === undefined ? {} : { onMismatch: options.onMismatch }),
  });
}

/**
 * The bridge from a dispatch-style executor over an effect adapter to the
 * pipeline's `ActionHandler`, so the registry the runtime runs through
 * `GovernedExecutionRunner` reaches it. It keeps the shape the boundary
 * requires and adds the effect plane:
 *
 * the executor's `prepare`, which reaches nothing; then its write inside
 * `dispatch.run`, bounded by the smaller of the configured timeout and what
 * is left of the grant; then its observation, compared field by field
 * against what was authorised; then the record, registered against this
 * exact authorization for the verifier to finalize with.
 *
 * What the executor observed is said to the registry in the registry's own
 * terms: an outcome nobody can determine is re-raised as
 * `IndeterminateOutcome`, which the registry reports as unknown; a provider
 * that was reached and said no is a `ProviderRefusal`, which it reports as
 * definitely not executed; and a commit returns its effect block.
 */
export function executorActionHandler<TAction>(
  executor: EffectAdapterExecutor<TAction>,
  options: ExecutorHandlerOptions<TAction>,
): ActionHandler<TAction, AdapterExecutionResult> {
  const execute = async (
    context: ActionExecutionContext<TAction>,
  ): Promise<AdapterExecutionResult> => {
    const prepared = executor.prepareNow(context.parameters);
    const deadline = MonotonicDeadline.after(
      dispatchBudgetMs(options.timeoutMs, context.authorization),
    );
    const effect = await executor.execute({
      action: context.parameters,
      prepared,
      intent: context.intent,
      scope: null,
      authorization: context.authorization,
      idempotencyKey: context.dispatch.idempotencyKey,
      deadline,
      dispatch: context.dispatch,
    });
    // The provider's receipt rides on the attempt to the finalization, where
    // the authority verifies it; this layer only compares what it states. An
    // indeterminate answer can carry one too, and it is not dropped with it.
    const signedReceipt = effect.kind === "DISPATCHED" ? (effect.signedReceipt ?? null) : null;
    if (typeof signedReceipt === "string") context.dispatch.receipt(signedReceipt);
    const observation = await executor.observe(effect);
    const observed = observation.result;
    if (observed === null) throw new IndeterminateOutcome("EXECUTOR_OBSERVATION_MISSING");
    const record = observed.record;
    options.register.attach(context.authorization, record);
    if (record.comparison === "MISMATCH" || record.receipt.comparison === "MISMATCH") {
      options.onMismatch?.(record.mismatched);
    }
    // An outcome nobody can determine stays undetermined: the throw is
    // re-raised so the pipeline reports an unknown outcome rather than a
    // failure or a success.
    if (observation.status === "INDETERMINATE") {
      throw new IndeterminateOutcome(
        observed.indeterminate?.reason ?? "PROVIDER_OUTCOME_UNKNOWN",
        observed.indeterminate?.providerStatus ?? null,
        signedReceipt,
      );
    }
    // A provider that was reached and said no is a fact, not a success. The
    // evidence is registered above either way, so the authority still learns
    // what was observed; the throw is what tells the pipeline that nothing
    // was effected, so it reports `DEFINITELY_NOT_EXECUTED` rather than a
    // completed execution whose own effect block says otherwise.
    if (observation.status === "FAILED") {
      throw new ProviderRefusal(observation.reason ?? "PROVIDER_REFUSED");
    }
    return executionResultOf(record);
  };

  const reconcile = async (
    context: ActionReconciliationContext<TAction>,
  ): Promise<ProviderReconciliation<AdapterExecutionResult>> => {
    const answer = await executor.reconcile({
      intent: context.intent,
      prepared: executor.prepareNow(context.parameters),
      idempotencyKey: context.idempotencyKey,
      scope: null,
      providerReference: null,
    });
    if (answer.status !== "COMPLETED") return { status: answer.status };
    return { status: "COMPLETED", result: executionResultOf(answer.result.record) };
  };

  return { parametersSchema: options.schema, execute, reconcile };
}

/** What the executor reports about a committed attempt, from its effect record. */
function executionResultOf(record: RegisteredEffect): AdapterExecutionResult {
  return {
    outcome: "COMMITTED",
    confirmation: record.confirmation,
    comparison: record.comparison,
    mismatchedFields: record.mismatched,
    observationMethod: record.observationMethod,
    expectedEffectDigest: record.expectedEffectDigest,
    observedEffectDigest: record.observedEffectDigest,
    responseDigest: record.responseDigest,
    providerReference: record.providerReference,
    evidenceDigest: record.evidenceDigest,
    reasonCodes: record.reasonCodes,
    receiptComparison: record.receipt.comparison,
    receiptStatus: record.receipt.status,
  };
}

/**
 * How an adapter with no description of its own reads as an intent: its
 * effect's action type and resource, the action itself as the parameters,
 * and the canonical action's digest as the retry identity. The registry path
 * never asks, because the intent was captured before the handler ran; a
 * family that is submitted to the runner directly describes itself.
 */
export function describeByEffect<TAction>(
  action: TAction,
  prepared: EffectPreparedAction,
): ActionDescription {
  return {
    proposal: {
      action: prepared.actionType.toLowerCase(),
      target: prepared.resourceRef,
      parameters: action as unknown as JsonObject,
    },
    downstreamTarget: { system: prepared.domain.toLowerCase(), operation: prepared.effectType },
    idempotencyKey: prepared.intentDigest,
    facts: {},
  };
}

/** The effect block a response carries, from the handler's own result. */
export function effectBlock(result: unknown): JsonObject | null {
  if (typeof result !== "object" || result === null) return null;
  const candidate = result as Partial<AdapterExecutionResult>;
  if (typeof candidate.evidenceDigest !== "string") return null;
  return {
    outcome: candidate.outcome ?? null,
    confirmation: candidate.confirmation ?? null,
    comparison: candidate.comparison ?? null,
    mismatched_fields: [...(candidate.mismatchedFields ?? [])],
    observation_method: candidate.observationMethod ?? null,
    expected_effect_digest: candidate.expectedEffectDigest ?? null,
    observed_effect_digest: candidate.observedEffectDigest ?? null,
    response_digest: candidate.responseDigest ?? null,
    provider_reference: candidate.providerReference ?? null,
    evidence_digest: candidate.evidenceDigest,
    reason_codes: [...(candidate.reasonCodes ?? [])],
    receipt_comparison: candidate.receiptComparison ?? null,
    receipt_status: candidate.receiptStatus ?? null,
  };
}
