import type {
  ActionExecutionContext,
  ActionHandler,
  ActionReconciliationContext,
  JsonObject,
  ProviderReconciliation,
} from "@decionis/agent-safe-pipeline";
import type { z } from "zod";
import { dispatchBudgetMs, MonotonicDeadline } from "../time/MonotonicClock.js";
import { IndeterminateOutcome, type EffectAdapter, type ProviderResult } from "./EffectAdapter.js";
import { buildEffectRecord } from "./EffectEvidenceBuilder.js";
import type { EffectEvidenceRegister } from "./EffectEvidenceRegister.js";

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

/**
 * The bridge from any `EffectAdapter` to the pipeline's `ActionHandler`. It
 * keeps the shape the boundary requires and adds the effect plane:
 *
 * prepare, which reaches nothing; then the side effect inside
 * `dispatch.run`, bounded by the smaller of the configured timeout and what
 * is left of the grant; then the observation, compared field by field
 * against what was authorised; then the record, registered against this
 * exact authorization for the verifier to finalize with.
 *
 * `SafeExecutor` and the pipeline's registry are untouched: a provider that
 * neither committed nor refused throws `IndeterminateOutcome` from inside
 * the dispatch, which the registry already reports as an unknown outcome,
 * and a deterministic refusal returns a result whose own outcome is
 * `FAILED`. What the pipeline calls the handler's outcome is unchanged;
 * what the effect plane says about it is separate, and that is deliberate.
 */
export function adapterActionHandler<TAction>(
  options: AdapterHandlerOptions<TAction>,
): ActionHandler<TAction, AdapterExecutionResult> {
  const clock = options.clock ?? ((): Date => new Date());
  const observer = { id: options.adapter.id, version: options.adapter.version };

  const execute = async (
    context: ActionExecutionContext<TAction>,
  ): Promise<AdapterExecutionResult> => {
    const prepared = options.adapter.prepare(context.parameters);
    const deadline = MonotonicDeadline.after(
      dispatchBudgetMs(options.timeoutMs, context.authorization),
    );
    let result: ProviderResult | null = null;
    let indeterminate: { readonly reason: string; readonly providerStatus: string | null } | null =
      null;
    try {
      result = await context.dispatch.run(
        async () =>
          await options.adapter.execute({
            action: context.parameters,
            prepared,
            authorization: context.authorization,
            idempotencyKey: context.dispatch.idempotencyKey,
            deadline,
          }),
      );
    } catch (error) {
      if (!(error instanceof IndeterminateOutcome)) throw error;
      indeterminate = { reason: error.reason, providerStatus: error.providerStatus };
    }
    const observed = result === null ? null : options.adapter.observeEffect(result, prepared);
    const record = buildEffectRecord({
      prepared,
      result: result === null ? null : { ...result, observed },
      ...(indeterminate === null ? {} : { indeterminate }),
      observer,
      correlationId: context.intent.intent.intentId,
      idempotencyKey: context.dispatch.idempotencyKey,
      observedAt: clock().toISOString(),
    });
    options.register.attach(context.authorization, record);
    if (record.comparison === "MISMATCH") options.onMismatch?.(record.mismatched);
    // An outcome nobody can determine stays undetermined: the throw is
    // re-raised so the pipeline reports an unknown outcome rather than a
    // failure or a success.
    if (indeterminate !== null) {
      throw new IndeterminateOutcome(indeterminate.reason, indeterminate.providerStatus);
    }
    return {
      outcome: record.outcome === "FAILED" ? "FAILED" : "COMMITTED",
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
    };
  };

  const reconcile = async (
    context: ActionReconciliationContext<TAction>,
  ): Promise<ProviderReconciliation<AdapterExecutionResult>> => {
    const prepared = options.adapter.prepare(context.parameters);
    const answer = await options.adapter.reconcile({
      idempotencyKey: context.idempotencyKey,
      providerReference: null,
      intentHash: context.intent.intentHash,
      prepared,
    });
    if (answer.status !== "COMPLETED") return { status: answer.status };
    const observed = options.adapter.observeEffect(answer.result, prepared);
    const record = buildEffectRecord({
      prepared,
      result: { ...answer.result, observed },
      observer,
      correlationId: context.intent.intent.intentId,
      idempotencyKey: context.idempotencyKey,
      observedAt: clock().toISOString(),
    });
    // Absence of an error is not success: only a read-back whose projection
    // matches what was authorised is a completed reconciliation.
    if (record.comparison !== "MATCH") return { status: "UNKNOWN" };
    return {
      status: "COMPLETED",
      result: {
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
      },
    };
  };

  return { parametersSchema: options.schema, execute, reconcile };
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
  };
}
