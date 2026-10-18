import { IndeterminateOutcome } from "@decionis/agent-safe-pipeline";
import type {
  AgentProposal,
  AuthorityEffectEvidence,
  ClaimedExecution,
  DownstreamTarget,
  EffectAdapter,
  EffectObservation,
  EffectPreparedAction,
  ExecutionCapability,
  ExecutionEffect,
  ExecutorScope,
  JsonObject,
  NativeExecutor,
  PlatformId,
  PreparedAction,
  ProviderResult,
  ReconcileContext,
  ReconcileResult,
} from "@decionis/agent-safe-pipeline";
import { authorityEffectEvidence, buildEffectRecord } from "./EffectEvidenceBuilder.js";
import type { RegisteredEffect } from "./EffectEvidenceRegister.js";

/** How an adapter's action is described to the authority: what `prepare` binds beyond the effect. */
export interface ActionDescription {
  readonly proposal: AgentProposal;
  readonly downstreamTarget: DownstreamTarget;
  readonly idempotencyKey: string;
  readonly facts: JsonObject;
}

export interface EffectAdapterExecutorOptions<TAction> {
  readonly adapter: EffectAdapter<TAction>;
  readonly platform: PlatformId;
  /** How the action reads as an intent; the adapter itself only knows its effect. */
  readonly describe: (action: TAction, prepared: EffectPreparedAction) => ActionDescription;
  /** What the connection can execute; absent, every action type is stated as live. */
  readonly capabilities?: (scope: ExecutorScope) => Promise<readonly ExecutionCapability[]>;
  readonly clock?: () => Date;
}

/** What the adapter's dispatch left for `observe`: everything the effect record is built from. */
export interface AdapterDispatchReceipt {
  readonly prepared: EffectPreparedAction;
  readonly result: ProviderResult | null;
  readonly indeterminate: {
    readonly reason: string;
    readonly providerStatus: string | null;
  } | null;
  readonly correlationId: string;
  readonly idempotencyKey: string;
}

/** What `observe` reads a dispatch as: the effect record, and the attempt it was observed for. */
export interface AdapterObservation {
  readonly record: RegisteredEffect;
  readonly indeterminate: AdapterDispatchReceipt["indeterminate"];
  readonly correlationId: string;
}

/**
 * Any `EffectAdapter` as a dispatch-style `NativeExecutor`
 * (`agent-safe.executors.native/1`): the adapter keeps its four methods and
 * this class says them in the contract's terms. `prepare` is the adapter's,
 * plus how the action reads as an intent; `execute` is the adapter's write,
 * inside the dispatch the caller opened and within its deadline; `observe`
 * is the adapter's projection turned into the effect record, field by field
 * against what was authorised; `reconcile` is the adapter's read-only
 * lookup, complete only on a matching read-back.
 *
 * The record is evidence, so it rides on the observation for whoever
 * finalizes the grant — the runtime registers it for its verifier — and its
 * wire form rides as `evidence` for a runner that finalizes directly.
 */
export class EffectAdapterExecutor<TAction> implements NativeExecutor<
  TAction,
  AdapterDispatchReceipt,
  AdapterObservation
> {
  public readonly platform: PlatformId;
  public readonly version: string;
  public readonly style = "dispatch" as const;
  private readonly clock: () => Date;
  /** The adapter's own preparation of each prepared action, so a write never prepares twice. */
  private readonly effects = new WeakMap<PreparedAction, EffectPreparedAction>();

  public constructor(private readonly options: EffectAdapterExecutorOptions<TAction>) {
    this.platform = options.platform;
    this.version = options.adapter.version;
    this.clock = options.clock ?? ((): Date => new Date());
  }

  public get actionTypes(): readonly string[] {
    return this.options.adapter.actionTypes;
  }

  /** The adapter's observer identity, as the effect record and the authority name it. */
  public get observer(): { readonly id: string; readonly version: string } {
    return { id: this.options.adapter.id, version: this.options.adapter.version };
  }

  public async capabilities(scope: ExecutorScope): Promise<readonly ExecutionCapability[]> {
    if (this.options.capabilities !== undefined) return await this.options.capabilities(scope);
    return this.actionTypes.map((actionType) => ({
      platform: this.platform,
      actionType,
      enabled: true,
      scopeGranted: true,
      connected: true,
      requirement: "",
    }));
  }

  public async prepare(action: TAction): Promise<PreparedAction> {
    return await Promise.resolve(this.prepareNow(action));
  }

  /** `prepare`, synchronously: the adapter reaches nothing, so neither does this. */
  public prepareNow(action: TAction): PreparedAction {
    const effect = this.options.adapter.prepare(action);
    const description = this.options.describe(action, effect);
    const prepared: PreparedAction = Object.freeze({
      actionType: description.proposal.action,
      proposal: description.proposal,
      downstreamTarget: description.downstreamTarget,
      idempotencyKey: description.idempotencyKey,
      expectedEffectDigest: effect.expectedEffectDigest,
      requestDigest: effect.requestDigest,
      facts: description.facts,
    });
    this.effects.set(prepared, effect);
    return prepared;
  }

  /**
   * The adapter's write, once, inside the caller's dispatch. A provider that
   * neither committed nor refused is carried as indeterminate, with any
   * receipt it gave; any other error after the dispatch began propagates, so
   * the caller reports an outcome nobody knows.
   */
  public async execute(
    run: ClaimedExecution<TAction>,
  ): Promise<ExecutionEffect<AdapterDispatchReceipt>> {
    const prepared = this.effectOf(run.prepared, run.action);
    let result: ProviderResult | null = null;
    let indeterminate: AdapterDispatchReceipt["indeterminate"] = null;
    let indeterminateReceipt: string | null = null;
    try {
      result = await run.dispatch.run(
        async () =>
          await this.options.adapter.execute({
            action: run.action,
            prepared,
            authorization: run.authorization,
            idempotencyKey: run.dispatch.idempotencyKey,
            deadline: run.deadline,
          }),
      );
    } catch (error) {
      if (!(error instanceof IndeterminateOutcome)) throw error;
      indeterminate = { reason: error.reason, providerStatus: error.providerStatus };
      indeterminateReceipt = error.receipt;
    }
    const signedReceipt = result?.receipt ?? indeterminateReceipt;
    return {
      kind: "DISPATCHED",
      receipt: {
        prepared,
        result,
        indeterminate,
        correlationId: run.intent.intent.intentId,
        idempotencyKey: run.dispatch.idempotencyKey,
      },
      signedReceipt: typeof signedReceipt === "string" ? signedReceipt : null,
    };
  }

  /**
   * The provider's answer as the effect record: the adapter's projection,
   * compared with what was authorised. An outcome nobody can determine stays
   * undetermined; a provider that was reached and said no is a refusal, not
   * a success whose effect block says otherwise.
   */
  public async observe(
    effect: ExecutionEffect<AdapterDispatchReceipt>,
  ): Promise<EffectObservation<AdapterObservation>> {
    if (effect.kind !== "DISPATCHED" || effect.receipt === null) {
      return await Promise.resolve({ status: "INDETERMINATE", reason: null, result: null });
    }
    const dispatch = effect.receipt;
    const observed =
      dispatch.result === null
        ? null
        : this.options.adapter.observeEffect(dispatch.result, dispatch.prepared);
    const record = buildEffectRecord({
      prepared: dispatch.prepared,
      result: dispatch.result === null ? null : { ...dispatch.result, observed },
      ...(dispatch.indeterminate === null ? {} : { indeterminate: dispatch.indeterminate }),
      observer: this.observer,
      correlationId: dispatch.correlationId,
      idempotencyKey: dispatch.idempotencyKey,
      observedAt: this.clock().toISOString(),
    });
    const observation: AdapterObservation = {
      record,
      indeterminate: dispatch.indeterminate,
      correlationId: dispatch.correlationId,
    };
    const evidence = this.evidenceOf(record, dispatch.correlationId);
    if (dispatch.indeterminate !== null) {
      return { status: "INDETERMINATE", reason: null, result: observation, evidence };
    }
    if (record.outcome === "FAILED") {
      return {
        status: "FAILED",
        reason: record.reasonCodes[0] ?? "PROVIDER_REFUSED",
        result: observation,
        evidence,
      };
    }
    return { status: "COMMITTED", reason: null, result: observation, evidence };
  }

  /**
   * The adapter's read-only lookup. Absence of an error is not success: only
   * a read-back whose projection matches what was authorised completes a
   * reconciliation.
   */
  public async reconcile(context: ReconcileContext): Promise<ReconcileResult<AdapterObservation>> {
    const prepared = this.effectOf(
      context.prepared,
      context.prepared.proposal.parameters as unknown as TAction,
    );
    const answer = await this.options.adapter.reconcile({
      idempotencyKey: context.idempotencyKey,
      providerReference: context.providerReference,
      intentHash: context.intent.intentHash,
      prepared,
    });
    if (answer.status !== "COMPLETED") return { status: answer.status };
    const observed = this.options.adapter.observeEffect(answer.result, prepared);
    const correlationId = context.intent.intent.intentId;
    const record = buildEffectRecord({
      prepared,
      result: { ...answer.result, observed },
      observer: this.observer,
      correlationId,
      idempotencyKey: context.idempotencyKey,
      observedAt: this.clock().toISOString(),
    });
    if (record.comparison !== "MATCH") return { status: "UNKNOWN" };
    return {
      status: "COMPLETED",
      result: { record, indeterminate: null, correlationId },
      evidence: this.evidenceOf(record, correlationId),
    };
  }

  /** The adapter's preparation of a prepared action: remembered from `prepare`, or made again. */
  private effectOf(prepared: PreparedAction, action: TAction): EffectPreparedAction {
    return this.effects.get(prepared) ?? this.options.adapter.prepare(action);
  }

  private evidenceOf(record: RegisteredEffect, correlationId: string): AuthorityEffectEvidence {
    return authorityEffectEvidence(record, correlationId, this.observer);
  }
}
