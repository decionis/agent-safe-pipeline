import type { JsonObject, JsonValue } from "../intent/JsonValue.js";
import type { VerifiedAuthorization } from "./AuthorizationVerifier.js";
import type { MonotonicDeadline } from "./ExecutionDeadline.js";
import type { Sha256Digest } from "./NativeExecutor.js";

/**
 * What an effect adapter worked out before anything left the process.
 *
 * @deprecated The dispatch-style `NativeExecutor` (`agent-safe.executors.native/1`)
 * is the contract; `@decionis/agentsafe` re-exports this as `PreparedAction`
 * for existing adapters.
 */
export interface EffectPreparedAction {
  /** The effect the action asks for, as the profile's projection of it. */
  readonly expectedEffect: JsonObject;
  readonly expectedEffectDigest: Sha256Digest;
  /** The digest of the canonical action itself, for the authority's binding. */
  readonly intentDigest: Sha256Digest;
  /** The digest of what will be sent, so a later reader can tell what was asked. */
  readonly requestDigest: Sha256Digest;
  /** The resource the effect lands on, as the profile names it. */
  readonly resourceRef: string;
  readonly effectType: string;
  readonly domain: string;
  readonly actionType: string;
}

/** What the provider said, as the adapter read it. Never a body, never a credential. */
export interface ProviderResult {
  readonly status: "COMMITTED" | "FAILED";
  readonly providerStatus: string | null;
  readonly providerReference: string | null;
  readonly responseDigest: Sha256Digest | null;
  /** A profile reason code when the provider refused; null when it accepted. */
  readonly failureReason: string | null;
  /** The observed effect as the adapter could read it, or null when it could not. */
  readonly observed: JsonObject | null;
  readonly observationMethod: ObservationMethod;
  readonly providerGenerated: boolean;
  readonly source: string;
  /**
   * The provider's effect receipt (VP-3), verbatim, when its answer carried
   * one in `x-agent-safe-effect-receipt`. Forwarded to the authority
   * unread; its statement is compared with this executor's own account.
   */
  readonly receipt?: string | null;
}

export type ObservationMethod =
  | "DOWNSTREAM_ACK"
  | "READ_AFTER_WRITE"
  | "EVENT_CONFIRMATION"
  | "STATE_RECONCILIATION"
  | "SIGNED_RECEIPT"
  | "EXTERNAL_ATTESTATION"
  | "HUMAN_VALIDATION";

/**
 * A provider that neither committed nor refused. Thrown from `execute`
 * after the request left the process, so the runner reports an unknown
 * outcome and nothing interprets silence as success.
 *
 * A provider can answer an indeterminate status with its signed receipt of
 * the effect all the same. `receipt` carries it to the finalization, where
 * the authority verifies it, instead of it being dropped with the answer.
 */
export class IndeterminateOutcome extends Error {
  public constructor(
    public readonly reason: string,
    public readonly providerStatus: string | null = null,
    public readonly receipt: string | null = null,
  ) {
    super(reason);
    this.name = "IndeterminateOutcome";
  }
}

export interface AdapterExecution<TAction> {
  readonly action: TAction;
  readonly prepared: EffectPreparedAction;
  readonly authorization: VerifiedAuthorization;
  readonly idempotencyKey: string;
  /** The budget left for this dispatch: the smaller of the timeout and the grant. */
  readonly deadline: MonotonicDeadline;
}

export interface AdapterReconciliation {
  readonly idempotencyKey: string;
  readonly providerReference: string | null;
  readonly intentHash: string;
  readonly prepared: EffectPreparedAction;
}

export type ProviderReconciliationResult =
  | { readonly status: "COMPLETED"; readonly result: ProviderResult }
  | { readonly status: "NOT_EXECUTED" }
  | { readonly status: "UNKNOWN" };

/**
 * The first contract for a family of consequential actions: four small
 * methods, three of them pure. It is the dispatch style of
 * `agent-safe.executors.native/1` under its earlier name, and
 * `@decionis/agentsafe`'s `EffectAdapterExecutor` runs any implementation of
 * it as a dispatch-style `NativeExecutor`, so an adapter written against it
 * keeps working unchanged.
 *
 * - `prepare` works out what the action asks for and what its effect should
 *   be. It reaches nothing and may be called before the authority is asked.
 * - `execute` performs the side effect, once, inside the dispatch the
 *   pipeline opened. A provider that neither committed nor refused is an
 *   `IndeterminateOutcome`, never a guess.
 * - `observeEffect` reads what the provider said into the profile's
 *   projection. Pure: no second call, no interpretation of silence.
 * - `reconcile` asks the provider what it did with an idempotency key,
 *   read-only, and may never initiate anything.
 *
 * @deprecated Implement `NativeExecutor` with `style: "dispatch"`. This
 * interface stays, unchanged, for the adapters already written against it.
 */
export interface EffectAdapter<TAction> {
  readonly id: string;
  readonly version: string;
  /** The transport action names this adapter answers for. */
  readonly actionTypes: readonly string[];
  prepare(action: TAction): EffectPreparedAction;
  execute(execution: AdapterExecution<TAction>): Promise<ProviderResult>;
  observeEffect(result: ProviderResult, prepared: EffectPreparedAction): JsonObject | null;
  reconcile(context: AdapterReconciliation): Promise<ProviderReconciliationResult>;
}

/** A value the projection can hold, narrowed for comparison. */
export type ProjectionValue = JsonValue;
