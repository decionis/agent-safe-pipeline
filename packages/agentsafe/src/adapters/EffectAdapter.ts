import type { JsonObject, JsonValue, VerifiedAuthorization } from "@decionis/agent-safe-pipeline";
import type { MonotonicDeadline } from "../time/MonotonicClock.js";
import type { Sha256 } from "./JcsDigest.js";

/** What the adapter worked out before anything left the process. */
export interface PreparedAction {
  /** The effect the action asks for, as the profile's projection of it. */
  readonly expectedEffect: JsonObject;
  readonly expectedEffectDigest: Sha256;
  /** The digest of the canonical action itself, for the authority's binding. */
  readonly intentDigest: Sha256;
  /** The digest of what will be sent, so a later reader can tell what was asked. */
  readonly requestDigest: Sha256;
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
  readonly responseDigest: Sha256 | null;
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
 * after the request left the process, so the registry reports an unknown
 * outcome and nothing interprets silence as success.
 */
export class IndeterminateOutcome extends Error {
  public constructor(
    public readonly reason: string,
    public readonly providerStatus: string | null = null,
  ) {
    super(reason);
    this.name = "IndeterminateOutcome";
  }
}

export interface AdapterExecution<TAction> {
  readonly action: TAction;
  readonly prepared: PreparedAction;
  readonly authorization: VerifiedAuthorization;
  readonly idempotencyKey: string;
  /** The budget left for this dispatch: the smaller of the timeout and the grant. */
  readonly deadline: MonotonicDeadline;
}

export interface AdapterReconciliation {
  readonly idempotencyKey: string;
  readonly providerReference: string | null;
  readonly intentHash: string;
  readonly prepared: PreparedAction;
}

export type ProviderReconciliationResult =
  | { readonly status: "COMPLETED"; readonly result: ProviderResult }
  | { readonly status: "NOT_EXECUTED" }
  | { readonly status: "UNKNOWN" };

/**
 * One contract for every family of consequential actions. It is deliberately
 * four small methods, three of them pure:
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
 * A second family is a directory beside `banking/`, not a rewrite: the
 * handler bridge, the comparison, the evidence and the verifier all work off
 * this contract alone.
 */
export interface EffectAdapter<TAction> {
  readonly id: string;
  readonly version: string;
  /** The transport action names this adapter answers for. */
  readonly actionTypes: readonly string[];
  prepare(action: TAction): PreparedAction;
  execute(execution: AdapterExecution<TAction>): Promise<ProviderResult>;
  observeEffect(result: ProviderResult, prepared: PreparedAction): JsonObject | null;
  reconcile(context: AdapterReconciliation): Promise<ProviderReconciliationResult>;
}

/** A value the projection can hold, narrowed for comparison. */
export type ProjectionValue = JsonValue;
