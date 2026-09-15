import type { JsonObject } from "@decionis/agent-safe-pipeline";
import { jcsDigest, type Sha256 } from "../JcsDigest.js";
import type {
  AdapterExecution,
  AdapterReconciliation,
  EffectAdapter,
  PreparedAction,
  ProviderReconciliationResult,
  ProviderResult,
} from "../EffectAdapter.js";
import { BEAP_PROFILE, transportActionName, type BankingAction } from "./BankingAction.js";
import { expectedEffect, registeredAction, REGISTERED_ACTIONS } from "./EffectProjections.js";
import { Money } from "./Money.js";
import { referenceIsValid } from "./Iban.js";

export class BankingActionError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "BankingActionError";
  }
}

/** What a banking adapter needs beyond the generic contract. */
export interface BankingTransport {
  /** Sends the action, once. Throws `IndeterminateOutcome` when nothing can be concluded. */
  execute(execution: AdapterExecution<BankingAction>): Promise<ProviderResult>;
  /** Asks what happened to an idempotency key. Read-only, always. */
  reconcile(context: AdapterReconciliation): Promise<ProviderReconciliationResult>;
}

export interface BankingAdapterOptions {
  readonly id: string;
  readonly version: string;
  readonly transport: BankingTransport;
}

/**
 * The banking family's adapter: the BEAP vocabulary over the generic
 * contract. `prepare` is where the profile's arithmetic happens and where a
 * malformed action is refused before the authority is asked:
 *
 * - the amount is read through `Money`, so a decimal whose scale is not the
 *   currency's is `AMOUNT_SCALE_INVALID` rather than a rounded number;
 * - an `iban:` reference with bad check digits is refused, because a typo
 *   that would still reach a valid-looking account is worth catching here;
 * - the action type must be one the profile registers for its domain, and
 *   the expected effect is the projection that registry names.
 *
 * The intent digest is taken over the canonical action exactly as received,
 * which is what the authority signs its binding against, and the
 * expected-effect digest over the projection, which is what an observation
 * is later compared to.
 */
export class BankingAdapter implements EffectAdapter<BankingAction> {
  public readonly id: string;
  public readonly version: string;

  public constructor(private readonly options: BankingAdapterOptions) {
    this.id = options.id;
    this.version = options.version;
  }

  /** Every transport name the profile's registered actions produce. */
  public get actionTypes(): readonly string[] {
    return registeredActionNames();
  }

  public prepare(action: BankingAction): PreparedAction {
    if (action.profile !== BEAP_PROFILE) throw new BankingActionError("BANKING_PROFILE_UNKNOWN");
    const registered = registeredAction(action.domain, action.action.type);
    // The amount is arithmetic, not text: reading it through Money refuses a
    // scale the currency does not have before anything is hashed.
    if (action.financial_context !== undefined) {
      Money.fromDecimal(action.financial_context.amount, action.financial_context.currency);
    }
    for (const reference of [
      action.requested_effect.source_ref,
      action.requested_effect.destination_ref,
      action.target.ref,
    ]) {
      if (reference !== undefined && !referenceIsValid(reference)) {
        throw new BankingActionError("BANKING_REFERENCE_INVALID");
      }
    }
    const projection = expectedEffect(action);
    return {
      expectedEffect: projection,
      expectedEffectDigest: jcsDigest(projection),
      intentDigest: jcsDigest(action as unknown as JsonObject),
      requestDigest: jcsDigest(action.requested_effect as unknown as JsonObject),
      resourceRef: action.target.ref,
      effectType: registered.effectType,
      domain: action.domain,
      actionType: action.action.type,
    };
  }

  public async execute(execution: AdapterExecution<BankingAction>): Promise<ProviderResult> {
    return await this.options.transport.execute(execution);
  }

  /**
   * The observation, as the profile's projection. Only a provider that
   * returned the effect's own fields can produce one; an acknowledgement
   * carries none, and none is invented for it.
   */
  public observeEffect(result: ProviderResult, prepared: PreparedAction): JsonObject | null {
    if (result.observed === null) return null;
    const observed: JsonObject = {};
    for (const field of Object.keys(prepared.expectedEffect)) {
      const value = result.observed[field];
      if (value !== undefined) observed[field] = value;
    }
    return observed;
  }

  public async reconcile(context: AdapterReconciliation): Promise<ProviderReconciliationResult> {
    return await this.options.transport.reconcile(context);
  }

  /** The digest of an action, for a caller that wants it without preparing. */
  public static intentDigest(action: BankingAction): Sha256 {
    return jcsDigest(action as unknown as JsonObject);
  }
}

/** The transport names of every action this build registers. */
export function registeredActionNames(): readonly string[] {
  return REGISTERED_TRANSPORT_NAMES;
}

const REGISTERED_TRANSPORT_NAMES: readonly string[] = REGISTERED_ACTIONS.map(
  (entry) => `beap.${entry.domain.toLowerCase()}.${entry.type.toLowerCase()}`,
);

export { transportActionName };
