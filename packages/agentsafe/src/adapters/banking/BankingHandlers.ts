import type { HandlerRegistration } from "../../handlers/HandlerRegistration.js";
import { adapterActionHandler } from "../AdapterActionHandler.js";
import { BankingActionWireSchema, type BankingAction } from "./BankingAction.js";
import { BankingAdapter } from "./BankingAdapter.js";
import { CoreBankingHttpAdapter } from "./CoreBankingHttpAdapter.js";
import { REGISTERED_ACTIONS } from "./EffectProjections.js";

export interface BankingHandlerOptions {
  /** Overrides the configured identity; the configuration's is the default. */
  readonly id?: string;
  readonly version?: string;
  /** Where the effect of a posted action is read back from, by provider reference. */
  readonly lookupByReferenceUrl?: string | null;
  readonly onMismatch?: (mismatched: readonly string[]) => void;
}

/**
 * The reference registration for the banking family: every action type this
 * build mirrors from the profile, each bridged to the same adapter over the
 * configured downstream. An adopter with their own core replaces the
 * transport and keeps everything else, because the profile's arithmetic, the
 * projection, the comparison and the evidence are the adapter's, not the
 * transport's.
 *
 * The adapter's identity comes from the configuration unless a caller
 * overrides it, so the observer named in the effect record is the observer
 * the executor reports to the authority: two sources that could disagree
 * would put one attempt's observation under two names.
 */
export function bankingHandlers(options: BankingHandlerOptions = {}): HandlerRegistration {
  return (context) => {
    const register = context.effects;
    const adapter = new BankingAdapter({
      id: options.id ?? context.banking.adapterId,
      version: options.version ?? context.banking.adapterVersion,
      transport: new CoreBankingHttpAdapter({
        url: context.downstream.url,
        lookupByReferenceUrl: options.lookupByReferenceUrl ?? context.banking.lookupByReferenceUrl,
        lookupByKeyUrl: context.downstream.lookupUrl,
        credential: context.credential,
        fetch: context.fetch,
        source: "CORE_BANKING_RESPONSE",
      }),
    });
    const handler = adapterActionHandler<BankingAction>({
      adapter,
      schema: BankingActionWireSchema,
      register,
      timeoutMs: context.downstream.timeoutMs,
      ...(options.onMismatch === undefined ? {} : { onMismatch: options.onMismatch }),
    });
    const names = REGISTERED_ACTIONS.map(
      (entry) => `beap.${entry.domain.toLowerCase()}.${entry.type.toLowerCase()}`,
    );
    for (const name of names) context.registry.register(name, handler);
    return names;
  };
}
