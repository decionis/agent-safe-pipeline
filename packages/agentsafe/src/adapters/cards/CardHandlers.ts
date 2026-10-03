import type { HandlerRegistration } from "../../handlers/HandlerRegistration.js";
import { CARD_PURCHASE_ACTION, CardPurchaseSchema } from "./CardPurchase.js";

/**
 * The registration for the cards family: `card.purchase`, whose grant the
 * executor holds on an `ALLOW` instead of running anything. The issuer
 * performs the effect, when its authorization hook asks; so this handler is
 * never dispatched, and one that somehow were would fail before dispatch
 * with the grant finalized as `FAILED`. Its parameters schema is what the
 * executor's admission checks the intent against.
 *
 * Reconciliation has no one to ask: the issuer is the system of record and
 * the executor has no read path into it, so an attempt whose result never
 * arrived stays unknown until someone who can see the issuer's ledger says.
 */
export function cardHandlers(): HandlerRegistration {
  return (context) => {
    context.registry.register(CARD_PURCHASE_ACTION, {
      parametersSchema: CardPurchaseSchema,
      execute: () => {
        throw new Error("CARD_PURCHASE_IS_HELD_NOT_RUN");
      },
      reconcile: () => ({ status: "UNKNOWN" }),
    });
    return [CARD_PURCHASE_ACTION];
  };
}
