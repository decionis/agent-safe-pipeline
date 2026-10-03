import type { JsonObject } from "@decionis/agent-safe-pipeline";
import type { AdapterExecutionResult } from "../AdapterActionHandler.js";
import type { PreparedAction, ProviderResult } from "../EffectAdapter.js";
import { buildEffectRecord } from "../EffectEvidenceBuilder.js";
import type { RegisteredEffect } from "../EffectEvidenceRegister.js";
import { jcsDigest } from "../JcsDigest.js";
import {
  CARD_PURCHASE_ACTION,
  cardTarget,
  type CardAuthorizationRequest,
  type CardAuthorizationResult,
  type CardPurchase,
} from "./CardPurchase.js";

export const CARD_EFFECT_TYPE = "CARD_PURCHASE_AUTHORIZATION";

/**
 * What a card purchase asks for, as a projection the authority binds its
 * grant to: this card, at this merchant (and category, when one was named),
 * in this currency, for at most this amount. The amount is a ceiling, which
 * is why the field says so: an issuer may authorise less than was approved,
 * and an authorization that stayed inside the ceiling is the authorised
 * effect, exactly.
 */
export function cardExpectedEffect(purchase: CardPurchase): JsonObject {
  return {
    card_token_ref: purchase.cardTokenRef,
    merchant_id: purchase.merchantId,
    ...(purchase.mcc === undefined ? {} : { mcc: purchase.mcc }),
    currency: purchase.currency,
    amount_minor_ceiling: purchase.amountMinor,
  };
}

/** The family's `prepare`: pure, reaching nothing, and the digests the intent is bound to. */
export function prepareCardPurchase(purchase: CardPurchase): PreparedAction {
  const expectedEffect = cardExpectedEffect(purchase);
  return {
    expectedEffect,
    expectedEffectDigest: jcsDigest(expectedEffect),
    intentDigest: jcsDigest(purchase as JsonObject),
    requestDigest: jcsDigest(purchase as JsonObject),
    resourceRef: cardTarget(purchase),
    effectType: CARD_EFFECT_TYPE,
    domain: "CARDS",
    actionType: CARD_PURCHASE_ACTION,
  };
}

export interface CardResultInput {
  readonly purchase: CardPurchase;
  readonly prepared: PreparedAction;
  readonly authorization: CardAuthorizationRequest;
  readonly result: CardAuthorizationResult;
  /** The claim's lease had closed when the result arrived: nothing about it can be recorded as known. */
  readonly leaseExpired: boolean;
  readonly observer: { readonly id: string; readonly version: string };
  readonly correlationId: string;
  readonly idempotencyKey: string;
  readonly observedAt: string;
}

/**
 * The effect record for one card authorization, from what the issuer said
 * about it. An approval is observed as the issuer stated it: the card,
 * merchant, category and currency of the authorization it matched, and the
 * ceiling, which held if the approved amount is at or below it and is the
 * approved amount itself if it is not, so an issuer that approved more than
 * was authorised is a mismatch on exactly that field. A decline is a
 * refusal, and a result after the lease is indeterminate whatever it says,
 * because the authority stopped accepting a commit for this claim.
 */
export function cardResultRecord(input: CardResultInput): RegisteredEffect {
  const { purchase, authorization, result } = input;
  const responseDigest = jcsDigest(result as JsonObject);
  const common = {
    observer: input.observer,
    correlationId: input.correlationId,
    idempotencyKey: input.idempotencyKey,
    observedAt: input.observedAt,
    prepared: input.prepared,
  };
  if (input.leaseExpired) {
    return buildEffectRecord({
      ...common,
      result: null,
      indeterminate: { reason: "CLAIM_LEASE_EXPIRED", providerStatus: result.status },
    });
  }
  const answered = {
    providerStatus: result.status,
    providerReference: authorization.authorization_id,
    responseDigest,
    observationMethod: "EVENT_CONFIRMATION",
    providerGenerated: true,
    source: "ISSUER_AUTHORIZATION_RESULT",
  } as const;
  if (result.status === "DECLINED") {
    const declined: ProviderResult = {
      ...answered,
      status: "FAILED",
      failureReason: "ISSUER_DECLINED",
      observed: null,
    };
    return buildEffectRecord({ ...common, result: declined });
  }
  const approved = result.approved_amount_minor ?? authorization.amount_minor;
  const approval: ProviderResult = {
    ...answered,
    status: "COMMITTED",
    failureReason: null,
    observed: {
      card_token_ref: authorization.card_token_ref,
      merchant_id: authorization.merchant_id,
      ...(purchase.mcc === undefined ? {} : { mcc: authorization.mcc ?? null }),
      currency: authorization.currency,
      amount_minor_ceiling: approved <= purchase.amountMinor ? purchase.amountMinor : approved,
    },
  };
  return buildEffectRecord({ ...common, result: approval });
}

/**
 * The record in the shape the response's effect block is read from, the
 * same shape an adapter's handler returns; its outcome may also be
 * `INDETERMINATE`, which a handler reports by throwing instead.
 */
export function cardExecutionResult(
  record: RegisteredEffect,
): Omit<AdapterExecutionResult, "outcome"> & { readonly outcome: RegisteredEffect["outcome"] } {
  return {
    outcome: record.outcome,
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
