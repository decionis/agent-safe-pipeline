/** A held grant, as the matcher sees it: what was authorised, until when, and whether it is spent. */
export interface HeldCardGrantView {
  readonly cardTokenRef: string;
  readonly amountMinor: number;
  readonly currency: string;
  readonly merchantId: string;
  /** The merchant category the purchase named, or null when it named none. */
  readonly mcc: string | null;
  readonly expiresAtMs: number;
  /** True once an authorization has matched it, whatever happened next. */
  readonly used: boolean;
}

/** An authorization, as the matcher sees it. */
export interface CardAuthorizationView {
  readonly cardTokenRef: string;
  readonly amountMinor: number;
  readonly currency: string;
  readonly merchantId: string;
  readonly mcc: string | null;
}

export type CardNoMatchCode =
  | "NO_GRANT"
  | "GRANT_ALREADY_USED"
  | "GRANT_EXPIRED"
  | "CARD_TOKEN_MISMATCH"
  | "CURRENCY_MISMATCH"
  | "MERCHANT_MISMATCH"
  | "MCC_MISMATCH"
  | "AMOUNT_EXCEEDS_GRANT";

export type CardMatch =
  | { readonly decision: "MATCHED" }
  | { readonly decision: "NO_MATCH"; readonly code: CardNoMatchCode };

/**
 * Whether an issuer's authorization is the purchase a held grant authorised.
 * Pure and synchronous, because it runs inside a card authorization's
 * millisecond budget: it reaches nothing and reads no clock of its own.
 *
 * Every rule is an equality or a ceiling over what the authority bound, and
 * the first that fails names the answer, in a fixed order: whether there is
 * a grant at all, whether it is still spendable, and then the purchase field
 * by field. An amount at or below the grant matches, because an issuer may
 * authorise less than was approved and never more. A merchant category is
 * only compared when the purchase named one.
 *
 * `NO_MATCH` is a statement, not a decline: what it means for the
 * authorization is the issuer's own policy.
 */
export function matchCardAuthorization(
  grant: HeldCardGrantView | undefined,
  authorization: CardAuthorizationView,
  nowMs: number,
): CardMatch {
  const code = mismatch(grant, authorization, nowMs);
  return code === null ? { decision: "MATCHED" } : { decision: "NO_MATCH", code };
}

function mismatch(
  grant: HeldCardGrantView | undefined,
  authorization: CardAuthorizationView,
  nowMs: number,
): CardNoMatchCode | null {
  if (grant === undefined) return "NO_GRANT";
  if (grant.used) return "GRANT_ALREADY_USED";
  if (nowMs >= grant.expiresAtMs) return "GRANT_EXPIRED";
  if (authorization.cardTokenRef !== grant.cardTokenRef) return "CARD_TOKEN_MISMATCH";
  if (authorization.currency !== grant.currency) return "CURRENCY_MISMATCH";
  if (authorization.merchantId !== grant.merchantId) return "MERCHANT_MISMATCH";
  if (grant.mcc !== null && authorization.mcc !== grant.mcc) return "MCC_MISMATCH";
  if (authorization.amountMinor > grant.amountMinor) return "AMOUNT_EXCEEDS_GRANT";
  return null;
}
