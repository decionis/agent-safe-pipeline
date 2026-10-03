import { z } from "zod";
import { isSupportedCurrency } from "../banking/Currency.js";
import { containsPan } from "./Pan.js";

/** The one card action this family registers: a purchase the issuer will authorize later. */
export const CARD_PURCHASE_ACTION = "card.purchase";

export class CardActionError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "CardActionError";
  }
}

/**
 * A reference: a card token reference, a merchant id, an authorization id.
 * Opaque to this boundary, bounded, and in a character set no header,
 * path segment or log line has to escape.
 */
const REFERENCE = /^[\w.:-]{1,200}$/;
const CURRENCY = /^[A-Z]{3}$/;
const MCC = /^\d{4}$/;

const reference = z.string().regex(REFERENCE);
/** A card reference is a reference that is not, and does not contain, a card number. */
const cardReference = reference.refine((value) => !containsPan(value));
/** Minor units, as a JSON integer: at least one, and exact in a double. */
const minorUnits = z.number().int().positive();

/**
 * The parameters of `card.purchase`: what the agent wants to buy, with which
 * card, from whom, for at most how much. The card is named by its token
 * reference, never by its number; the amount is minor units of a currency
 * this build knows the exponent of, and it is the ceiling the issuer's
 * authorization will be matched against.
 */
export const CardPurchaseSchema = z.strictObject({
  cardTokenRef: cardReference,
  amountMinor: minorUnits,
  currency: z.string().regex(CURRENCY),
  merchantId: reference,
  mcc: z.string().regex(MCC).optional(),
});

export type CardPurchase = z.infer<typeof CardPurchaseSchema>;

/** What the issuer's real-time authorization hook asks. */
export const CardAuthorizationRequestSchema = z.strictObject({
  authorization_id: reference,
  card_token_ref: cardReference,
  amount_minor: minorUnits,
  currency: z.string().regex(CURRENCY),
  merchant_id: reference,
  mcc: z.string().regex(MCC).optional(),
});

export type CardAuthorizationRequest = z.infer<typeof CardAuthorizationRequestSchema>;

/** What the issuer says it did with an authorization it asked about. */
export const CardAuthorizationResultSchema = z.strictObject({
  status: z.enum(["APPROVED", "DECLINED"]),
  approved_amount_minor: minorUnits.optional(),
  auth_code: z
    .string()
    .regex(/^[A-Z0-9]{1,12}$/)
    .optional(),
});

export type CardAuthorizationResult = z.infer<typeof CardAuthorizationResultSchema>;

/**
 * A card number anywhere it could be read is refused under its own code,
 * before any other rule, so a caller learns that it sent one and never the
 * value: no response, record or line repeats a parameter. Whatever JSON type
 * carries it, a number written as digits is still a card number.
 */
function refusePan(value: unknown): void {
  if (containsPan(String(value))) throw new CardActionError("CARD_PAN_REFUSED");
}

/** The action as the profile reads it, or the refusal that says why not. */
export function cardPurchaseOf(parameters: unknown): CardPurchase {
  refusePan((parameters as { readonly cardTokenRef?: unknown } | null)?.cardTokenRef);
  const parsed = CardPurchaseSchema.safeParse(parameters);
  if (!parsed.success) throw new CardActionError("CARD_PURCHASE_INVALID");
  // A currency is only a number once its exponent is known; one this build lacks is refused.
  if (!isSupportedCurrency(parsed.data.currency)) {
    throw new CardActionError("CARD_CURRENCY_UNSUPPORTED");
  }
  return parsed.data;
}

/**
 * The binding between the transport and the action: the target is derived
 * from the card, so a caller describing one card and asking for another is
 * refused before the authority is asked.
 */
export function bindCardPurchase(input: {
  readonly target: string;
  readonly parameters: unknown;
}): CardPurchase {
  const purchase = cardPurchaseOf(input.parameters);
  if (input.target !== cardTarget(purchase)) throw new CardActionError("CARD_TARGET_MISMATCH");
  return purchase;
}

/** The transport target a card purchase names: the card it spends from. */
export function cardTarget(purchase: CardPurchase): string {
  return `card:${purchase.cardTokenRef}`;
}

export function cardAuthorizationOf(input: unknown): CardAuthorizationRequest {
  refusePan((input as { readonly card_token_ref?: unknown } | null)?.card_token_ref);
  const parsed = CardAuthorizationRequestSchema.safeParse(input);
  if (!parsed.success) throw new CardActionError("CARD_AUTHORIZATION_INVALID");
  return parsed.data;
}

export function cardAuthorizationResultOf(input: unknown): CardAuthorizationResult {
  const parsed = CardAuthorizationResultSchema.safeParse(input);
  if (!parsed.success) throw new CardActionError("CARD_AUTHORIZATION_RESULT_INVALID");
  return parsed.data;
}

/** An authorization id as it arrives in a path segment, held to the same rule as everywhere else. */
export function isCardReference(value: string): boolean {
  return REFERENCE.test(value);
}

export function isCardActionName(action: string): boolean {
  return action === CARD_PURCHASE_ACTION;
}
