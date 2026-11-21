import { z } from "zod";
import { isSupportedCurrency } from "../banking/Currency.js";
import {
  cardAuthorizationOf,
  CardActionError,
  type CardAuthorizationRequest,
  type CardAuthorizationResult,
} from "../cards/CardPurchase.js";

/** The real-time event Stripe sends to the authorization endpoint and waits on. */
export const STRIPE_AUTHORIZATION_REQUEST = "issuing_authorization.request";
/** The ordinary event that says what became of an authorization, whoever decided it. */
export const STRIPE_AUTHORIZATION_CREATED = "issuing_authorization.created";

export class StripeEventError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "StripeEventError";
  }
}

/**
 * The only fields read from a Stripe event. Everything else in the payload, including the
 * cardholder's name, email, phone, billing address and the card's last four digits, is never
 * copied out: the parse below builds a fresh object from these fields and drops the rest.
 */
const EnvelopeSchema = z.object({
  id: z.string().min(1).max(255),
  type: z.string().min(1).max(100),
  livemode: z.boolean(),
  data: z.object({ object: z.unknown() }),
});

const AuthorizationSchema = z.object({
  id: z.string().min(1).max(255),
  object: z.literal("issuing.authorization"),
  livemode: z.boolean(),
  approved: z.boolean(),
  amount: z.number().int().nonnegative(),
  currency: z.string(),
  card: z.union([z.string(), z.object({ id: z.string() })]),
  merchant_data: z.object({
    category_code: z.string().nullish(),
    network_id: z.string().nullish(),
  }),
  pending_request: z.object({ amount: z.number().int(), currency: z.string() }).nullish(),
  request_history: z
    .array(
      z.object({
        amount: z.number().int(),
        currency: z.string(),
        approved: z.boolean(),
        reason: z.string().max(100),
      }),
    )
    .nullish(),
});

/** What the bridge keeps of an authorization: references, an amount, a merchant category. */
export interface StripeAuthorizationView {
  readonly eventId: string;
  readonly type: string;
  readonly livemode: boolean;
  readonly authorizationId: string;
  readonly cardId: string;
  readonly approved: boolean;
  /** The amount Stripe approved or declined, in the cardholder's currency (minor units). */
  readonly amount: number;
  readonly currency: string;
  readonly mcc: string | null;
  readonly merchantNetworkId: string | null;
  /** Present only while Stripe waits on the real-time answer. */
  readonly pending: { readonly amount: number; readonly currency: string } | null;
  /** The last decision Stripe recorded, and why: `webhook_approved`, `webhook_timeout`, ... */
  readonly lastRequest: {
    readonly amount: number;
    readonly currency: string;
    readonly approved: boolean;
    readonly reason: string;
  } | null;
}

/** Parses an event already proven to be Stripe's. Anything but an authorization is refused. */
export function stripeAuthorizationOf(body: Buffer): StripeAuthorizationView {
  let json: unknown;
  try {
    json = JSON.parse(body.toString("utf8"));
  } catch {
    throw new StripeEventError("STRIPE_EVENT_INVALID");
  }
  const envelope = EnvelopeSchema.safeParse(json);
  if (!envelope.success) throw new StripeEventError("STRIPE_EVENT_INVALID");
  const parsed = AuthorizationSchema.safeParse(envelope.data.data.object);
  if (!parsed.success) throw new StripeEventError("STRIPE_AUTHORIZATION_INVALID");
  const authorization = parsed.data;
  const history = authorization.request_history ?? [];
  const last = history.length > 0 ? history[history.length - 1]! : null;
  return {
    eventId: envelope.data.id,
    type: envelope.data.type,
    livemode: envelope.data.livemode,
    authorizationId: authorization.id,
    cardId: typeof authorization.card === "string" ? authorization.card : authorization.card.id,
    approved: authorization.approved,
    amount: authorization.amount,
    currency: authorization.currency.toUpperCase(),
    mcc: authorization.merchant_data.category_code ?? null,
    merchantNetworkId: authorization.merchant_data.network_id ?? null,
    pending:
      authorization.pending_request == null
        ? null
        : {
            amount: authorization.pending_request.amount,
            currency: authorization.pending_request.currency.toUpperCase(),
          },
    lastRequest:
      last === null
        ? null
        : {
            amount: last.amount,
            currency: last.currency.toUpperCase(),
            approved: last.approved,
            reason: last.reason,
          },
  };
}

/**
 * The issuer hook's request for an authorization: the card by Stripe's card id (an opaque
 * reference, never a card number), the merchant by its network id, the category by its MCC,
 * and the amount asked, in the cardholder's currency. `source` picks the amount: the pending
 * request while Stripe waits, or the last request in the history once it has decided.
 *
 * A zero amount (an account verification) moves no money and is not a purchase the hook can
 * evaluate; it is refused here, and the bridge's undecided rule answers for it.
 */
export function cardAuthorizationFromStripe(
  view: StripeAuthorizationView,
  source: "pending" | "history",
): CardAuthorizationRequest {
  const asked = source === "pending" ? view.pending : view.lastRequest;
  if (asked === null) throw new StripeEventError("STRIPE_AMOUNT_MISSING");
  if (asked.amount <= 0) throw new StripeEventError("STRIPE_AMOUNT_ZERO");
  if (!isSupportedCurrency(asked.currency)) {
    throw new StripeEventError("STRIPE_CURRENCY_UNSUPPORTED");
  }
  if (view.merchantNetworkId === null || view.merchantNetworkId.length === 0) {
    throw new StripeEventError("STRIPE_MERCHANT_UNIDENTIFIED");
  }
  const request = {
    authorization_id: view.authorizationId,
    card_token_ref: view.cardId,
    amount_minor: asked.amount,
    currency: asked.currency,
    merchant_id: view.merchantNetworkId,
    ...(view.mcc !== null && /^\d{4}$/.test(view.mcc) ? { mcc: view.mcc } : {}),
  };
  try {
    // The hook's own schema, PAN refusal included: the bridge sends nothing it would refuse.
    return cardAuthorizationOf(request);
  } catch (error) {
    if (error instanceof CardActionError) throw new StripeEventError(`STRIPE_${error.code}`);
    throw error;
  }
}

/** What Stripe did with an authorization, as the hook's result route records it. */
export function cardResultFromStripe(view: StripeAuthorizationView): CardAuthorizationResult {
  if (!view.approved) return { status: "DECLINED" };
  return view.amount > 0
    ? { status: "APPROVED", approved_amount_minor: view.amount }
    : { status: "APPROVED" };
}
