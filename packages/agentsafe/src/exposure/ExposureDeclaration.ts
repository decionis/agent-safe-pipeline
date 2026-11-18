import { z } from "zod";

/**
 * The action types a cumulative limit may name, as the Decionis exposure
 * ledger names them (`COMMERCE_EXPOSURE_ACTION_TYPES`). A route that releases
 * money states one of these; `PAYMENT_RELEASE` unless it says otherwise.
 */
export const EXPOSURE_ACTION_TYPES = [
  "PRICE_CHANGE",
  "INVENTORY_MUTATION",
  "ORDER_ACCEPTANCE",
  "FULFILLMENT_ACTION",
  "PROMOTION_CHANGE",
  "REFUND_REQUEST",
  "RETURN_AUTHORIZATION",
  "PAYMENT_RELEASE",
  "VENDOR_BANK_CHANGE",
  "EARLY_PAYMENT_DISCOUNT",
  "CREDIT_HOLD_RELEASE",
] as const;
export type ExposureActionType = (typeof EXPOSURE_ACTION_TYPES)[number];
export const DEFAULT_EXPOSURE_ACTION_TYPE: ExposureActionType = "PAYMENT_RELEASE";

/**
 * The subjects a route can name, beside `org`, which every route supplies:
 * the organisation is the gateway's own tenant.
 */
export const EXPOSURE_ROUTE_SUBJECTS = ["vendor", "customer", "sku", "agent"] as const;
export type ExposureRouteSubject = (typeof EXPOSURE_ROUTE_SUBJECTS)[number];

/** How a route's amount is written: integer minor units, or a decimal in the currency's major unit. */
export type ExposureAmountUnit = "MINOR" | "MAJOR";

/** RFC 6901 pointers into the request as the gateway reads it: path parameters, query, headers, JSON body. */
const REQUEST_POINTER = /^\/(?:path|query|headers|body)(?:\/\P{Cc}*)?$/u;
/** A pointer into a forwarded write's JSON answer. */
const RESPONSE_POINTER = /^\/body(?:\/\P{Cc}*)?$/u;
const CURRENCY_CODE = /^[a-z]{3}$/i;

const requestPointer = z.string().trim().min(2).max(300).regex(REQUEST_POINTER);
const lower = <T extends readonly [string, ...string[]]>(values: T) =>
  z.preprocess(
    (value) => (typeof value === "string" ? value.trim().toLowerCase() : value),
    z.enum(values),
  );

/**
 * A route's `exposure` section in `agentsafe.yaml`: the route releases money,
 * and says where in the request the amount, the currency and the subjects
 * are. The values are read from the request the authority evaluated and the
 * gateway forwards, never from a header the gateway adds.
 */
export const RouteExposureSchema = z.strictObject({
  actionType: z
    .preprocess(
      (value) => (typeof value === "string" ? value.trim().toUpperCase() : value),
      z.enum(EXPOSURE_ACTION_TYPES),
    )
    .optional(),
  amount: requestPointer,
  amountUnit: lower(["minor", "major"]).optional(),
  /** A pointer into the request, or a fixed ISO 4217 code for a route in one currency. */
  currency: z
    .string()
    .trim()
    .min(2)
    .max(300)
    .refine(
      (value) => CURRENCY_CODE.test(value) || REQUEST_POINTER.test(value),
      "an ISO 4217 code or a pointer into the request",
    ),
  subjects: z
    .strictObject({
      vendor: requestPointer.optional(),
      customer: requestPointer.optional(),
      sku: requestPointer.optional(),
      agent: requestPointer.optional(),
    })
    .optional(),
  /** Where a 2xx answer states the amount that actually moved; the reserved amount is settled without it. */
  settledAmount: z.string().trim().min(5).max(300).regex(RESPONSE_POINTER).optional(),
  /** `failClosed` (the default) refuses a payment the ledger could not be asked about. */
  failurePolicy: lower(["failclosed", "failopen"]).optional(),
});

export type RouteExposureFile = z.infer<typeof RouteExposureSchema>;

/** A route's money declaration, resolved: every default applied. */
export interface ExposureDeclaration {
  readonly actionType: ExposureActionType;
  readonly amount: string;
  readonly amountUnit: ExposureAmountUnit;
  /** A pointer (it starts with `/`) or an upper-case ISO 4217 code. */
  readonly currency: string;
  readonly subjects: Readonly<Partial<Record<ExposureRouteSubject, string>>>;
  readonly settledAmount: string | null;
  readonly failurePolicy: "FAIL_CLOSED" | "FAIL_OPEN";
}

/** The declaration a route's file section resolves to. */
export function exposureDeclaration(file: RouteExposureFile): ExposureDeclaration {
  const subjects: Partial<Record<ExposureRouteSubject, string>> = {};
  for (const kind of EXPOSURE_ROUTE_SUBJECTS) {
    const pointer = file.subjects?.[kind];
    if (pointer !== undefined) subjects[kind] = pointer;
  }
  return {
    actionType: file.actionType ?? DEFAULT_EXPOSURE_ACTION_TYPE,
    amount: file.amount,
    amountUnit: file.amountUnit === "major" ? "MAJOR" : "MINOR",
    currency: file.currency.startsWith("/") ? file.currency : file.currency.toUpperCase(),
    subjects,
    settledAmount: file.settledAmount ?? null,
    failurePolicy: file.failurePolicy === "failopen" ? "FAIL_OPEN" : "FAIL_CLOSED",
  };
}
