import { z } from "zod";

export const BEAP_PROFILE = "decionis.beap/v0.1";

/** The identifier shape the profile uses for every registered name. */
const identifier = z.string().regex(/^[A-Z][A-Z0-9_]{1,63}$/);
const reference = z.string().min(1).max(500);
const sha256 = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const currency = z.string().regex(/^[A-Z]{3}$/);
/**
 * The wire form of an amount: a decimal string. A JSON number is refused by
 * this schema, not merely discouraged, so a float never reaches the
 * canonicaliser and `1e3`, `-0` and `250000.00000000000000001` cannot become
 * an amount the authority signed something else about. The scale rule is the
 * currency's, and `Money` enforces it.
 */
const decimalAmount = z.string().regex(/^(0|[1-9]\d{0,27})(\.\d{1,18})?$/);

const entity = z.strictObject({ type: identifier, ref: reference });

/** A scalar parameter: the profile allows a string, a number, a boolean, or null. */
const parameterValue = z.union([z.string().max(500), z.number(), z.boolean(), z.null()]);

export const BankingActionSchema = z.strictObject({
  profile: z.literal(BEAP_PROFILE),
  domain: identifier,
  action: z.strictObject({ type: identifier, request_id: reference }),
  actor: z.strictObject({
    type: z.enum([
      "HUMAN",
      "APPLICATION",
      "AGENT",
      "SERVICE",
      "WORKFLOW",
      "BATCH_PROCESS",
      "MIDDLEWARE",
      "SYSTEM",
    ]),
    id: reference,
    runtime: reference.optional(),
  }),
  principal: z.strictObject({
    type: z.enum(["PERSON", "ORGANIZATION", "ORGANIZATIONAL_FUNCTION", "SERVICE"]),
    id: reference,
  }),
  subject: entity.optional(),
  target: entity,
  financial_context: z.strictObject({ amount: decimalAmount, currency }).optional(),
  requested_effect: z.strictObject({
    operation: identifier,
    source_ref: reference.optional(),
    destination_ref: reference.optional(),
    parameters: z
      .record(z.string().regex(/^[a-z][a-z0-9_]{0,63}$/), parameterValue)
      .refine((value) => Object.keys(value).length <= 64, { message: "too many parameters" })
      .optional(),
  }),
  downstream: z.strictObject({
    provider: identifier,
    product: identifier.optional(),
    operation: identifier,
    environment: identifier.optional(),
  }),
  batch: z
    .strictObject({
      manifest_digest: sha256,
      item_count: z.number().int().min(1),
      source_file_digest: sha256,
    })
    .optional(),
  evidence_refs: z
    .array(z.strictObject({ kind: identifier, ref: reference, digest: sha256.optional() }))
    .max(100),
});

export type BankingAction = z.infer<typeof BankingActionSchema>;

/**
 * The profile's own conditional rule: releasing a batch requires the batch
 * block and the amount, because a release with neither is not a release of
 * anything. Expressed here rather than left to the JSON schema, since this
 * is the schema the runtime uses.
 */
export const BankingActionWireSchema = BankingActionSchema.superRefine((action, context) => {
  if (action.action.type !== "RELEASE_PAYMENT_BATCH") return;
  if (action.batch === undefined) {
    context.addIssue({ code: "custom", path: ["batch"], message: "required for a batch release" });
  }
  if (action.financial_context === undefined) {
    context.addIssue({
      code: "custom",
      path: ["financial_context"],
      message: "required for a batch release",
    });
  }
});

/** The action name the transport carries for a BEAP action, per Appendix B.5. */
export function transportActionName(action: BankingAction): string {
  return `beap.${action.domain.toLowerCase()}.${action.action.type.toLowerCase()}`;
}

/** The transport target, per Appendix B.5: the entity's type and reference. */
export function transportTarget(action: BankingAction): string {
  return `${action.target.type.toLowerCase()}:${action.target.ref}`;
}

/** Whether a transport action name belongs to the banking family at all. */
export function isBankingActionName(action: string): boolean {
  return action.startsWith("beap.");
}
