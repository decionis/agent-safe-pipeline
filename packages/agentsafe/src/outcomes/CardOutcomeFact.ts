import { z } from "zod";

export const CARD_OUTCOME_FACT_VERSION = "agent-safe.card-outcome/1" as const;

const identifier = z.string().min(1).max(200);
const instant = z.string().datetime({ offset: true }).max(40);
const reasonCodes = z.array(z.string().min(1).max(200)).max(50);
const verdict = z.enum(["ALLOW", "ESCALATE", "BLOCK"]);
const decisionIds = {
  decision_id: identifier.nullable(),
  dossier_id: identifier.nullable(),
};

/**
 * What the cards family records about one card purchase, one fact per step, for the outcome
 * evidence producer to read later: the decision, a person's answer to an escalation, the
 * issuer's authorization claiming the grant, and the issuer's result. Each fact names the
 * purchase by its intent id. Identifiers, codes, times and the amount at decision time only:
 * never a card reference, a merchant, an authorization id, a token or an attestation, so what
 * the producer reads cannot carry card data into what it states.
 *
 * - `DECIDED`: the first decision an intent was given, in enforcement or in shadow, with the
 *   amount the purchase named and, when a grant was held for the issuer, until when.
 * - `RESUMED`: a fresh decision on an open escalation, after a presence provider's attestation
 *   (a cardholder's tap) or a Presence answer. Only an `ALLOW` or a `BLOCK` is recorded; a
 *   ceremony still pending changes nothing.
 * - `CLAIMED`: the issuer's authorization matched the hold and claimed its grant.
 * - `SETTLED`: what the issuer said it did with that authorization.
 */
export const CardOutcomeFactSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    version: z.literal(CARD_OUTCOME_FACT_VERSION),
    kind: z.literal("DECIDED"),
    at: instant,
    intent_id: identifier,
    tenant_id: z.string().uuid(),
    mode: z.enum(["ENFORCEMENT", "SHADOW"]),
    verdict,
    ...decisionIds,
    reason_codes: reasonCodes,
    /** The held grant's expiry; null when no grant was held for the issuer. */
    held_until: instant.nullable(),
    /** The intent's own expiry: nothing can be claimed for it afterwards. */
    expires_at: instant,
    currency: z.string().regex(/^[A-Z]{3}$/),
    amount_minor: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  }),
  z.strictObject({
    version: z.literal(CARD_OUTCOME_FACT_VERSION),
    kind: z.literal("RESUMED"),
    at: instant,
    intent_id: identifier,
    via: z.enum(["ATTESTATION", "PRESENCE"]),
    verdict: z.enum(["ALLOW", "BLOCK"]),
    ...decisionIds,
    reason_codes: reasonCodes,
    held_until: instant.nullable(),
  }),
  z.strictObject({
    version: z.literal(CARD_OUTCOME_FACT_VERSION),
    kind: z.literal("CLAIMED"),
    at: instant,
    intent_id: identifier,
    grant_id: identifier,
  }),
  z.strictObject({
    version: z.literal(CARD_OUTCOME_FACT_VERSION),
    kind: z.literal("SETTLED"),
    at: instant,
    intent_id: identifier,
    outcome: z.enum(["COMMITTED", "FAILED", "INDETERMINATE"]),
    /** The digest of the effect record the grant was finalized with. */
    receipt_digest: z
      .string()
      .regex(/^sha256:[0-9a-f]{64}$/)
      .nullable(),
  }),
]);

export type CardOutcomeFact = z.infer<typeof CardOutcomeFactSchema>;
export type CardOutcomeFactKind = CardOutcomeFact["kind"];
export type DecidedCardFact = Extract<CardOutcomeFact, { readonly kind: "DECIDED" }>;
export type ResumedCardFact = Extract<CardOutcomeFact, { readonly kind: "RESUMED" }>;
export type ClaimedCardFact = Extract<CardOutcomeFact, { readonly kind: "CLAIMED" }>;
export type SettledCardFact = Extract<CardOutcomeFact, { readonly kind: "SETTLED" }>;
