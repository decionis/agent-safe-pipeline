import { z } from "zod";
import { reportDueAt, usagePeriod, type UsagePeriod } from "./UsagePeriod.js";

/** The JWS `typ` of the signed entitlement document. */
export const ENTITLEMENT_TYPE = "decionis-edge-entitlement+jwt";

/** How long after a period ends its report is due, when no entitlement says otherwise. */
export const DEFAULT_REPORT_DUE_DAYS = 35;

const count = z.number().int().nonnegative();

/**
 * The entitlement's claims (Edge evaluator phase 4, section 2). Claims this
 * host does not read are allowed, so Decionis can add one without breaking
 * a deployed executor. `volume_band` is read only for a ceiling it states.
 */
export const EntitlementClaimsSchema = z.looseObject({
  iss: z.string().min(1),
  aud: z.string().min(1),
  iat: count,
  exp: count,
  plan: z.string().min(1),
  tier: z.enum(["hosted", "dedicated", "self_managed"]),
  included_actions_per_month: count.nullable(),
  volume_band: z.unknown(),
  edge: z.boolean(),
  usage_report_due_days: count,
});

export type EntitlementClaims = z.infer<typeof EntitlementClaimsSchema>;

/**
 * What the host could establish about the entitlement before evaluating it:
 * none to read, or one read whose claims are those its signature verified,
 * and null when the signature did not verify.
 */
export type EntitlementState =
  { readonly status: "missing" } | { readonly status: "read"; readonly claims: unknown };

/**
 * Everything a licence warning can say. None of them stops or changes a
 * decision: each is a line, a security event and a metric for someone to
 * act on.
 */
export type LicenceWarning =
  | "ENTITLEMENT_MISSING"
  | "ENTITLEMENT_INVALID"
  | "ENTITLEMENT_EXPIRED"
  | "EDGE_NOT_ENTITLED"
  | "INCLUDED_ACTIONS_EXCEEDED"
  | "VOLUME_BAND_EXCEEDED"
  | "USAGE_REPORT_KEY_MISSING"
  | "USAGE_REPORT_OVERDUE";

export interface LicenceInput {
  readonly entitlement: EntitlementState;
  /** The organisation the executor decides for: the entitlement's audience. */
  readonly orgId: string;
  readonly now: number;
  /** Governed actions this month as this installation counted them: decisions not delegated. */
  readonly governed: number;
  /** Whether a usage-report key is configured; without one no report is ever made. */
  readonly reporting: boolean;
  /** Completed periods whose report has not been delivered. */
  readonly undelivered: readonly string[];
}

/** The ceiling a volume band states, when it states one as `max_actions_per_month`. */
function bandCeiling(band: unknown): number | null {
  const parsed = z.object({ max_actions_per_month: count }).safeParse(band);
  return parsed.success ? parsed.data.max_actions_per_month : null;
}

/**
 * The licence warnings that stand at `now`, in a fixed order. An entitlement
 * that is missing, or whose claims are not an entitlement for this
 * organisation, is a warning about itself and says nothing else; one that
 * verified is read in full even when expired, so every limit it states is
 * reported. A report is overdue once its period ended more than the
 * entitlement's due days ago (35 without one).
 */
export function licenceWarnings(input: LicenceInput): readonly LicenceWarning[] {
  const warnings: LicenceWarning[] = [];
  let claims: EntitlementClaims | null = null;
  if (input.entitlement.status === "missing") warnings.push("ENTITLEMENT_MISSING");
  else {
    const parsed = EntitlementClaimsSchema.safeParse(input.entitlement.claims);
    if (parsed.success && parsed.data.aud === input.orgId) claims = parsed.data;
    else warnings.push("ENTITLEMENT_INVALID");
  }
  if (claims !== null) {
    if (claims.exp * 1000 <= input.now) warnings.push("ENTITLEMENT_EXPIRED");
    if (!claims.edge) warnings.push("EDGE_NOT_ENTITLED");
    const included = claims.included_actions_per_month;
    if (included !== null && input.governed > included) {
      warnings.push("INCLUDED_ACTIONS_EXCEEDED");
    }
    const ceiling = bandCeiling(claims.volume_band);
    if (ceiling !== null && input.governed > ceiling) warnings.push("VOLUME_BAND_EXCEEDED");
  }
  if (!input.reporting) warnings.push("USAGE_REPORT_KEY_MISSING");
  const dueDays = claims?.usage_report_due_days ?? DEFAULT_REPORT_DUE_DAYS;
  const overdue = input.undelivered.some((period) => {
    const parsed = usagePeriod(period) as UsagePeriod;
    return reportDueAt(parsed, dueDays) <= input.now;
  });
  if (overdue) warnings.push("USAGE_REPORT_OVERDUE");
  return warnings;
}
