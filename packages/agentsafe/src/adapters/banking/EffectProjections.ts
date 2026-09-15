import type { JsonObject, JsonValue } from "@decionis/agent-safe-pipeline";
import type { BankingAction } from "./BankingAction.js";

/** The registry this file mirrors, and the version of it. */
export const PROJECTION_PROFILE = "decionis.beap/v1.0";

/** Every projection begins with these, per the registry's `base_projection`. */
export const BASE_PROJECTION = ["effect_type", "domain", "action", "target"] as const;

export interface RegisteredAction {
  readonly domain: string;
  readonly type: string;
  readonly effectType: string;
  /** The fields beyond the base that this action's expected effect is made of. */
  readonly projection: readonly string[];
}

/**
 * The action types this build implements, mirrored from the profile's
 * `action-types` registry: the effect each produces and the fields its
 * expected-effect projection is made of. A test hashes the registry files
 * against the profile's own manifest and asserts every entry here equals the
 * mirror, so a drift in the profile is a failing test rather than a silent
 * disagreement. The runtime never reads `profiles/`.
 */
export const REGISTERED_ACTIONS: readonly RegisteredAction[] = [
  {
    domain: "CORPORATE_PAYMENTS",
    type: "SEND_PAYMENT",
    effectType: "PAYMENT_SENT",
    projection: [
      "amount",
      "currency",
      "source_ref",
      "destination_ref",
      "parameters.value_date",
      "parameters.rail",
    ],
  },
  {
    domain: "LOAN_DISBURSEMENT",
    type: "DISBURSE_LOAN",
    effectType: "LOAN_DISBURSEMENT",
    projection: ["subject", "amount", "currency", "destination_ref"],
  },
  {
    domain: "CREDIT_LIMITS",
    type: "SET_CREDIT_LIMIT",
    effectType: "CREDIT_LIMIT_SET",
    projection: ["amount", "currency"],
  },
  {
    domain: "ACCOUNT_ORIGINATION",
    type: "CREATE_ACCOUNT",
    effectType: "ACCOUNT_CREATED",
    projection: ["subject", "currency", "parameters.product", "parameters.account_type"],
  },
];

export class ProjectionError extends Error {
  public constructor(
    public readonly code: "ACTION_NOT_REGISTERED_IN_PROFILE" | "PROJECTION_FIELD_MISSING",
    public readonly subject?: string,
  ) {
    super(subject === undefined ? code : `${code}: ${subject}`);
    this.name = "ProjectionError";
  }
}

export function registeredAction(domain: string, type: string): RegisteredAction {
  const found = REGISTERED_ACTIONS.find((entry) => entry.domain === domain && entry.type === type);
  if (found === undefined) {
    throw new ProjectionError("ACTION_NOT_REGISTERED_IN_PROFILE", `${domain}/${type}`);
  }
  return found;
}

/**
 * Where a projection field comes from in a BankingAction. The profile names
 * the fields but not the paths, so this is the executor's own rule, written
 * down rather than implied:
 *
 * - `amount` and `currency` come from `financial_context`
 * - `source_ref`, `destination_ref` and `parameters.*` from `requested_effect`
 * - `subject` and `target` are the entity's `type:ref`
 * - `batch.*` from `batch`
 *
 * It is implementation-defined until the profile's owner confirms it, and the
 * conformance note says so. A field the action does not carry is a refusal,
 * not an absent key, because an expected effect with a hole in it would
 * compare equal to an observation with a different hole.
 */
export function projectionValue(action: BankingAction, field: string): JsonValue {
  if (field === "effect_type")
    return registeredAction(action.domain, action.action.type).effectType;
  if (field === "domain") return action.domain;
  if (field === "action") return action.action.type;
  if (field === "target") return `${action.target.type}:${action.target.ref}`;
  if (field === "subject") {
    if (action.subject === undefined) throw new ProjectionError("PROJECTION_FIELD_MISSING", field);
    return `${action.subject.type}:${action.subject.ref}`;
  }
  if (field === "amount") {
    const amount = action.financial_context?.amount;
    if (amount === undefined) throw new ProjectionError("PROJECTION_FIELD_MISSING", field);
    return amount;
  }
  if (field === "currency") {
    const currency = action.financial_context?.currency;
    if (currency === undefined) throw new ProjectionError("PROJECTION_FIELD_MISSING", field);
    return currency;
  }
  if (field === "source_ref" || field === "destination_ref") {
    const value = action.requested_effect[field];
    if (value === undefined) throw new ProjectionError("PROJECTION_FIELD_MISSING", field);
    return value;
  }
  if (field.startsWith("parameters.")) {
    const value = action.requested_effect.parameters?.[field.slice("parameters.".length)];
    if (value === undefined) throw new ProjectionError("PROJECTION_FIELD_MISSING", field);
    return value;
  }
  if (field.startsWith("batch.")) {
    const batch = action.batch;
    const key = field.slice("batch.".length);
    const value = batch === undefined ? undefined : (batch as Record<string, JsonValue>)[key];
    if (value === undefined) throw new ProjectionError("PROJECTION_FIELD_MISSING", field);
    return value;
  }
  throw new ProjectionError("PROJECTION_FIELD_MISSING", field);
}

/**
 * The expected effect: the base fields and the action's own, each read from
 * the action, in the order the registry lists them. This object is what the
 * expected-effect digest is taken over, and what an observation is compared
 * against field by field.
 */
export function expectedEffect(action: BankingAction): JsonObject {
  const registered = registeredAction(action.domain, action.action.type);
  const projection: JsonObject = {};
  for (const field of [...BASE_PROJECTION, ...registered.projection]) {
    projection[field] = projectionValue(action, field);
  }
  return projection;
}
