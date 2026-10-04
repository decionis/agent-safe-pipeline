import canonicalContract from "../../contract/CommercePreflight.v1.json" with { type: "json" };
import type { CommerceAction, SupportedActionType } from "../CommerceGateClient.js";

/** Metadata is generated from the server contract; this module contains no business rules. */
export const COMMERCE_PREFLIGHT_VERSION = canonicalContract.version as "commerce-preflight-v1";
export const COMMERCE_PREFLIGHT_RELEASE_STATUS = canonicalContract.release_status;
export type CommerceCheckId =
  "P01" | "P02" | "P03" | "P04" | "P05" | "P06" | "P07" | "P08" | "P09" | "P10" | "P11";
export const COMMERCE_CHECK_IDS = canonicalContract.checks.map(
  (check) => check.id,
) as readonly CommerceCheckId[];
export type CommercePreflightDisposition = "PROCEED" | "HOLD" | "BLOCK";
export const COMMERCE_PREFLIGHT_CHECKS = canonicalContract.checks as readonly {
  id: CommerceCheckId;
  key: string;
  name: string;
  action_types: readonly SupportedActionType[];
}[];
export type CommerceLifecycleState =
  | "created"
  | "acknowledged"
  | "shipped"
  | "delivered"
  | "cancelled"
  | "refunded"
  | "return_authorized"
  | "returned";
export const COMMERCE_LIFECYCLE_STATES = canonicalContract.schemas.CommercePreflightFacts.properties
  .lifecycle.properties.current_state.enum as readonly CommerceLifecycleState[];

export interface CommercePreflightFacts {
  observed_at?: string;
  source?: string;
  currency?: string;
  pricing?: { gross_amount?: number; discount_amount?: number; estimated_cost?: number };
  cost_basis?: { source_cost?: number; system_of_record_cost?: number };
  inventory?: {
    source_on_hand?: number;
    system_on_hand?: number;
    reserved_quantity?: number;
    requested_quantity?: number;
  };
  region?: { country?: string };
  discounts?: { count?: number; sources?: string[] };
  contract?: { account_type?: "retail" | "b2b"; offered_price?: number; contract_price?: number };
  promotion?: {
    discount_codes?: string[];
    prior_redemptions?: number;
    account_age_days?: number;
    identity_hash?: string;
  };
  refund?: { remaining_refundable?: number; prior_refund_count?: number };
  lifecycle?: {
    current_state?: (typeof COMMERCE_LIFECYCLE_STATES)[number];
    delivered_at?: string;
    return_eligible?: boolean;
  };
}

export interface CommercePreflightInput {
  version: typeof COMMERCE_PREFLIGHT_VERSION;
  facts: CommercePreflightFacts;
}

export interface CommerceCheckResult {
  id: CommerceCheckId;
  status: "evaluated" | "not_applicable" | "disabled" | "missing_facts" | "unsupported";
  verdict: CommercePreflightDisposition | null;
  reason_codes: string[];
  missing_facts: string[];
  measurements?: Record<string, number>;
}

export interface CommercePreflightResult {
  version: typeof COMMERCE_PREFLIGHT_VERSION;
  action_type: CommerceAction["action_type"];
  action_digest: string;
  facts_digest: string;
  policy_version: string;
  idempotency_key: string;
  evaluated_at: string;
  disposition: CommercePreflightDisposition;
  execution_available: false;
  checks: CommerceCheckResult[];
}
