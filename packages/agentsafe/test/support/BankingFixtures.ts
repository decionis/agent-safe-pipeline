import type { BankingAction } from "../../src/adapters/banking/BankingAction.js";
import type { PreparedAction } from "../../src/adapters/EffectAdapter.js";
import { BEAP_PROFILE } from "../../src/adapters/banking/BankingAction.js";

/** The reserved fixture tenant this package's tests use throughout. */
export const FIXTURE_ACTOR_ID = "synthetic-treasury-agent";

/**
 * A canonical banking action, synthetic throughout: the shape the profile's
 * own loan-disbursement example carries, with the pieces a test varies
 * lifted into overrides.
 */
export function bankingAction(overrides: Partial<BankingAction> = {}): BankingAction {
  return {
    profile: BEAP_PROFILE,
    domain: "LOAN_DISBURSEMENT",
    action: { type: "DISBURSE_LOAN", request_id: "synthetic-req-0001" },
    actor: { type: "AGENT", id: FIXTURE_ACTOR_ID, runtime: "synthetic-agent-runtime" },
    principal: { type: "ORGANIZATIONAL_FUNCTION", id: "synthetic-credit-operations" },
    subject: { type: "CUSTOMER", ref: "fixture_customer_28491" },
    target: { type: "LOAN", ref: "fixture_loan_84721" },
    financial_context: { amount: "250000.00", currency: "CHF" },
    requested_effect: { operation: "DISBURSE", destination_ref: "fixture_account_1921" },
    downstream: {
      provider: "SYNTHETIC_CORE",
      product: "LENDING",
      operation: "LOAN_DISBURSEMENT",
      environment: "LOCAL",
    },
    evidence_refs: [],
    ...overrides,
  } as BankingAction;
}

/** A payment action, the family's other shape: the projection has parameters in it. */
export function paymentAction(overrides: Partial<BankingAction> = {}): BankingAction {
  return bankingAction({
    domain: "CORPORATE_PAYMENTS",
    action: { type: "SEND_PAYMENT", request_id: "synthetic-req-0002" },
    subject: undefined,
    target: { type: "ACCOUNT", ref: "fixture_account_5150" },
    financial_context: { amount: "1250.00", currency: "EUR" },
    requested_effect: {
      operation: "TRANSFER",
      source_ref: "fixture_account_5150",
      destination_ref: "fixture_account_7788",
      parameters: { value_date: "2026-03-02", rail: "SEPA_CT" },
    },
    downstream: {
      provider: "SYNTHETIC_CORE",
      product: "PAYMENTS",
      operation: "LOAN_DISBURSEMENT",
      environment: "LOCAL",
    },
    ...overrides,
  });
}

/** The effect the provider would report for an action, as its projection. */
export function observedEffect(prepared: PreparedAction): Record<string, unknown> {
  return { ...prepared.expectedEffect };
}
