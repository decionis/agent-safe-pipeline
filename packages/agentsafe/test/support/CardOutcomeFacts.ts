import {
  CARD_OUTCOME_FACT_VERSION,
  type ClaimedCardFact,
  type DecidedCardFact,
  type ResumedCardFact,
  type SettledCardFact,
} from "../../src/outcomes/CardOutcomeFact.js";
import type { OutcomeEvidence } from "../../src/outcomes/OutcomeEvidence.js";

/** The Decionis organization the synthetic evidence is about: the reserved fixture block. */
export const ORG_ID = "00000000-0000-4000-8000-000000000005";
export const FACT_TENANT = "00000000-0000-4000-8000-000000000007";
export const FACT_INTENT = "6a1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8";
export const FACT_GRANT = "33333333-3333-4333-8333-333333333333";
export const FACT_RECEIPT = `sha256:${"d".repeat(64)}`;
/** A producer token shaped as Core's registry takes one: printable, at least 32 characters. */
export const PRODUCER_TOKEN = "synthetic-producer-token-0123456789abcdef";

const T0 = Date.parse("2026-10-12T12:00:00.000Z");

/** An instant `seconds` after the synthetic purchase's decision. */
export function at(seconds: number): string {
  return new Date(T0 + seconds * 1_000).toISOString();
}

export function decided(overrides: Partial<DecidedCardFact> = {}): DecidedCardFact {
  return {
    version: CARD_OUTCOME_FACT_VERSION,
    kind: "DECIDED",
    at: at(0),
    intent_id: FACT_INTENT,
    tenant_id: FACT_TENANT,
    mode: "ENFORCEMENT",
    verdict: "ALLOW",
    decision_id: "fixture_decision_1",
    dossier_id: "fixture_dossier_1",
    reason_codes: [],
    held_until: at(300),
    expires_at: at(300),
    currency: "EUR",
    amount_minor: 4_250,
    ...overrides,
  };
}

export function resumed(overrides: Partial<ResumedCardFact> = {}): ResumedCardFact {
  return {
    version: CARD_OUTCOME_FACT_VERSION,
    kind: "RESUMED",
    at: at(60),
    intent_id: FACT_INTENT,
    via: "ATTESTATION",
    verdict: "ALLOW",
    decision_id: "fixture_decision_2",
    dossier_id: "fixture_dossier_2",
    reason_codes: ["PRESENCE_ATTESTATION_VERIFIED"],
    held_until: at(300),
    ...overrides,
  };
}

export function claimed(overrides: Partial<ClaimedCardFact> = {}): ClaimedCardFact {
  return {
    version: CARD_OUTCOME_FACT_VERSION,
    kind: "CLAIMED",
    at: at(90),
    intent_id: FACT_INTENT,
    grant_id: FACT_GRANT,
    ...overrides,
  };
}

export function settled(overrides: Partial<SettledCardFact> = {}): SettledCardFact {
  return {
    version: CARD_OUTCOME_FACT_VERSION,
    kind: "SETTLED",
    at: at(95),
    intent_id: FACT_INTENT,
    outcome: "COMMITTED",
    receipt_digest: FACT_RECEIPT,
    ...overrides,
  };
}

/**
 * Core's `OutcomeCalculator.classify` (`decionis.outcomes.calculator/1`), restated for the cases
 * card evidence can reach, under an agreement whose scope names `card-authorization` and whose
 * confirmation is by reviewer. Core remains the only place classification lives: this restates
 * it so a test can show which bucket each stated purchase lands in, and that nothing the card
 * producer states reads as prevented without a person's confirmation.
 */
export function coreClassification(evidence: OutcomeEvidence): string {
  if (evidence.coverage === "UNGOVERNED") return "COVERAGE_GAP/FAIL_OPEN_PASS_THROUGH";
  if (evidence.coverage === "OBSERVED") return "COVERAGE_GAP/OBSERVED_ONLY";
  const decision = evidence.decision;
  if (decision === null) throw new Error("governed evidence names its decision");
  const held = decision.disposition !== "PROCEED";
  if (decision.mode !== "ENFORCEMENT") {
    return held ? "ESTIMATE/SHADOW_WOULD_HOLD" : "EXCLUDED/SHADOW_WOULD_PROCEED";
  }
  const committed = evidence.execution?.status === "COMMITTED";
  if (!held) {
    if (committed) return "GOVERNED/EXECUTED_WITH_PERMIT";
    if (evidence.execution?.status === "FAILED" || evidence.execution?.status === "NOT_EXECUTED") {
      return "EXCLUDED/EXECUTION_FAILED";
    }
    return "PENDING/AWAITING_EXECUTION";
  }
  const paid = committed || evidence.financial?.status === "SETTLED";
  const review = evidence.review;
  if (review === null) {
    if (paid) return "COVERAGE_GAP/PAID_DESPITE_HOLD";
    return decision.disposition === "BLOCK"
      ? "HELD_UNCONFIRMED/BLOCKED_WITHOUT_REVIEW"
      : "PENDING/AWAITING_REVIEW";
  }
  if (review.outcome === "RELEASED") return "FALSE_HOLD/RELEASED_AS_LEGITIMATE";
  if (paid) return "COVERAGE_GAP/PAID_DESPITE_HOLD";
  return review.confirmation === "CONFIRMED_PROBLEM" && review.confirmed_by !== null
    ? "PREVENTED/CONFIRMED_AND_NOT_PAID"
    : "HELD_UNCONFIRMED/REJECTED_WITHOUT_CONFIRMATION";
}
