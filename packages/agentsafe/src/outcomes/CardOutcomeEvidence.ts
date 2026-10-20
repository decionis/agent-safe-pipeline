import { z } from "zod";
import type { JsonValue } from "@decionis/agent-safe-pipeline";
import { isSupportedCurrency, minorUnitExponent } from "../adapters/banking/Currency.js";
import type {
  CardOutcomeFact,
  ClaimedCardFact,
  DecidedCardFact,
  ResumedCardFact,
  SettledCardFact,
} from "./CardOutcomeFact.js";
import {
  OUTCOME_CODE,
  OUTCOME_EVIDENCE_LIMITS,
  OUTCOME_EVIDENCE_VERSION,
  outcomeDigest,
  type OutcomeDecision,
  type OutcomeEvidenceDraft,
  type OutcomeExecution,
  type OutcomeReview,
} from "./OutcomeEvidence.js";

/**
 * The platform module id card evidence is stated under. An agreement's scope names it in
 * `platforms` (with `CARD_PURCHASE` in `action_types`, and no connection ids, since card
 * evidence carries none) for the meter to count it. The executor that matches the issuer's
 * authorizations runs as the `card-issuer` platform; this id names what is measured, the card
 * authorization, and is the one an agreement uses.
 */
export const CARD_OUTCOME_PLATFORM = "card-authorization";
/** The one action the cards family governs, `card.purchase`, in the contract's code form. */
export const CARD_OUTCOME_ACTION_TYPE = "CARD_PURCHASE";
/**
 * Reason codes that say a person refused a held purchase: Presence's answer in direct mode
 * (`PRESENCE_DENIED`) and in managed mode (`PRESENCE_REJECTED`). Any other refusal on a
 * resumed escalation (a forged or expired attestation, an authority that did not answer, a
 * policy that still blocks) is not a person's answer, and states no review.
 */
const PERSON_REFUSED: ReadonlySet<string> = new Set(["PRESENCE_DENIED", "PRESENCE_REJECTED"]);
const DISPOSITION = { ALLOW: "PROCEED", ESCALATE: "HOLD", BLOCK: "BLOCK" } as const;
const grantId = z.string().uuid();

/** The facts one purchase left, sorted into the steps they record. */
interface PurchaseFacts {
  readonly decided: DecidedCardFact;
  readonly resumed: readonly ResumedCardFact[];
  readonly claimed: ClaimedCardFact | null;
  readonly settled: SettledCardFact | null;
  readonly all: readonly CardOutcomeFact[];
}

/**
 * Card purchases as outcome evidence (`decionis.outcomes.evidence/1`), one subject per
 * purchase, stated only from the facts AgentSafe recorded. Nothing is classified here: Core's
 * one `OutcomeCalculator` applies the customer's signed agreement. Every field is stated
 * conservatively, from a fact that establishes it, or left null:
 *
 * - subject: a digest of the tenant and the purchase's intent id, so subjects are scoped to the
 *   tenant and nothing in them identifies a card, a cardholder or a merchant.
 * - amount: what the purchase named at decision time, in its own currency and minor units.
 * - coverage and decision: every stated purchase carried a decision, so it is `GOVERNED`; the
 *   decision's `mode` says whether it was enforced or only evaluated in shadow, which Core
 *   reads as an estimate and never sums with realized results. A decision the authority never
 *   took (it did not answer, and the boundary refused on its own) is not stated at all.
 * - review: only for an enforced hold, and only from a person's answer. A cardholder's tap or a
 *   Presence approval that released the hold is `RELEASED` as `LEGITIMATE`; a Presence denial is
 *   `REJECTED` and `UNCONFIRMED`, because refusing a purchase is not establishing that it was a
 *   problem. AgentSafe records no one's confirmation of a problem, so it never states one.
 * - execution: the issuer's result for the authorization that claimed the grant (`COMMITTED`,
 *   `FAILED`, or `UNKNOWN` for a result after the claim's lease); `UNKNOWN` while a claimed
 *   authorization has no result; `NOT_EXECUTED` once nothing can be claimed any more (a held
 *   grant expired unspent, a grant that was never held, or an intent past its expiry with no
 *   grant ever held). Shadow never executes here, so it states none.
 * - financial: always null. The issuer's clearing, settlement and reversals are outside this
 *   boundary, and nothing here records them.
 */
export class CardOutcomeEvidenceProvider {
  public readonly platform = CARD_OUTCOME_PLATFORM;

  /** Each purchase decided inside the window (both ends included), stated as it stands at `to`. */
  public collect(
    facts: readonly CardOutcomeFact[],
    window: { readonly from: Date; readonly to: Date },
  ): OutcomeEvidenceDraft[] {
    const purchases = new Map<string, CardOutcomeFact[]>();
    for (const fact of facts) {
      const list = purchases.get(fact.intent_id) ?? [];
      list.push(fact);
      purchases.set(fact.intent_id, list);
    }
    const from = window.from.getTime();
    const to = window.to.getTime();
    const drafts: OutcomeEvidenceDraft[] = [];
    for (const list of purchases.values()) {
      const draft = this.map(list, window.to);
      if (draft === null) continue;
      const at = Date.parse(draft.occurred_at);
      if (at >= from && at <= to) drafts.push(draft);
    }
    return drafts;
  }

  /** One purchase's evidence from its facts, oldest first, or null when they state none. */
  public map(facts: readonly CardOutcomeFact[], now: Date): OutcomeEvidenceDraft | null {
    const purchase = CardOutcomeEvidenceProvider.sort(facts);
    if (purchase === null) return null;
    const { decided } = purchase;
    if (!isSupportedCurrency(decided.currency)) return null;
    const disposition = DISPOSITION[decided.verdict];
    const enforced = decided.mode === "ENFORCEMENT";
    const decision: OutcomeDecision = {
      decision_id:
        decided.decision_id !== null && decided.decision_id.length <= 120
          ? decided.decision_id
          : null,
      dossier_id: decided.dossier_id,
      disposition,
      mode: enforced ? "ENFORCEMENT" : "SHADOW",
      decided_at: decided.at,
      reason_codes: [...new Set(decided.reason_codes)]
        .filter((code) => OUTCOME_CODE.test(code))
        .slice(0, OUTCOME_EVIDENCE_LIMITS.reasons),
    };
    return {
      version: OUTCOME_EVIDENCE_VERSION,
      subject_digest: outcomeDigest({
        producer: "agentsafe",
        platform: CARD_OUTCOME_PLATFORM,
        tenant_id: decided.tenant_id,
        intent_id: decided.intent_id,
      }),
      platform: CARD_OUTCOME_PLATFORM,
      connection_id: null,
      action_type: CARD_OUTCOME_ACTION_TYPE,
      occurred_at: decided.at,
      amount: {
        currency: decided.currency,
        scale: minorUnitExponent(decided.currency),
        amount_minor: decided.amount_minor,
      },
      coverage: "GOVERNED",
      decision,
      review: enforced && disposition !== "PROCEED" ? this.review(purchase) : null,
      execution: enforced ? this.execution(purchase, now) : null,
      financial: null,
      exclusion_codes: [],
      source_sha256: outcomeDigest(purchase.all as unknown as JsonValue),
    };
  }

  /** A person's answer to the hold: the first resumption that released it or that a person refused. */
  private review(purchase: PurchaseFacts): OutcomeReview | null {
    const caseId = `agentsafe:card:${purchase.decided.intent_id}`.slice(0, 200);
    for (const fact of purchase.resumed) {
      if (fact.verdict === "ALLOW") {
        return {
          case_id: caseId,
          outcome: "RELEASED",
          confirmation: "LEGITIMATE",
          confirmed_by: "CUSTOMER",
          reviewer: "CUSTOMER",
          decided_at: fact.at,
          analyst_minutes: null,
        };
      }
      if (fact.reason_codes.some((code) => PERSON_REFUSED.has(code))) {
        return {
          case_id: caseId,
          outcome: "REJECTED",
          confirmation: "UNCONFIRMED",
          confirmed_by: null,
          reviewer: "CUSTOMER",
          decided_at: fact.at,
          analyst_minutes: null,
        };
      }
    }
    return null;
  }

  /** What became of the purchase at the issuer, as far as this boundary saw it, at `now`. */
  private execution(purchase: PurchaseFacts, now: Date): OutcomeExecution | null {
    const { claimed, settled, decided } = purchase;
    const grant = claimed === null ? null : CardOutcomeEvidenceProvider.grant(claimed.grant_id);
    if (settled !== null) {
      return {
        status:
          settled.outcome === "COMMITTED"
            ? "COMMITTED"
            : settled.outcome === "FAILED"
              ? "FAILED"
              : "UNKNOWN",
        grant_id: grant,
        receipt_sha256:
          settled.outcome === "COMMITTED" && settled.receipt_digest !== null
            ? settled.receipt_digest.slice("sha256:".length)
            : null,
        at: settled.at,
      };
    }
    // A claimed authorization whose result has not arrived: the issuer may have approved it.
    if (claimed !== null) {
      return { status: "UNKNOWN", grant_id: grant, receipt_sha256: null, at: claimed.at };
    }
    const lapsed = (at: string): OutcomeExecution => ({
      status: "NOT_EXECUTED",
      grant_id: null,
      receipt_sha256: null,
      at,
    });
    const allowed = [decided, ...purchase.resumed].filter((fact) => fact.verdict === "ALLOW");
    const latest = allowed.at(-1);
    if (latest !== undefined) {
      // Allowed, but no grant was kept for the issuer: nothing could ever claim it.
      if (latest.held_until === null) return lapsed(latest.at);
      return now.getTime() >= Date.parse(latest.held_until) ? lapsed(latest.held_until) : null;
    }
    // Never allowed: once the intent expired, no grant can be held or claimed for it.
    return now.getTime() >= Date.parse(decided.expires_at) ? lapsed(decided.expires_at) : null;
  }

  /** The facts in their steps; null without the decision every stated purchase starts from. */
  private static sort(facts: readonly CardOutcomeFact[]): PurchaseFacts | null {
    const decided = facts.find((fact): fact is DecidedCardFact => fact.kind === "DECIDED");
    if (decided === undefined) return null;
    const all = facts.filter((fact) => fact.intent_id === decided.intent_id);
    const resumed: ResumedCardFact[] = [];
    let claimed: ClaimedCardFact | null = null;
    let settled: SettledCardFact | null = null;
    for (const fact of all) {
      if (fact.kind === "RESUMED") resumed.push(fact);
      else if (fact.kind === "CLAIMED") claimed ??= fact;
      else if (fact.kind === "SETTLED") settled ??= fact;
    }
    return { decided, resumed, claimed, settled, all };
  }

  /** A grant id as the contract carries one: a UUID, or nothing. */
  private static grant(value: string): string | null {
    return grantId.safeParse(value).success ? value : null;
  }
}
