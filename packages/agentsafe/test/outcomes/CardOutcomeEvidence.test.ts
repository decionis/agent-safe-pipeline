import { createHash } from "node:crypto";
import type { JsonValue } from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { jcsCanonical } from "../../src/adapters/JcsDigest.js";
import {
  CARD_OUTCOME_ACTION_TYPE,
  CARD_OUTCOME_PLATFORM,
  CardOutcomeEvidenceProvider,
} from "../../src/outcomes/CardOutcomeEvidence.js";
import type { CardOutcomeFact } from "../../src/outcomes/CardOutcomeFact.js";
import {
  OutcomeEvidenceSchema,
  outcomeDigest,
  type OutcomeEvidence,
  type OutcomeEvidenceDraft,
} from "../../src/outcomes/OutcomeEvidence.js";
import { OutcomeEvidenceStore } from "../../src/outcomes/OutcomeEvidenceStore.js";
import {
  FACT_GRANT,
  FACT_INTENT,
  FACT_TENANT,
  at,
  claimed,
  coreClassification,
  decided,
  resumed,
  settled,
} from "../support/CardOutcomeFacts.js";

const provider = new CardOutcomeEvidenceProvider();
/** Long after every synthetic purchase's grant and intent expired. */
const LATER = new Date(Date.parse(at(3_600)));
/** While the synthetic purchase's grant and intent are still open. */
const MEANWHILE = new Date(Date.parse(at(120)));

function stated(facts: readonly CardOutcomeFact[], now: Date = LATER): OutcomeEvidenceDraft {
  const draft = provider.map(facts, now);
  if (draft === null) throw new Error("the facts stated no evidence");
  // Every draft is evidence the contract accepts once the store gives it a revision.
  OutcomeEvidenceSchema.parse({ ...draft, revision: 1 });
  return draft;
}

const classified = (draft: OutcomeEvidenceDraft): string =>
  coreClassification({ ...draft, revision: 1 } as OutcomeEvidence);

const ESCALATED = decided({
  verdict: "ESCALATE",
  held_until: null,
  reason_codes: ["HUMAN_APPROVAL_REQUIRED"],
});
const PRESENCE_REFUSED = resumed({
  via: "PRESENCE",
  verdict: "BLOCK",
  decision_id: null,
  dossier_id: null,
  reason_codes: ["REJECTED", "PRESENCE_REJECTED"],
  held_until: null,
});

describe("card purchases as outcome evidence", () => {
  it("states each purchase as one governed subject, scoped to the tenant, with only digests to identify it", () => {
    const draft = stated([decided(), claimed(), settled()]);
    expect(draft).toMatchObject({
      version: "decionis.outcomes.evidence/1",
      platform: CARD_OUTCOME_PLATFORM,
      action_type: CARD_OUTCOME_ACTION_TYPE,
      connection_id: null,
      occurred_at: at(0),
      amount: { currency: "EUR", scale: 2, amount_minor: 4_250 },
      coverage: "GOVERNED",
      financial: null,
      exclusion_codes: [],
    });
    expect([CARD_OUTCOME_PLATFORM, CARD_OUTCOME_ACTION_TYPE]).toEqual([
      "card-authorization",
      "CARD_PURCHASE",
    ]);
    // The subject is the tenant and the intent, digested: the same purchase in another tenant
    // is another subject, and the digest is the contract's canonical one.
    expect(draft.subject_digest).toBe(
      createHash("sha256")
        .update(
          jcsCanonical({
            producer: "agentsafe",
            platform: "card-authorization",
            tenant_id: FACT_TENANT,
            intent_id: FACT_INTENT,
          }),
        )
        .digest("hex"),
    );
    const elsewhere = stated([
      decided({ tenant_id: "00000000-0000-4000-8000-000000000002" }),
      claimed(),
      settled(),
    ]);
    expect(elsewhere.subject_digest).not.toBe(draft.subject_digest);
    expect(draft.source_sha256).toBe(outcomeDigest([decided(), claimed(), settled()]));
    // The minor-unit scale is the currency's own.
    expect(stated([decided({ currency: "JPY", amount_minor: 900 })]).amount).toEqual({
      currency: "JPY",
      scale: 0,
      amount_minor: 900,
    });
    expect(stated([decided({ currency: "KWD", amount_minor: 1_500 })]).amount.scale).toBe(3);
  });

  it("maps every way a purchase can end onto the facts Core classifies, and never onto a prevention", () => {
    const cases: readonly {
      readonly name: string;
      readonly facts: readonly CardOutcomeFact[];
      readonly now?: Date;
      readonly disposition: string;
      readonly review: string | null;
      readonly execution: string | null;
      readonly core: string;
    }[] = [
      {
        name: "allowed, claimed, approved by the issuer",
        facts: [decided(), claimed(), settled()],
        disposition: "PROCEED",
        review: null,
        execution: "COMMITTED",
        core: "GOVERNED/EXECUTED_WITH_PERMIT",
      },
      {
        name: "allowed, claimed, declined by the issuer",
        facts: [decided(), claimed(), settled({ outcome: "FAILED" })],
        disposition: "PROCEED",
        review: null,
        execution: "FAILED",
        core: "EXCLUDED/EXECUTION_FAILED",
      },
      {
        name: "allowed, claimed, result after the claim's lease",
        facts: [decided(), claimed(), settled({ outcome: "INDETERMINATE" })],
        disposition: "PROCEED",
        review: null,
        execution: "UNKNOWN",
        core: "PENDING/AWAITING_EXECUTION",
      },
      {
        name: "allowed, claimed, no result yet",
        facts: [decided(), claimed()],
        disposition: "PROCEED",
        review: null,
        execution: "UNKNOWN",
        core: "PENDING/AWAITING_EXECUTION",
      },
      {
        name: "allowed, held, the issuer has not asked yet",
        facts: [decided()],
        now: MEANWHILE,
        disposition: "PROCEED",
        review: null,
        execution: null,
        core: "PENDING/AWAITING_EXECUTION",
      },
      {
        name: "allowed, held, expired unspent",
        facts: [decided()],
        disposition: "PROCEED",
        review: null,
        execution: "NOT_EXECUTED",
        core: "EXCLUDED/EXECUTION_FAILED",
      },
      {
        name: "allowed, but no hold could be kept",
        facts: [decided({ held_until: null, reason_codes: ["CARD_HOLD_UNAVAILABLE"] })],
        now: MEANWHILE,
        disposition: "PROCEED",
        review: null,
        execution: "NOT_EXECUTED",
        core: "EXCLUDED/EXECUTION_FAILED",
      },
      {
        name: "escalated, the cardholder tapped, claimed and approved",
        facts: [ESCALATED, resumed(), claimed(), settled()],
        disposition: "HOLD",
        review: "RELEASED/LEGITIMATE",
        execution: "COMMITTED",
        core: "FALSE_HOLD/RELEASED_AS_LEGITIMATE",
      },
      {
        name: "escalated, released through Presence, the grant expired unspent",
        facts: [ESCALATED, resumed({ via: "PRESENCE", held_until: at(200) })],
        disposition: "HOLD",
        review: "RELEASED/LEGITIMATE",
        execution: "NOT_EXECUTED",
        core: "FALSE_HOLD/RELEASED_AS_LEGITIMATE",
      },
      {
        name: "escalated, refused through managed Presence",
        facts: [ESCALATED, PRESENCE_REFUSED],
        disposition: "HOLD",
        review: "REJECTED/UNCONFIRMED",
        execution: "NOT_EXECUTED",
        core: "HELD_UNCONFIRMED/REJECTED_WITHOUT_CONFIRMATION",
      },
      {
        name: "escalated, denied through direct Presence",
        facts: [ESCALATED, resumed({ ...PRESENCE_REFUSED, reason_codes: ["PRESENCE_DENIED"] })],
        disposition: "HOLD",
        review: "REJECTED/UNCONFIRMED",
        execution: "NOT_EXECUTED",
        core: "HELD_UNCONFIRMED/REJECTED_WITHOUT_CONFIRMATION",
      },
      {
        name: "escalated, a forged tap refused: nobody answered",
        facts: [
          ESCALATED,
          resumed({
            verdict: "BLOCK",
            reason_codes: ["PRESENCE_ATTESTATION_SIGNATURE_INVALID"],
            held_until: null,
          }),
        ],
        disposition: "HOLD",
        review: null,
        execution: "NOT_EXECUTED",
        core: "PENDING/AWAITING_REVIEW",
      },
      {
        name: "escalated, waiting for the cardholder",
        facts: [ESCALATED],
        now: MEANWHILE,
        disposition: "HOLD",
        review: null,
        execution: null,
        core: "PENDING/AWAITING_REVIEW",
      },
      {
        name: "escalated, the intent expired with nobody answering",
        facts: [ESCALATED],
        disposition: "HOLD",
        review: null,
        execution: "NOT_EXECUTED",
        core: "PENDING/AWAITING_REVIEW",
      },
      {
        name: "blocked by policy",
        facts: [decided({ verdict: "BLOCK", held_until: null, reason_codes: ["AMOUNT_LIMIT"] })],
        disposition: "BLOCK",
        review: null,
        execution: "NOT_EXECUTED",
        core: "HELD_UNCONFIRMED/BLOCKED_WITHOUT_REVIEW",
      },
      {
        name: "shadow, would have escalated",
        facts: [decided({ mode: "SHADOW", verdict: "ESCALATE", held_until: null })],
        disposition: "HOLD",
        review: null,
        execution: null,
        core: "ESTIMATE/SHADOW_WOULD_HOLD",
      },
      {
        name: "shadow, would have blocked",
        facts: [decided({ mode: "SHADOW", verdict: "BLOCK", held_until: null })],
        disposition: "BLOCK",
        review: null,
        execution: null,
        core: "ESTIMATE/SHADOW_WOULD_HOLD",
      },
      {
        name: "shadow, would have allowed",
        facts: [decided({ mode: "SHADOW", held_until: null })],
        disposition: "PROCEED",
        review: null,
        execution: null,
        core: "EXCLUDED/SHADOW_WOULD_PROCEED",
      },
    ];
    for (const entry of cases) {
      const draft = stated(entry.facts, entry.now);
      const review =
        draft.review === null ? null : `${draft.review.outcome}/${draft.review.confirmation}`;
      expect(
        {
          disposition: draft.decision?.disposition,
          review,
          execution: draft.execution?.status ?? null,
          core: classified(draft),
        },
        entry.name,
      ).toEqual({
        disposition: entry.disposition,
        review: entry.review,
        execution: entry.execution,
        core: entry.core,
      });
      // AgentSafe records no one's confirmation of a problem, so it never states one, and the
      // meter never reads a card purchase as prevented.
      expect(draft.review?.confirmation, entry.name).not.toBe("CONFIRMED_PROBLEM");
      expect(classified(draft), entry.name).not.toMatch(/^PREVENTED/);
    }
  });

  it("states the decision, the person's answer and the issuer's receipt as the facts recorded them", () => {
    const draft = stated([
      decided({
        verdict: "ESCALATE",
        held_until: null,
        reason_codes: ["HUMAN_APPROVAL_REQUIRED", "HUMAN_APPROVAL_REQUIRED", "lower-case", "X"],
      }),
      resumed({ at: at(45) }),
      claimed(),
      settled(),
    ]);
    expect(draft.decision).toEqual({
      decision_id: "fixture_decision_1",
      dossier_id: "fixture_dossier_1",
      disposition: "HOLD",
      mode: "ENFORCEMENT",
      decided_at: at(0),
      reason_codes: ["HUMAN_APPROVAL_REQUIRED", "X"],
    });
    expect(draft.review).toEqual({
      case_id: `agentsafe:card:${FACT_INTENT}`,
      outcome: "RELEASED",
      confirmation: "LEGITIMATE",
      confirmed_by: "CUSTOMER",
      reviewer: "CUSTOMER",
      decided_at: at(45),
      analyst_minutes: null,
    });
    expect(draft.execution).toEqual({
      status: "COMMITTED",
      grant_id: FACT_GRANT,
      receipt_sha256: "d".repeat(64),
      at: at(95),
    });
    // A decline carries no receipt; a grant id that is not a UUID is not stated.
    expect(
      stated([
        decided(),
        claimed({ grant_id: "fixture-local-grant" }),
        settled({ outcome: "FAILED" }),
      ]).execution,
    ).toEqual({ status: "FAILED", grant_id: null, receipt_sha256: null, at: at(95) });
    // A decision id longer than the contract carries is left out rather than cut.
    expect(stated([decided({ decision_id: "d".repeat(121) })]).decision?.decision_id).toBeNull();
    // At most thirty reason codes.
    const many = Array.from({ length: 40 }, (_, index) => `CODE_${index}`);
    expect(stated([decided({ reason_codes: many })]).decision?.reason_codes).toHaveLength(30);
  });

  it("reads only the first decision and the first answer, and only a person's refusal as one", () => {
    // A later resumption does not undo the first person's answer.
    const answered = stated([
      ESCALATED,
      PRESENCE_REFUSED,
      resumed({ at: at(80), held_until: at(280) }),
      claimed(),
      settled(),
    ]);
    expect(answered.review?.outcome).toBe("REJECTED");
    // A second decision fact for the same intent is not a second purchase.
    expect(
      stated([decided(), decided({ verdict: "BLOCK", at: at(5) })]).decision?.disposition,
    ).toBe("PROCEED");
    // An allowed purchase is never reviewed, whatever follows.
    expect(stated([decided(), resumed()]).review).toBeNull();
    // A later grant held on a resumption keeps the purchase spendable until it lapses.
    const relapsed = [
      decided({ held_until: at(30) }),
      resumed({ at: at(40), held_until: at(240) }),
    ];
    expect(stated(relapsed, MEANWHILE).execution).toBeNull();
    expect(stated(relapsed).execution).toMatchObject({ status: "NOT_EXECUTED", at: at(240) });
  });

  it("states nothing without the decision, or for a currency this build cannot scale", () => {
    expect(provider.map([claimed(), settled()], LATER)).toBeNull();
    expect(provider.map([], LATER)).toBeNull();
    expect(provider.map([decided({ currency: "XXX" })], LATER)).toBeNull();
    // Facts of another purchase are not read as this one's.
    const other = "7b2d3e4f-5061-4b72-8c83-a4b5c6d7e8f9";
    const draft = stated([decided(), claimed({ intent_id: other }), settled({ intent_id: other })]);
    expect(draft.execution).toMatchObject({ status: "NOT_EXECUTED" });
  });

  it("collects each purchase decided inside the window, stated as it stands at the window's end", () => {
    const second = "7b2d3e4f-5061-4b72-8c83-a4b5c6d7e8f9";
    const facts: CardOutcomeFact[] = [
      decided(),
      decided({ intent_id: second, at: at(10), verdict: "BLOCK", held_until: null }),
      claimed(),
      settled(),
      // Decided before the window: its later facts state nothing on their own.
      claimed({ intent_id: "8c3e4f50-6172-4c83-9d94-b5c6d7e8f9a0", at: at(20) }),
    ];
    const drafts = provider.collect(facts, {
      from: new Date(Date.parse(at(0))),
      to: LATER,
    });
    expect(drafts.map((draft) => draft.decision?.disposition).sort()).toEqual(["BLOCK", "PROCEED"]);
    expect(provider.collect(facts, { from: new Date(Date.parse(at(5))), to: LATER })).toHaveLength(
      1,
    );
    expect(
      provider.collect(facts, {
        from: new Date(Date.parse(at(-60))),
        to: new Date(Date.parse(at(9))),
      }),
    ).toHaveLength(1);
  });

  it("raises a subject's revision only when its evidence changes, and states a correction as the next one", async () => {
    const store = new OutcomeEvidenceStore();
    const record = async (facts: readonly CardOutcomeFact[], now: Date) => {
      const draft = stated(facts, now);
      return await store.record([{ draft, sha256: outcomeDigest(draft as unknown as JsonValue) }]);
    };
    expect(await record([decided()], MEANWHILE)).toEqual({
      recorded: 1,
      unchanged: 0,
      exhausted: 0,
    });
    // The same facts at a later moment while nothing lapsed: unchanged, no new revision.
    expect(await record([decided()], new Date(Date.parse(at(150))))).toEqual({
      recorded: 0,
      unchanged: 1,
      exhausted: 0,
    });
    // The issuer claimed and approved: the evidence changed, so it is the next revision.
    expect(await record([decided(), claimed(), settled()], LATER)).toEqual({
      recorded: 1,
      unchanged: 0,
      exhausted: 0,
    });
    const [owed] = await store.owed(10);
    expect(owed).toMatchObject({ revision: 2, execution: { status: "COMMITTED" } });
  });
});
