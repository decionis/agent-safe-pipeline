import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { CardOutcomeEvidenceProvider } from "../../src/outcomes/CardOutcomeEvidence.js";
import type { CardOutcomeFact } from "../../src/outcomes/CardOutcomeFact.js";
import {
  OUTCOME_EVIDENCE_CONTRACT_SHA256,
  OUTCOME_EVIDENCE_LIMITS,
  OUTCOME_EVIDENCE_VERSION,
  OUTCOME_SUBMISSION_VERSION,
  OutcomeEvidenceSchema,
  OutcomeEvidenceSubmissionSchema,
  type OutcomeEvidence,
  type OutcomeEvidenceSubmission,
} from "../../src/outcomes/OutcomeEvidence.js";
import { ORG_ID, at, claimed, decided, resumed, settled } from "../support/CardOutcomeFacts.js";

/** The vendored owner bytes, read as they are on disk. */
const BYTES = readFileSync(new URL("../../contracts/OutcomeEvidence.v1.json", import.meta.url));
const contract = JSON.parse(BYTES.toString("utf8")) as {
  readonly version: string;
  readonly evidence_version: string;
  readonly endpoints: Record<string, string>;
  readonly limits: Record<string, number>;
  readonly schemas: Record<
    string,
    { readonly properties: Record<string, unknown>; readonly required: readonly string[] }
  >;
};
/** Core's own JSON Schemas, as validators: what the vendored contract says, and nothing of ours. */
const vendored = {
  evidence: z.fromJSONSchema(contract.schemas["OutcomeEvidence"] as never),
  submission: z.fromJSONSchema(contract.schemas["OutcomeEvidenceSubmission"] as never),
};

const LATER = new Date(Date.parse(at(3_600)));
const provider = new CardOutcomeEvidenceProvider();
const intent = (index: number): string =>
  `6a1c2d3e-4f50-4a61-8b72-${index.toString(16).padStart(12, "0")}`;

/** One purchase per way a card purchase can end, stated by the producer, at revision 1. */
function built(): OutcomeEvidence[] {
  const purchases: (readonly CardOutcomeFact[])[] = [
    [decided(), claimed(), settled()],
    [decided(), claimed(), settled({ outcome: "FAILED" })],
    [decided(), claimed(), settled({ outcome: "INDETERMINATE" })],
    [decided(), claimed()],
    [decided()],
    [decided({ held_until: null })],
    [decided({ verdict: "ESCALATE", held_until: null }), resumed(), claimed(), settled()],
    [
      decided({ verdict: "ESCALATE", held_until: null }),
      resumed({ via: "PRESENCE", verdict: "BLOCK", reason_codes: ["PRESENCE_REJECTED"] }),
    ],
    [decided({ verdict: "BLOCK", held_until: null, reason_codes: ["AMOUNT_LIMIT"] })],
    [decided({ mode: "SHADOW", verdict: "ESCALATE", held_until: null })],
    [decided({ mode: "SHADOW", held_until: null })],
    [decided({ currency: "JPY", amount_minor: 900 })],
  ];
  return purchases.map((facts, index) => {
    const own = facts.map((fact) => ({ ...fact, intent_id: intent(index) }));
    const draft = provider.map(own, LATER);
    if (draft === null) throw new Error("the facts stated no evidence");
    return { ...draft, revision: 1 };
  });
}

function submission(evidence: OutcomeEvidence[]): OutcomeEvidenceSubmission {
  return { version: OUTCOME_SUBMISSION_VERSION, producer: "agentsafe", org_id: ORG_ID, evidence };
}

describe("the vendored outcome evidence contract", () => {
  it("pins the exact bytes Core owns", () => {
    expect(createHash("sha256").update(BYTES).digest("hex")).toBe(OUTCOME_EVIDENCE_CONTRACT_SHA256);
    expect(contract.version).toBe(OUTCOME_SUBMISSION_VERSION);
    expect(contract.evidence_version).toBe(OUTCOME_EVIDENCE_VERSION);
    expect(contract.limits).toEqual(OUTCOME_EVIDENCE_LIMITS);
    expect(contract.endpoints["submit"]).toBe("POST /v1/outcomes/evidence");
  });

  it("names exactly the fields the producer builds, every one of them required", () => {
    const [evidence] = built();
    const fields = Object.keys(evidence ?? {}).sort();
    const schema = contract.schemas["OutcomeEvidence"];
    expect(Object.keys(schema?.properties ?? {}).sort()).toEqual(fields);
    expect([...(schema?.required ?? [])].sort()).toEqual(fields);
    const outer = contract.schemas["OutcomeEvidenceSubmission"];
    expect(Object.keys(outer?.properties ?? {}).sort()).toEqual(
      Object.keys(submission(built())).sort(),
    );
  });

  it("accepts every submission the producer builds, and so does this package's validator", () => {
    const whole = submission(built());
    expect(whole.evidence.length).toBeGreaterThan(10);
    expect(vendored.submission.safeParse(whole).success).toBe(true);
    expect(OutcomeEvidenceSubmissionSchema.parse(whole)).toEqual(whole);
    for (const evidence of whole.evidence) {
      expect(vendored.evidence.safeParse(evidence).success).toBe(true);
    }
  });

  it("refuses what the vendored schema refuses", () => {
    const [base] = built();
    if (base === undefined) throw new Error("nothing built");
    const decision = base.decision as NonNullable<OutcomeEvidence["decision"]>;
    const execution = base.execution as NonNullable<OutcomeEvidence["execution"]>;
    const refused: unknown[] = [
      { ...base, extra: true },
      { ...base, revision: 0 },
      { ...base, revision: 10_001 },
      { ...base, subject_digest: "A".repeat(64) },
      { ...base, platform: "Card-Authorization" },
      { ...base, action_type: "card.purchase" },
      { ...base, occurred_at: "yesterday" },
      { ...base, connection_id: "not-a-uuid" },
      { ...base, amount: { currency: "EUR", scale: 2, amount_minor: 1.5 } },
      { ...base, amount: { currency: "EUR", scale: 7, amount_minor: 1 } },
      { ...base, amount: { currency: "eur", scale: 2, amount_minor: 1 } },
      { ...base, coverage: "PARTIAL" },
      { ...base, decision: { ...decision, mode: "OBSERVE" } },
      { ...base, decision: { ...decision, reason_codes: Array.from({ length: 31 }, () => "R") } },
      { ...base, execution: { ...execution, grant_id: "not-a-uuid" } },
      { ...base, execution: { ...execution, status: "PAID" } },
      { ...base, exclusion_codes: Array.from({ length: 11 }, () => "CODE") },
      { ...base, source_sha256: "b".repeat(63) },
    ];
    for (const value of refused) {
      expect(vendored.evidence.safeParse(value).success, JSON.stringify(value)).toBe(false);
      expect(OutcomeEvidenceSchema.safeParse(value).success, JSON.stringify(value)).toBe(false);
    }
  });

  it("adds Core's three cross-field rules, which the JSON Schema cannot state", () => {
    const [base] = built();
    if (base === undefined) throw new Error("nothing built");
    const decision = base.decision as NonNullable<OutcomeEvidence["decision"]>;
    const crossField: OutcomeEvidence[] = [
      { ...base, decision: null },
      {
        ...base,
        review: {
          case_id: "agentsafe:card:x",
          outcome: "RELEASED",
          confirmation: "LEGITIMATE",
          confirmed_by: "CUSTOMER",
          reviewer: "CUSTOMER",
          decided_at: at(5),
          analyst_minutes: null,
        },
        decision: { ...decision, disposition: "PROCEED" },
      },
      {
        ...base,
        financial: {
          status: "SETTLED",
          amount: { currency: "USD", scale: 2, amount_minor: 1 },
          at: at(5),
        },
      },
    ];
    for (const value of crossField) {
      expect(vendored.evidence.safeParse(value).success).toBe(true);
      expect(OutcomeEvidenceSchema.safeParse(value).success).toBe(false);
    }
  });

  it("refuses an empty, oversized, foreign or repeated-subject submission", () => {
    const [base] = built();
    if (base === undefined) throw new Error("nothing built");
    const many = Array.from({ length: 1_001 }, (_, index) => ({
      ...base,
      subject_digest: index.toString(16).padStart(64, "0"),
    }));
    for (const value of [
      submission([]),
      submission(many),
      { ...submission([base]), producer: "walmart" },
      { ...submission([base]), org_id: "not-a-uuid" },
      { ...submission([base]), version: "decionis.outcomes.submission/2" },
    ]) {
      expect(vendored.submission.safeParse(value).success).toBe(false);
      expect(OutcomeEvidenceSubmissionSchema.safeParse(value).success).toBe(false);
    }
    // One revision per subject in a batch: Core keys a batch's items by subject and revision.
    expect(OutcomeEvidenceSubmissionSchema.safeParse(submission([base, base])).success).toBe(false);
  });
});
