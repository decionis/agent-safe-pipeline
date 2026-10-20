import { z } from "zod";
import type { JsonValue } from "@decionis/agent-safe-pipeline";
import { jcsDigest } from "../adapters/JcsDigest.js";

/**
 * Core's outcome evidence wire contract (`decionis.outcomes.evidence/1`, inside
 * `decionis.outcomes.submission/1`), mirrored here. Core owns the meter: the signed agreement,
 * the one `OutcomeCalculator` that classifies, the append-only ledger and the signed monthly
 * statement. AgentSafe only states what it recorded about its card purchases and submits it with
 * its producer token.
 *
 * Owner: decionis/Decionis, `packages/shared/src/outcomes/Evidence.ts`, generated to
 * `packages/shared/contracts/OutcomeEvidence.v1.json` (owner revision e264bfbf5, source digest
 * 865c60e2…). The exact bytes are vendored at `packages/agentsafe/contracts/OutcomeEvidence.v1.json`
 * and pinned by {@link OUTCOME_EVIDENCE_CONTRACT_SHA256}: a test fails when the copy drifts, and
 * holds every submission this package builds to the vendored schema.
 */
export const OUTCOME_EVIDENCE_VERSION = "decionis.outcomes.evidence/1" as const;
export const OUTCOME_SUBMISSION_VERSION = "decionis.outcomes.submission/1" as const;
export const OUTCOME_EVIDENCE_LIMITS = { batch: 1000, reasons: 30, exclusions: 10 } as const;
/** SHA-256 of the vendored owner bytes (`packages/agentsafe/contracts/OutcomeEvidence.v1.json`). */
export const OUTCOME_EVIDENCE_CONTRACT_SHA256 =
  "488c42003adce72cadfd6096586ebdb1c4bb79801e796810da78000bdded3d5b";

const HEX = /^[a-f0-9]{64}$/;
const hex = z.string().regex(HEX);
export const OUTCOME_CODE = /^[A-Z][A-Z0-9_]{0,119}$/;
const code = z.string().regex(OUTCOME_CODE);
const instant = z.string().datetime({ offset: true }).max(40);
const uuid = z.string().uuid();

/** Integer minor units in the transaction currency at its own scale; never converted. */
export const OutcomeMoneySchema = z.strictObject({
  currency: z.string().regex(/^[A-Z]{3}$/),
  scale: z.number().int().min(0).max(6),
  amount_minor: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
});

/**
 * One business action, normalized by its producer. A later revision of the same subject
 * supersedes the earlier one; business identifiers never leave AgentSafe, only digests. The
 * three cross-field rules are Core's, and the JSON Schema cannot state them: governed evidence
 * names its decision, only a held or blocked action is reviewed, and the financial result stays
 * in the transaction currency.
 */
export const OutcomeEvidenceSchema = z
  .strictObject({
    version: z.literal(OUTCOME_EVIDENCE_VERSION),
    subject_digest: hex,
    revision: z.number().int().min(1).max(10_000),
    platform: z.string().regex(/^[a-z0-9][a-z0-9-]{0,99}$/),
    connection_id: uuid.nullable(),
    action_type: code,
    occurred_at: instant,
    amount: OutcomeMoneySchema,
    coverage: z.enum(["GOVERNED", "UNGOVERNED", "OBSERVED"]),
    decision: z
      .strictObject({
        decision_id: z.string().min(1).max(120).nullable(),
        dossier_id: z.string().min(1).max(200).nullable(),
        disposition: z.enum(["PROCEED", "HOLD", "BLOCK"]),
        mode: z.enum(["SHADOW", "PARALLEL", "ENFORCEMENT"]),
        decided_at: instant,
        reason_codes: z.array(code).max(OUTCOME_EVIDENCE_LIMITS.reasons),
      })
      .nullable(),
    review: z
      .strictObject({
        case_id: z.string().min(1).max(200),
        outcome: z.enum(["RELEASED", "REJECTED"]),
        confirmation: z.enum(["CONFIRMED_PROBLEM", "LEGITIMATE", "UNCONFIRMED"]),
        confirmed_by: z.enum(["REVIEWER", "CUSTOMER"]).nullable(),
        reviewer: z.enum(["DESK", "CUSTOMER"]),
        decided_at: instant,
        analyst_minutes: z.number().int().min(0).max(10_000).nullable(),
      })
      .nullable(),
    execution: z
      .strictObject({
        status: z.enum(["COMMITTED", "FAILED", "NOT_EXECUTED", "UNKNOWN"]),
        grant_id: uuid.nullable(),
        receipt_sha256: hex.nullable(),
        at: instant,
      })
      .nullable(),
    financial: z
      .strictObject({
        status: z.enum(["SETTLED", "REVERSED", "PENDING", "UNKNOWN"]),
        amount: OutcomeMoneySchema,
        at: instant,
      })
      .nullable(),
    exclusion_codes: z.array(code).max(OUTCOME_EVIDENCE_LIMITS.exclusions),
    source_sha256: hex,
  })
  .superRefine((evidence, context) => {
    if (evidence.coverage === "GOVERNED" && evidence.decision === null) {
      context.addIssue({ code: "custom", path: ["decision"], message: "OUTCOME_DECISION_MISSING" });
    }
    if (evidence.review !== null && evidence.decision?.disposition === "PROCEED") {
      context.addIssue({ code: "custom", path: ["review"], message: "OUTCOME_REVIEW_OF_PROCEED" });
    }
    if (
      evidence.financial !== null &&
      evidence.financial.amount.currency !== evidence.amount.currency
    ) {
      context.addIssue({
        code: "custom",
        path: ["financial", "amount"],
        message: "OUTCOME_FINANCIAL_CURRENCY",
      });
    }
  });

/**
 * `POST /v1/outcomes/evidence`: the producer token names the producer, the body names the
 * organization it observed. One revision per subject in a batch, as Core holds it.
 */
export const OutcomeEvidenceSubmissionSchema = z
  .strictObject({
    version: z.literal(OUTCOME_SUBMISSION_VERSION),
    producer: z.enum(["commerce", "agentsafe"]),
    org_id: uuid,
    evidence: z.array(OutcomeEvidenceSchema).min(1).max(OUTCOME_EVIDENCE_LIMITS.batch),
  })
  .refine(
    (submission) =>
      new Set(submission.evidence.map((item) => item.subject_digest)).size ===
      submission.evidence.length,
    { message: "OUTCOME_SUBJECT_REPEATED", path: ["evidence"] },
  );

export type OutcomeMoney = z.infer<typeof OutcomeMoneySchema>;
export type OutcomeEvidence = z.infer<typeof OutcomeEvidenceSchema>;
export type OutcomeDecision = NonNullable<OutcomeEvidence["decision"]>;
export type OutcomeReview = NonNullable<OutcomeEvidence["review"]>;
export type OutcomeExecution = NonNullable<OutcomeEvidence["execution"]>;
export type OutcomeEvidenceSubmission = z.infer<typeof OutcomeEvidenceSubmissionSchema>;

/**
 * What the producer states about one subject. The revision is not the producer's to choose:
 * the store assigns it from what it last recorded for the subject, so a subject's revision
 * rises exactly when its evidence changes.
 */
export type OutcomeEvidenceDraft = Omit<OutcomeEvidence, "revision">;

/** Whether a string is a digest in the contract's form: 64 lowercase hex characters. */
export function isOutcomeDigest(value: unknown): value is string {
  return typeof value === "string" && HEX.test(value);
}

/**
 * The contract's digest: SHA-256 over the RFC 8785 canonical form, as 64 lowercase hex
 * characters with no prefix. The canonicaliser is the one every other digest here uses.
 */
export function outcomeDigest(value: JsonValue): string {
  return jcsDigest(value).slice("sha256:".length);
}
