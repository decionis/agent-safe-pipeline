import { describe, expect, it } from "vitest";
import {
  authorityEffectEvidence,
  buildEffectRecord,
  confirmationFor,
} from "../../src/adapters/EffectEvidenceBuilder.js";
import { EffectEvidenceRegister } from "../../src/adapters/EffectEvidenceRegister.js";
import { jcsDigest } from "../../src/adapters/JcsDigest.js";
import type { PreparedAction, ProviderResult } from "../../src/adapters/EffectAdapter.js";

const expectedEffect = { effect_type: "LOAN_DISBURSEMENT", amount: "250000.00", currency: "CHF" };

const prepared: PreparedAction = {
  expectedEffect,
  expectedEffectDigest: jcsDigest(expectedEffect),
  intentDigest: jcsDigest({ action: "DISBURSE_LOAN" }),
  requestDigest: jcsDigest({ operation: "DISBURSE" }),
  resourceRef: "fixture_loan_84721",
  effectType: "LOAN_DISBURSEMENT",
  domain: "LOAN_DISBURSEMENT",
  actionType: "DISBURSE_LOAN",
};

const committed = (overrides: Partial<ProviderResult> = {}): ProviderResult => ({
  status: "COMMITTED",
  providerStatus: "POSTED",
  providerReference: "fixture_provider_ref_1",
  responseDigest: jcsDigest({ status: "POSTED" }),
  failureReason: null,
  observed: { ...expectedEffect },
  observationMethod: "READ_AFTER_WRITE",
  providerGenerated: true,
  source: "CORE_BANKING_RESPONSE",
  ...overrides,
});

const record = (result: ProviderResult | null, indeterminate?: { reason: string }) =>
  buildEffectRecord({
    prepared,
    result,
    ...(indeterminate === undefined
      ? {}
      : { indeterminate: { ...indeterminate, providerStatus: null } }),
    observer: { id: "synthetic-adapter", version: "0.1.0" },
    correlationId: "11111111-1111-4111-8111-111111111111",
    idempotencyKey: "synthetic-key-1",
    observedAt: "2026-03-02T10:00:00.000Z",
  });

/** A receipt's shape, unsigned, saying what the payload says. */
const receiptSaying = (effect: Record<string, unknown>): string =>
  `${Buffer.from('{"alg":"EdDSA"}').toString("base64url")}.${Buffer.from(
    JSON.stringify({ sub: "fixture_grant_1", effect }),
  ).toString("base64url")}.c2ln`;

describe("confirmationFor", () => {
  it("never turns an acknowledgement into a confirmation", () => {
    expect(confirmationFor("COMMITTED", "MATCH", "DOWNSTREAM_ACK")).toBe("PENDING");
    expect(confirmationFor("COMMITTED", "MATCH", "READ_AFTER_WRITE")).toBe("CONFIRMED");
    expect(confirmationFor("COMMITTED", "PENDING", "READ_AFTER_WRITE")).toBe("PENDING");
    expect(confirmationFor("COMMITTED", "MISMATCH", "READ_AFTER_WRITE")).toBe("UNKNOWN");
    expect(confirmationFor("FAILED", "PENDING", "DOWNSTREAM_ACK")).toBe("NOT_EFFECTED");
    expect(confirmationFor("INDETERMINATE", "PENDING", "DOWNSTREAM_ACK")).toBe("UNKNOWN");
  });

  it("lets a receipt that agrees, or says nothing, leave the confirmation as the observation had it", () => {
    expect(confirmationFor("COMMITTED", "MATCH", "READ_AFTER_WRITE", "MATCH")).toBe("CONFIRMED");
    expect(confirmationFor("COMMITTED", "MATCH", "READ_AFTER_WRITE", "SILENT")).toBe("CONFIRMED");
    expect(confirmationFor("COMMITTED", "MATCH", "DOWNSTREAM_ACK", "MATCH")).toBe("PENDING");
    expect(confirmationFor("FAILED", "PENDING", "DOWNSTREAM_ACK", "MATCH")).toBe("NOT_EFFECTED");
  });

  it("makes a receipt that contradicts the account unknown, whatever the observation said", () => {
    expect(confirmationFor("COMMITTED", "MATCH", "READ_AFTER_WRITE", "MISMATCH")).toBe("UNKNOWN");
    expect(confirmationFor("FAILED", "PENDING", "DOWNSTREAM_ACK", "MISMATCH")).toBe("UNKNOWN");
    expect(confirmationFor("INDETERMINATE", "PENDING", "DOWNSTREAM_ACK", "MISMATCH")).toBe(
      "UNKNOWN",
    );
  });
});

describe("buildEffectRecord", () => {
  it("confirms a read-back that matches, and digests its own record", () => {
    const built = record(committed());
    expect(built.outcome).toBe("COMMITTED");
    expect(built.comparison).toBe("MATCH");
    expect(built.confirmation).toBe("CONFIRMED");
    expect(built.observedEffectDigest).toBe(prepared.expectedEffectDigest);
    expect(built.evidenceDigest).toBe(jcsDigest(built.evidence));
    expect(built.reasonCodes).toEqual([]);
    expect(built.evidence["evidence_status"]).toBe("COMPLETE");
  });

  it("names a mismatch, keeps both digests, and never confirms it", () => {
    const built = record(committed({ observed: { ...expectedEffect, amount: "1.00" } }));
    expect(built.comparison).toBe("MISMATCH");
    expect(built.mismatched).toEqual(["amount"]);
    expect(built.confirmation).toBe("UNKNOWN");
    expect(built.observedEffectDigest).not.toBe(built.expectedEffectDigest);
    expect(built.reasonCodes).toContain("EFFECT_MISMATCH");
    const effect = built.evidence["effect"] as Record<string, unknown>;
    expect(effect["mismatched_fields"]).toEqual(["amount"]);
  });

  it("leaves an acknowledgement pending, with no observation invented for it", () => {
    const built = record(
      committed({
        observed: null,
        observationMethod: "DOWNSTREAM_ACK",
        providerStatus: "ACCEPTED",
      }),
    );
    expect(built.confirmation).toBe("PENDING");
    expect(built.comparison).toBe("PENDING");
    expect(built.observedEffectDigest).toBeNull();
    expect(built.evidence["evidence_status"]).toBe("INCOMPLETE");
  });

  it("reports a deterministic refusal as effecting nothing, with the provider's own code", () => {
    const built = record(
      committed({ status: "FAILED", observed: null, failureReason: "POLICY_STATE_CHANGED" }),
    );
    expect(built.outcome).toBe("FAILED");
    expect(built.confirmation).toBe("NOT_EFFECTED");
    expect(built.reasonCodes).toEqual(["POLICY_STATE_CHANGED"]);
  });

  it("reports an outcome nobody determined as indeterminate and unknown", () => {
    const built = record(null, { reason: "PROVIDER_UNREACHABLE" });
    expect(built.outcome).toBe("INDETERMINATE");
    expect(built.confirmation).toBe("UNKNOWN");
    expect(built.reasonCodes).toEqual(["INDETERMINATE_OUTCOME"]);
    expect(built.providerReference).toBeNull();
    const outcome = built.evidence["outcome"] as Record<string, unknown>;
    expect(outcome["failure_reason"]).toBe("PROVIDER_UNREACHABLE");
  });

  it("carries no provider body, parameter, or credential", () => {
    const text = JSON.stringify(record(committed()).evidence);
    expect(text).not.toContain("Bearer");
    expect(text).not.toContain("fixture_account");
    expect(text).toContain("sha256:");
  });

  it("records what the provider's receipt states beside the observation, and agreement between them", () => {
    const without = record(committed());
    expect(without.receipt).toEqual({ comparison: "ABSENT", status: null, digest: null });
    expect(without.evidence["effect"]).not.toHaveProperty("receipt");
    const agreeing = record(
      committed({
        receipt: receiptSaying({
          status: "EFFECTED",
          digest: prepared.expectedEffectDigest,
          effected_at: "2026-03-02T10:00:01Z",
        }),
      }),
    );
    expect(agreeing.receipt).toEqual({
      comparison: "MATCH",
      status: "EFFECTED",
      digest: prepared.expectedEffectDigest,
    });
    expect(agreeing.confirmation).toBe("CONFIRMED");
    expect(agreeing.reasonCodes).toEqual([]);
    expect((agreeing.evidence["effect"] as Record<string, unknown>)["receipt"]).toEqual({
      comparison: "MATCH",
      status: "EFFECTED",
      digest: prepared.expectedEffectDigest,
    });
    // A record without a receipt is byte for byte what it was before receipts existed.
    expect(agreeing.evidenceDigest).not.toBe(without.evidenceDigest);
    const silent = record(committed({ receipt: receiptSaying({ status: "EFFECTED" }) }));
    expect(silent.receipt).toEqual({ comparison: "SILENT", status: "EFFECTED", digest: null });
    expect(silent.confirmation).toBe("CONFIRMED");
  });

  it("names a receipt that contradicts the account as a mismatch nobody can confirm", () => {
    const contradicted = record(
      committed({
        receipt: receiptSaying({ status: "EFFECTED", digest: `sha256:${"9".repeat(64)}` }),
      }),
    );
    expect(contradicted.comparison).toBe("MATCH");
    expect(contradicted.receipt.comparison).toBe("MISMATCH");
    expect(contradicted.confirmation).toBe("UNKNOWN");
    expect(contradicted.reasonCodes).toEqual(["EFFECT_MISMATCH"]);
    // The provider refused in its answer and says it effected in its receipt.
    const refusedYetEffected = record(
      committed({
        status: "FAILED",
        observed: null,
        failureReason: "POLICY_STATE_CHANGED",
        receipt: receiptSaying({ status: "EFFECTED" }),
      }),
    );
    expect(refusedYetEffected.receipt.comparison).toBe("MISMATCH");
    expect(refusedYetEffected.confirmation).toBe("UNKNOWN");
    expect(refusedYetEffected.reasonCodes).toEqual(["EFFECT_MISMATCH", "POLICY_STATE_CHANGED"]);
    // An observation that mismatched and a receipt that mismatched name the code once.
    const both = record(
      committed({
        observed: { ...expectedEffect, amount: "1.00" },
        receipt: receiptSaying({ status: "REFUSED" }),
      }),
    );
    expect(both.reasonCodes).toEqual(["EFFECT_MISMATCH"]);
  });
});

describe("authorityEffectEvidence", () => {
  it("reports a confirmed observation as confirmed and a mismatch as unconfirmed", () => {
    const confirmed = authorityEffectEvidence(record(committed()), "corr-1", {
      id: "synthetic-adapter",
      version: "0.1.0",
    });
    expect(confirmed.status).toBe("CONFIRMED");
    expect(confirmed.execution_correlation_id).toBe("corr-1");
    expect(confirmed.expected_effect_digest).toBe(prepared.expectedEffectDigest);
    const mismatch = authorityEffectEvidence(
      record(committed({ observed: { ...expectedEffect, amount: "1.00" } })),
      "corr-2",
      { id: "synthetic-adapter", version: "0.1.0" },
    );
    expect(mismatch.status).toBe("UNCONFIRMED");
    expect(mismatch.observed_effect_digest).not.toBe(mismatch.expected_effect_digest);
  });
});

describe("EffectEvidenceRegister", () => {
  it("hands one attempt's observation to one taker, and nothing to another attempt", () => {
    const register = new EffectEvidenceRegister();
    const one = Object.freeze({ grantId: "g1" }) as never;
    const other = Object.freeze({ grantId: "g2" }) as never;
    const built = record(committed());
    register.attach(one, built);
    expect(register.take(other)).toBeNull();
    expect(register.take(one)).toBe(built);
    expect(register.take(one)).toBeNull();
  });
});
