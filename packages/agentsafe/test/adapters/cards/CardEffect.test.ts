import { describe, expect, it } from "vitest";
import {
  CARD_EFFECT_TYPE,
  cardExecutionResult,
  cardExpectedEffect,
  cardResultRecord,
  prepareCardPurchase,
  type CardResultInput,
} from "../../../src/adapters/cards/CardEffect.js";
import { effectBlock } from "../../../src/adapters/AdapterActionHandler.js";
import { jcsDigest } from "../../../src/adapters/JcsDigest.js";

const purchase = {
  cardTokenRef: "fixture_card_ref_0042",
  amountMinor: 4_250,
  currency: "EUR",
  merchantId: "fixture_merchant_17",
};

const authorization = {
  authorization_id: "fixture_auth_1",
  card_token_ref: "fixture_card_ref_0042",
  amount_minor: 4_000,
  currency: "EUR",
  merchant_id: "fixture_merchant_17",
};

function input(overrides: Partial<CardResultInput> = {}): CardResultInput {
  return {
    purchase,
    prepared: prepareCardPurchase(purchase),
    authorization,
    result: { status: "APPROVED" },
    leaseExpired: false,
    observer: { id: "fixture_observer", version: "0.1.0" },
    correlationId: "00000000-0000-4000-8000-000000000001",
    idempotencyKey: "fixture-key",
    observedAt: "2026-10-02T00:00:00.000Z",
    ...overrides,
  };
}

describe("the card effect", () => {
  it("projects a purchase as a ceiling, naming a category only when there is one", () => {
    expect(cardExpectedEffect(purchase)).toEqual({
      card_token_ref: "fixture_card_ref_0042",
      merchant_id: "fixture_merchant_17",
      currency: "EUR",
      amount_minor_ceiling: 4_250,
    });
    expect(cardExpectedEffect({ ...purchase, mcc: "5411" })).toMatchObject({ mcc: "5411" });
    const prepared = prepareCardPurchase(purchase);
    expect(prepared).toMatchObject({
      expectedEffectDigest: jcsDigest(cardExpectedEffect(purchase)),
      intentDigest: jcsDigest(purchase),
      requestDigest: jcsDigest(purchase),
      resourceRef: "card:fixture_card_ref_0042",
      effectType: CARD_EFFECT_TYPE,
      domain: "CARDS",
      actionType: "card.purchase",
    });
  });

  it("confirms an approval inside the ceiling, whatever amount under it", () => {
    for (const result of [
      { status: "APPROVED" as const },
      { status: "APPROVED" as const, approved_amount_minor: 4_250 },
      { status: "APPROVED" as const, approved_amount_minor: 1 },
    ]) {
      const record = cardResultRecord(input({ result }));
      expect(record).toMatchObject({
        outcome: "COMMITTED",
        comparison: "MATCH",
        confirmation: "CONFIRMED",
        observationMethod: "EVENT_CONFIRMATION",
        providerReference: "fixture_auth_1",
        responseDigest: jcsDigest(result),
        observedEffectDigest: record.expectedEffectDigest,
      });
    }
  });

  it("reads an approval above the ceiling as a mismatch on exactly that field", () => {
    const record = cardResultRecord(
      input({ result: { status: "APPROVED", approved_amount_minor: 4_251 } }),
    );
    expect(record).toMatchObject({
      outcome: "COMMITTED",
      comparison: "MISMATCH",
      mismatched: ["amount_minor_ceiling"],
      confirmation: "UNKNOWN",
      reasonCodes: ["EFFECT_MISMATCH"],
    });
  });

  it("compares the category the issuer reported where the purchase named one", () => {
    const named = { ...purchase, mcc: "5411" };
    const prepared = prepareCardPurchase(named);
    expect(
      cardResultRecord(
        input({ purchase: named, prepared, authorization: { ...authorization, mcc: "5411" } }),
      ).comparison,
    ).toBe("MATCH");
    expect(cardResultRecord(input({ purchase: named, prepared })).mismatched).toEqual(["mcc"]);
  });

  it("records a decline as a refusal and a late result as indeterminate", () => {
    expect(cardResultRecord(input({ result: { status: "DECLINED" } }))).toMatchObject({
      outcome: "FAILED",
      confirmation: "NOT_EFFECTED",
      observedEffectDigest: null,
      reasonCodes: ["ISSUER_DECLINED"],
    });
    const late = cardResultRecord(input({ leaseExpired: true }));
    expect(late).toMatchObject({
      outcome: "INDETERMINATE",
      confirmation: "UNKNOWN",
      reasonCodes: ["INDETERMINATE_OUTCOME"],
    });
    expect((late.evidence["outcome"] as Record<string, unknown>)["failure_reason"]).toBe(
      "CLAIM_LEASE_EXPIRED",
    );
  });

  it("reads into the same effect block a handler's result does", () => {
    const record = cardResultRecord(input());
    expect(effectBlock(cardExecutionResult(record))).toMatchObject({
      outcome: "COMMITTED",
      confirmation: "CONFIRMED",
      comparison: "MATCH",
      mismatched_fields: [],
      observation_method: "EVENT_CONFIRMATION",
      expected_effect_digest: record.expectedEffectDigest,
      provider_reference: "fixture_auth_1",
      evidence_digest: record.evidenceDigest,
      receipt_comparison: "ABSENT",
      receipt_status: null,
    });
  });
});
