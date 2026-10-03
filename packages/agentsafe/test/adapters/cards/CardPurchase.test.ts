import { describe, expect, it } from "vitest";
import {
  bindCardPurchase,
  CARD_PURCHASE_ACTION,
  CardActionError,
  cardAuthorizationOf,
  cardAuthorizationResultOf,
  cardPurchaseOf,
  cardTarget,
  isCardActionName,
  isCardReference,
} from "../../../src/adapters/cards/CardPurchase.js";

const purchase = {
  cardTokenRef: "fixture_card_ref_0042",
  amountMinor: 4_250,
  currency: "EUR",
  merchantId: "fixture_merchant_17",
};

const authorization = {
  authorization_id: "fixture_auth_1",
  card_token_ref: "fixture_card_ref_0042",
  amount_minor: 4_250,
  currency: "EUR",
  merchant_id: "fixture_merchant_17",
};

function codeOf(work: () => unknown): string {
  try {
    work();
  } catch (error) {
    if (error instanceof CardActionError) return error.code;
    throw error;
  }
  throw new Error("expected a refusal");
}

describe("card purchase parameters", () => {
  it("reads a purchase, with or without a merchant category", () => {
    expect(cardPurchaseOf(purchase)).toEqual(purchase);
    expect(cardPurchaseOf({ ...purchase, mcc: "5411" })).toEqual({ ...purchase, mcc: "5411" });
    expect(isCardActionName(CARD_PURCHASE_ACTION)).toBe(true);
    expect(isCardActionName("card.refund")).toBe(false);
    expect(CARD_PURCHASE_ACTION).toBe("card.purchase");
    const error = new CardActionError("CARD_PAN_REFUSED");
    expect(error.name).toBe("CardActionError");
    expect(error.message).toBe("CARD_PAN_REFUSED");
  });

  it("refuses a card number under its own code, before any other rule", () => {
    for (const cardTokenRef of [
      "4111111111111111",
      "4111 1111 1111 1111",
      "tok_4111111111111111",
    ]) {
      expect(codeOf(() => cardPurchaseOf({ ...purchase, cardTokenRef }))).toBe("CARD_PAN_REFUSED");
      // Even when the rest of the purchase is wrong too, or the number is not text.
      expect(codeOf(() => cardPurchaseOf({ cardTokenRef }))).toBe("CARD_PAN_REFUSED");
    }
  });

  it("refuses a card number written as a JSON number, or inside a list", () => {
    expect(codeOf(() => cardPurchaseOf({ ...purchase, cardTokenRef: 4111111111111111 }))).toBe(
      "CARD_PAN_REFUSED",
    );
    expect(codeOf(() => cardPurchaseOf({ ...purchase, cardTokenRef: ["4111111111111111"] }))).toBe(
      "CARD_PAN_REFUSED",
    );
    expect(
      codeOf(() => cardAuthorizationOf({ ...authorization, card_token_ref: 4111111111111111 })),
    ).toBe("CARD_PAN_REFUSED");
  });

  it.each([
    ["no parameters", null],
    ["a list", []],
    ["a number for the card", { ...purchase, cardTokenRef: 4111 }],
    ["an empty card reference", { ...purchase, cardTokenRef: "" }],
    ["a card reference of 201 characters", { ...purchase, cardTokenRef: "a".repeat(201) }],
    ["a space in the card reference", { ...purchase, cardTokenRef: "fixture card" }],
    ["a leading slash in the card reference", { ...purchase, cardTokenRef: "/fixture" }],
    ["a trailing slash in the card reference", { ...purchase, cardTokenRef: "fixture/" }],
    ["a zero amount", { ...purchase, amountMinor: 0 }],
    ["a negative amount", { ...purchase, amountMinor: -1 }],
    ["a fractional amount", { ...purchase, amountMinor: 1.5 }],
    ["an amount past a double's exact integers", { ...purchase, amountMinor: 2 ** 53 }],
    ["an amount as text", { ...purchase, amountMinor: "4250" }],
    ["a lowercase currency", { ...purchase, currency: "eur" }],
    ["a two-letter currency", { ...purchase, currency: "EU" }],
    ["a four-letter currency", { ...purchase, currency: "EURO" }],
    ["a currency after a letter", { ...purchase, currency: "XEUR" }],
    ["a currency before a letter", { ...purchase, currency: "EURX" }],
    ["an empty merchant", { ...purchase, merchantId: "" }],
    ["a merchant of 201 characters", { ...purchase, merchantId: "m".repeat(201) }],
    ["a three-digit category", { ...purchase, mcc: "541" }],
    ["a five-digit category", { ...purchase, mcc: "54111" }],
    ["a category after a letter", { ...purchase, mcc: "x5411" }],
    ["a category before a letter", { ...purchase, mcc: "5411x" }],
    ["a lettered category", { ...purchase, mcc: "54a1" }],
    ["a field the action does not name", { ...purchase, pan: "x" }],
  ])("refuses %s", (_name, parameters) => {
    expect(codeOf(() => cardPurchaseOf(parameters))).toBe("CARD_PURCHASE_INVALID");
  });

  it("accepts references at their bounds and in their whole character set", () => {
    for (const cardTokenRef of ["a", "a".repeat(200), "tok_A-1.b:2"]) {
      expect(cardPurchaseOf({ ...purchase, cardTokenRef }).cardTokenRef).toBe(cardTokenRef);
    }
    expect(cardPurchaseOf({ ...purchase, merchantId: "m".repeat(200) }).merchantId).toHaveLength(
      200,
    );
    expect(cardPurchaseOf({ ...purchase, amountMinor: 1 }).amountMinor).toBe(1);
    expect(cardPurchaseOf({ ...purchase, amountMinor: 2 ** 53 - 1 }).amountMinor).toBe(2 ** 53 - 1);
  });

  it("refuses a currency whose exponent this build does not know", () => {
    expect(codeOf(() => cardPurchaseOf({ ...purchase, currency: "XYZ" }))).toBe(
      "CARD_CURRENCY_UNSUPPORTED",
    );
    expect(cardPurchaseOf({ ...purchase, currency: "JPY" }).currency).toBe("JPY");
  });

  it("derives the target from the card and refuses a caller naming another", () => {
    expect(cardTarget(purchase)).toBe("card:fixture_card_ref_0042");
    expect(
      bindCardPurchase({ target: "card:fixture_card_ref_0042", parameters: purchase }),
    ).toEqual(purchase);
    expect(
      codeOf(() => bindCardPurchase({ target: "card:fixture_card_ref_9", parameters: purchase })),
    ).toBe("CARD_TARGET_MISMATCH");
    expect(
      codeOf(() =>
        bindCardPurchase({
          target: "card:4111111111111111",
          parameters: { cardTokenRef: "4111111111111111" },
        }),
      ),
    ).toBe("CARD_PAN_REFUSED");
  });
});

describe("card authorization requests", () => {
  it("reads what the issuer's hook asks", () => {
    expect(cardAuthorizationOf(authorization)).toEqual(authorization);
    expect(cardAuthorizationOf({ ...authorization, mcc: "5411" })).toMatchObject({ mcc: "5411" });
  });

  it("refuses a card number under its own code, and anything malformed", () => {
    expect(
      codeOf(() => cardAuthorizationOf({ ...authorization, card_token_ref: "5555555555554444" })),
    ).toBe("CARD_PAN_REFUSED");
    expect(codeOf(() => cardAuthorizationOf({ card_token_ref: "5555-5555-5555-4444" }))).toBe(
      "CARD_PAN_REFUSED",
    );
    for (const input of [
      null,
      { ...authorization, authorization_id: "" },
      { ...authorization, authorization_id: "a b" },
      { ...authorization, card_token_ref: "" },
      { ...authorization, amount_minor: 0 },
      { ...authorization, amount_minor: 1.5 },
      { ...authorization, currency: "eur" },
      { ...authorization, merchant_id: "" },
      { ...authorization, mcc: "541" },
      { ...authorization, pan: "x" },
    ]) {
      expect(codeOf(() => cardAuthorizationOf(input))).toBe("CARD_AUTHORIZATION_INVALID");
    }
  });

  it("reads a result and refuses anything else", () => {
    expect(cardAuthorizationResultOf({ status: "DECLINED" })).toEqual({ status: "DECLINED" });
    expect(
      cardAuthorizationResultOf({
        status: "APPROVED",
        approved_amount_minor: 1,
        auth_code: "A1B2C3",
      }),
    ).toEqual({ status: "APPROVED", approved_amount_minor: 1, auth_code: "A1B2C3" });
    expect(
      cardAuthorizationResultOf({ status: "APPROVED", auth_code: "Z".repeat(12) }),
    ).toMatchObject({ auth_code: "Z".repeat(12) });
    for (const input of [
      null,
      {},
      { status: "PENDING" },
      { status: "APPROVED", approved_amount_minor: 0 },
      { status: "APPROVED", auth_code: "" },
      { status: "APPROVED", auth_code: "a1b2c3" },
      { status: "APPROVED", auth_code: "A".repeat(13) },
      { status: "APPROVED", auth_code: "-A1" },
      { status: "APPROVED", auth_code: "A1-" },
      { status: "APPROVED", note: "x" },
    ]) {
      expect(codeOf(() => cardAuthorizationResultOf(input))).toBe(
        "CARD_AUTHORIZATION_RESULT_INVALID",
      );
    }
  });

  it("holds an authorization id from a path to the same rule", () => {
    expect(isCardReference("fixture_auth.1:x-y")).toBe(true);
    expect(isCardReference("a".repeat(200))).toBe(true);
    for (const value of ["", "a".repeat(201), "%41", "a/b", " a", "a "]) {
      expect([value, isCardReference(value)]).toEqual([value, false]);
    }
  });
});
