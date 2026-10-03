import { describe, expect, it } from "vitest";
import {
  matchCardAuthorization,
  type CardAuthorizationView,
  type HeldCardGrantView,
} from "../../../src/adapters/cards/CardAuthorizationMatcher.js";

const NOW = 1_800_000_000_000;

const grant: HeldCardGrantView = {
  cardTokenRef: "fixture_card_ref_0042",
  amountMinor: 4_250,
  currency: "EUR",
  merchantId: "fixture_merchant_17",
  mcc: null,
  expiresAtMs: NOW + 1,
  used: false,
};

const authorization: CardAuthorizationView = {
  cardTokenRef: "fixture_card_ref_0042",
  amountMinor: 4_250,
  currency: "EUR",
  merchantId: "fixture_merchant_17",
  mcc: "5411",
};

describe("matchCardAuthorization", () => {
  it("matches the authorised purchase, and anything less, until the instant the grant expires", () => {
    expect(matchCardAuthorization(grant, authorization, NOW)).toEqual({ decision: "MATCHED" });
    expect(matchCardAuthorization(grant, { ...authorization, amountMinor: 1 }, NOW)).toEqual({
      decision: "MATCHED",
    });
    expect(matchCardAuthorization(grant, authorization, NOW + 1)).toEqual({
      decision: "NO_MATCH",
      code: "GRANT_EXPIRED",
    });
  });

  it("refuses one minor unit more than the grant", () => {
    expect(matchCardAuthorization(grant, { ...authorization, amountMinor: 4_251 }, NOW)).toEqual({
      decision: "NO_MATCH",
      code: "AMOUNT_EXCEEDS_GRANT",
    });
  });

  it.each([
    ["no grant", undefined, authorization, "NO_GRANT"],
    ["a spent grant", { ...grant, used: true }, authorization, "GRANT_ALREADY_USED"],
    ["an expired grant", { ...grant, expiresAtMs: NOW - 1 }, authorization, "GRANT_EXPIRED"],
    [
      "another card",
      grant,
      { ...authorization, cardTokenRef: "fixture_card_ref_9" },
      "CARD_TOKEN_MISMATCH",
    ],
    ["another currency", grant, { ...authorization, currency: "USD" }, "CURRENCY_MISMATCH"],
    [
      "another merchant",
      grant,
      { ...authorization, merchantId: "fixture_merchant_18" },
      "MERCHANT_MISMATCH",
    ],
    [
      "another category",
      { ...grant, mcc: "5411" },
      { ...authorization, mcc: "5812" },
      "MCC_MISMATCH",
    ],
    [
      "no category where one was named",
      { ...grant, mcc: "5411" },
      { ...authorization, mcc: null },
      "MCC_MISMATCH",
    ],
  ] as const)("answers %s with its code", (_name, held, asked, code) => {
    expect(matchCardAuthorization(held, asked, NOW)).toEqual({ decision: "NO_MATCH", code });
  });

  it("compares a category only where the purchase named one", () => {
    expect(matchCardAuthorization({ ...grant, mcc: "5411" }, authorization, NOW)).toEqual({
      decision: "MATCHED",
    });
    expect(matchCardAuthorization(grant, { ...authorization, mcc: null }, NOW)).toEqual({
      decision: "MATCHED",
    });
  });

  it("names the first rule that fails, in order", () => {
    const everything: CardAuthorizationView = {
      cardTokenRef: "fixture_card_ref_9",
      amountMinor: 9_999,
      currency: "USD",
      merchantId: "fixture_merchant_18",
      mcc: "5812",
    };
    const spent = { ...grant, used: true, expiresAtMs: NOW - 1, mcc: "5411" };
    expect(matchCardAuthorization(spent, everything, NOW)).toMatchObject({
      code: "GRANT_ALREADY_USED",
    });
    expect(matchCardAuthorization({ ...spent, used: false }, everything, NOW)).toMatchObject({
      code: "GRANT_EXPIRED",
    });
    const live = { ...spent, used: false, expiresAtMs: NOW + 1 };
    expect(matchCardAuthorization(live, everything, NOW)).toMatchObject({
      code: "CARD_TOKEN_MISMATCH",
    });
    expect(
      matchCardAuthorization(live, { ...everything, cardTokenRef: grant.cardTokenRef }, NOW),
    ).toMatchObject({ code: "CURRENCY_MISMATCH" });
    expect(
      matchCardAuthorization(
        live,
        { ...everything, cardTokenRef: grant.cardTokenRef, currency: "EUR" },
        NOW,
      ),
    ).toMatchObject({ code: "MERCHANT_MISMATCH" });
    expect(
      matchCardAuthorization(
        live,
        {
          ...everything,
          cardTokenRef: grant.cardTokenRef,
          currency: "EUR",
          merchantId: grant.merchantId,
        },
        NOW,
      ),
    ).toMatchObject({ code: "MCC_MISMATCH" });
  });
});
