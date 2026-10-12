import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  SIGNED_SIGNAL_MAX_LIFETIME_SECONDS,
  SIGNED_SIGNAL_TYPE,
  mintSignedSignal,
  signedSignalFacts,
  verifySignedSignal,
  verifySignedSignals,
  type SignedSignalClaims,
  type SignedSignalIntentView,
  type SignedSignalKey,
} from "../../src/testing/SignedSignals.js";

const ORG = "00000000-0000-4000-8000-000000000001";
const KOARD = generateKeyPairSync("ed25519");
const OTHER = generateKeyPairSync("ed25519");
const KEYS: readonly SignedSignalKey[] = [
  { kid: "koard-signal-key-a", issuer: "koard", publicKey: KOARD.publicKey },
];
const findKey = (kid: string): SignedSignalKey | null =>
  KEYS.find((key) => key.kid === kid) ?? null;
const NOW = Date.parse("2026-10-13T10:00:00.000Z");

const DELEGATION: SignedSignalClaims = {
  name: "card_delegation",
  method: "card_tap",
  result: "VERIFIED",
  agent: "synthetic-agent-1",
  scope: { actions: ["card.purchase"] },
  limits: { currency: "usd", amount_minor: 5000 },
  card_token_ref: "tok_synthetic_card_a",
};

const PURCHASE: SignedSignalIntentView = {
  action: "card.purchase",
  actorId: "synthetic-agent-1",
  resource: "card:tok_synthetic_card_a",
  parameters: {
    cardTokenRef: "tok_synthetic_card_a",
    amountMinor: 4000,
    currency: "USD",
    merchantId: "merchant_synthetic_1",
  },
};

function mint(overrides: Partial<Parameters<typeof mintSignedSignal>[0]> = {}): string {
  return mintSignedSignal({
    privateKey: KOARD.privateKey,
    kid: "koard-signal-key-a",
    issuer: "koard",
    audience: ORG,
    subject: "cardholder-synthetic-7",
    signal: DELEGATION,
    issuedAtMs: NOW - 60_000,
    jti: "signal-synthetic-1",
    ...overrides,
  });
}

describe("verifySignedSignal", () => {
  it("verifies a producer's token and reads its claims", () => {
    const verification = verifySignedSignal(mint(), { orgId: ORG, findKey, nowMs: NOW });
    expect(verification.ok).toBe(true);
    if (!verification.ok) return;
    expect(verification.signal).toMatchObject({
      name: "card_delegation",
      producer: "koard",
      method: "card_tap",
      subject: "cardholder-synthetic-7",
      signal_id: "signal-synthetic-1",
      key_id: "koard-signal-key-a",
      issued_at: "2026-10-13T09:59:00.000Z",
      expires_at: "2026-10-14T09:59:00.000Z",
    });
    expect(verification.signal.evidence_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(verification.signal.claims.limits).toEqual({ currency: "USD", amount_minor: 5000 });
  });

  it.each([
    ["an unregistered key", { kid: "koard-signal-key-z" }, "SIGNED_SIGNAL_KEY_UNKNOWN"],
    [
      "another key under the registered kid",
      { privateKey: OTHER.privateKey },
      "SIGNED_SIGNAL_SIGNATURE_INVALID",
    ],
    ["an issuer other than the key's", { issuer: "someone-else" }, "SIGNED_SIGNAL_ISSUER_MISMATCH"],
    ["the reserved producer name", { issuer: "presence" }, "SIGNED_SIGNAL_ISSUER_MISMATCH"],
    [
      "another organisation's audience",
      { audience: "00000000-0000-4000-8000-000000000002" },
      "SIGNED_SIGNAL_AUDIENCE_MISMATCH",
    ],
    [
      "a token past its expiry",
      { issuedAtMs: NOW - 2 * 24 * 60 * 60 * 1_000 },
      "SIGNED_SIGNAL_EXPIRED",
    ],
    [
      "a lifetime over thirty days",
      { lifetimeSeconds: SIGNED_SIGNAL_MAX_LIFETIME_SECONDS + 1 },
      "SIGNED_SIGNAL_MALFORMED",
    ],
    ["a token from the future", { issuedAtMs: NOW + 10 * 60_000 }, "SIGNED_SIGNAL_MALFORMED"],
    ["a card number as the subject", { subject: "4242424242424242" }, "SIGNED_SIGNAL_MALFORMED"],
    [
      "the wrong token type",
      { header: { typ: "decionis-presence-attestation+jwt" } },
      "SIGNED_SIGNAL_MALFORMED",
    ],
    [
      "a signal the producer did not verify",
      { signal: { ...DELEGATION, result: "FAILED" } },
      "SIGNED_SIGNAL_NOT_VERIFIED",
    ],
    [
      "a claim the contract does not name",
      { signal: { ...DELEGATION, extra: true } as unknown as SignedSignalClaims },
      "SIGNED_SIGNAL_MALFORMED",
    ],
    [
      "a card number as the card reference",
      { signal: { ...DELEGATION, card_token_ref: "4242 4242 4242 4242" } },
      "SIGNED_SIGNAL_MALFORMED",
    ],
    [
      "an empty scope",
      { signal: { ...DELEGATION, scope: { actions: [] } } },
      "SIGNED_SIGNAL_MALFORMED",
    ],
    [
      "a negative limit",
      { signal: { ...DELEGATION, limits: { currency: "USD", amount_minor: -1 } } },
      "SIGNED_SIGNAL_MALFORMED",
    ],
  ])("refuses %s", (_, overrides, code) => {
    expect(verifySignedSignal(mint(overrides), { orgId: ORG, findKey, nowMs: NOW })).toEqual({
      ok: false,
      code,
    });
  });

  it("refuses what is not a compact JWS", () => {
    expect(verifySignedSignal("not.a-token", { orgId: ORG, findKey, nowMs: NOW })).toEqual({
      ok: false,
      code: "SIGNED_SIGNAL_MALFORMED",
    });
    expect(verifySignedSignal("a.b.c", { orgId: ORG, findKey, nowMs: NOW })).toEqual({
      ok: false,
      code: "SIGNED_SIGNAL_MALFORMED",
    });
  });

  it("names the token type the producer must use", () => {
    expect(SIGNED_SIGNAL_TYPE).toBe("decionis-signed-signal+jwt");
  });
});

describe("signedSignalFacts", () => {
  const verified = (claims: SignedSignalClaims) => {
    const verification = verifySignedSignal(mint({ signal: claims }), {
      orgId: ORG,
      findKey,
      nowMs: NOW,
    });
    if (!verification.ok) throw new Error(verification.code);
    return verification.signal;
  };

  it("covers a purchase within the permission on every axis", () => {
    const facts = signedSignalFacts(verified(DELEGATION), PURCHASE);
    expect(facts.covers).toEqual({
      action: true,
      agent: true,
      amount: true,
      currency: true,
      card: true,
    });
    expect(facts.covers_intent).toBe(true);
    expect(facts).toMatchObject({
      verified: true,
      producer: "koard",
      agent: "synthetic-agent-1",
      scope: { actions: ["card.purchase"] },
      limits: { currency: "USD", amount_minor: 5000 },
      card_token_ref: "tok_synthetic_card_a",
    });
  });

  it("does not cover a purchase over the limit, for another agent, action or card", () => {
    const over = signedSignalFacts(verified(DELEGATION), {
      ...PURCHASE,
      parameters: { ...PURCHASE.parameters, amountMinor: 5001 },
    });
    expect(over.covers.amount).toBe(false);
    expect(over.covers_intent).toBe(false);
    expect(
      signedSignalFacts(verified(DELEGATION), { ...PURCHASE, actorId: "synthetic-agent-2" }).covers
        .agent,
    ).toBe(false);
    expect(
      signedSignalFacts(verified(DELEGATION), { ...PURCHASE, action: "payout" }).covers.action,
    ).toBe(false);
    expect(
      signedSignalFacts(verified(DELEGATION), {
        ...PURCHASE,
        resource: "card:tok_synthetic_card_b",
        parameters: { ...PURCHASE.parameters, cardTokenRef: "tok_synthetic_card_b" },
      }).covers.card,
    ).toBe(false);
    expect(
      signedSignalFacts(verified(DELEGATION), {
        ...PURCHASE,
        parameters: { ...PURCHASE.parameters, currency: "EUR" },
      }).covers.currency,
    ).toBe(false);
  });

  it("leaves an axis null when the signal asserts nothing about it, and covers the intent then", () => {
    const bare = signedSignalFacts(
      verified({ name: "card_delegation", method: "card_tap", result: "VERIFIED" }),
      PURCHASE,
    );
    expect(bare.covers).toEqual({
      action: null,
      agent: null,
      amount: null,
      currency: null,
      card: null,
    });
    expect(bare.covers_intent).toBe(true);
    expect(bare).not.toHaveProperty("limits");
  });

  it("does not cover a limit the intent gives it nothing to check against", () => {
    const facts = signedSignalFacts(verified(DELEGATION), {
      ...PURCHASE,
      resource: "payout:synthetic-beneficiary-1",
      parameters: {},
    });
    expect(facts.covers).toEqual({
      action: true,
      agent: true,
      amount: false,
      currency: false,
      card: false,
    });
    expect(facts.covers_intent).toBe(false);
  });
});

describe("verifySignedSignals", () => {
  it("keys the facts by name and refuses two signals with one name", () => {
    const verified = verifySignedSignals([mint()], {
      orgId: ORG,
      findKey,
      intent: PURCHASE,
      nowMs: NOW,
    });
    expect(verified.ok).toBe(true);
    if (!verified.ok) return;
    expect(Object.keys(verified.facts)).toEqual(["card_delegation"]);
    expect(verified.facts.card_delegation?.covers_intent).toBe(true);
    expect(
      verifySignedSignals([mint(), mint({ jti: "signal-synthetic-2" })], {
        orgId: ORG,
        findKey,
        intent: PURCHASE,
        nowMs: NOW,
      }),
    ).toEqual({ ok: false, code: "SIGNED_SIGNAL_DUPLICATE_NAME" });
  });

  it("refuses the whole request on the first refused token", () => {
    expect(
      verifySignedSignals(
        [mint(), mint({ kid: "koard-signal-key-z", jti: "signal-synthetic-2" })],
        {
          orgId: ORG,
          findKey,
          intent: PURCHASE,
          nowMs: NOW,
        },
      ),
    ).toEqual({ ok: false, code: "SIGNED_SIGNAL_KEY_UNKNOWN" });
  });
});
