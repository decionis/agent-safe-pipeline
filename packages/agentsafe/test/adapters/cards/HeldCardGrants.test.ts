import type {
  HeldExecution,
  SafeExecutor,
  VerifiedAuthorization,
} from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { prepareCardPurchase } from "../../../src/adapters/cards/CardEffect.js";
import {
  HeldCardGrants,
  type CardApproval,
  type HeldCardGrant,
} from "../../../src/adapters/cards/HeldCardGrants.js";

const NOW = 1_800_000_000_000;

function grant(cardTokenRef: string, overrides: Partial<HeldCardGrant> = {}): HeldCardGrant {
  const purchase = { cardTokenRef, amountMinor: 100, currency: "EUR", merchantId: "fixture_m" };
  return {
    cardTokenRef,
    amountMinor: 100,
    currency: "EUR",
    merchantId: "fixture_m",
    mcc: null,
    expiresAtMs: NOW + 60_000,
    used: false,
    purchase,
    prepared: prepareCardPurchase(purchase),
    held: {} as HeldExecution,
    executor: {} as SafeExecutor,
    ...overrides,
  };
}

function claim(held: HeldCardGrant): Parameters<HeldCardGrants["recordClaim"]>[1] {
  return {
    grant: held,
    request: {
      authorization_id: "fixture_auth",
      card_token_ref: held.cardTokenRef,
      amount_minor: 100,
      currency: "EUR",
      merchant_id: "fixture_m",
    },
    authorization: {} as VerifiedAuthorization,
    leaseExpiresAtMs: NOW + 30_000,
    answer: { decision: "APPROVE" } as CardApproval,
  };
}

describe("HeldCardGrants", () => {
  it("keeps one spendable hold per card, and replaces one that is spent or expired", () => {
    let now = NOW;
    const store = new HeldCardGrants({ clock: () => now });
    const first = grant("fixture_card_1");
    expect(store.hold(first)).toBe(true);
    expect(store.spendable("fixture_card_1")).toBe(true);
    expect(store.hold(grant("fixture_card_1"))).toBe(false);
    expect(store.grant("fixture_card_1")).toBe(first);
    first.used = true;
    expect(store.spendable("fixture_card_1")).toBe(false);
    const second = grant("fixture_card_1");
    expect(store.hold(second)).toBe(true);
    expect(store.grant("fixture_card_1")).toBe(second);
    now = NOW + 60_000;
    expect(store.spendable("fixture_card_1")).toBe(false);
    expect(store.hold(grant("fixture_card_1", { expiresAtMs: now + 1 }))).toBe(true);
    expect(store.spendable("fixture_card_2")).toBe(false);
  });

  it("remembers an expired hold as long as a claim, then forgets it", () => {
    let now = NOW;
    const store = new HeldCardGrants({ clock: () => now, claimRetentionMs: 1_000 });
    store.hold(grant("fixture_card_1", { expiresAtMs: NOW + 10 }));
    now = NOW + 1_009;
    expect(store.grant("fixture_card_1")).toBeDefined();
    now = NOW + 1_010;
    expect(store.grant("fixture_card_1")).toBeUndefined();
    expect(store.size).toEqual({ holds: 0, claims: 0 });
  });

  it("refuses a hold beyond its bound, and forgets the oldest claim beyond it", () => {
    let now = NOW;
    const store = new HeldCardGrants({ clock: () => now, maxEntries: 1, claimRetentionMs: 100 });
    expect(store.hold(grant("fixture_card_1"))).toBe(true);
    expect(store.hold(grant("fixture_card_2"))).toBe(false);
    const recorded = store.recordClaim("fixture_auth_1", claim(grant("fixture_card_1")));
    expect(recorded).toMatchObject({ settled: false, retainUntilMs: NOW + 100 });
    expect(store.claimed("fixture_auth_1")).toBe(recorded);
    store.recordClaim("fixture_auth_2", claim(grant("fixture_card_1")));
    expect(store.claimed("fixture_auth_1")).toBeUndefined();
    expect(store.claimed("fixture_auth_2")).toBeDefined();
    now = NOW + 100;
    expect(store.claimed("fixture_auth_2")).toBeUndefined();
  });

  it("defaults to the wall clock, ten thousand entries and fifteen minutes", () => {
    const store = new HeldCardGrants();
    const recorded = store.recordClaim("fixture_auth_1", claim(grant("fixture_card_1")));
    expect(recorded.retainUntilMs - Date.now()).toBeGreaterThan(15 * 60_000 - 1_000);
    expect(recorded.retainUntilMs - Date.now()).toBeLessThanOrEqual(15 * 60_000);
    expect(store.hold(grant("fixture_card_1", { expiresAtMs: Date.now() + 60_000 }))).toBe(true);
  });

  it("counts a card's holds and claims over the window, and nothing older", () => {
    let now = NOW;
    const store = new HeldCardGrants({ clock: () => now });
    expect(store.velocity("fixture_card_1")).toEqual({ window_seconds: 600, holds: 0, claims: 0 });
    const first = grant("fixture_card_1");
    expect(store.hold(first)).toBe(true);
    store.recordClaim("fixture_auth_1", claim(first));
    first.used = true;
    now += 60_000;
    expect(store.hold(grant("fixture_card_1", { expiresAtMs: now + 60_000 }))).toBe(true);
    expect(store.velocity("fixture_card_1")).toEqual({ window_seconds: 600, holds: 2, claims: 1 });
    expect(store.velocity("fixture_card_2")).toEqual({ window_seconds: 600, holds: 0, claims: 0 });
    // A refused hold is not activity.
    expect(store.hold(grant("fixture_card_1", { expiresAtMs: now + 60_000 }))).toBe(false);
    expect(store.velocity("fixture_card_1").holds).toBe(2);
    // The window moves: the first hold and its claim fall out together.
    now = NOW + 600_000;
    expect(store.velocity("fixture_card_1")).toEqual({ window_seconds: 600, holds: 1, claims: 0 });
    expect(store.velocity("fixture_card_1", 30_000)).toEqual({
      window_seconds: 30,
      holds: 0,
      claims: 0,
    });
    now = NOW + 660_000;
    expect(store.velocity("fixture_card_1")).toEqual({ window_seconds: 600, holds: 0, claims: 0 });
  });

  it("bounds what it remembers per card and across cards, forgetting the stalest card first", () => {
    let now = NOW;
    const store = new HeldCardGrants({ clock: () => now, maxEntries: 2 });
    for (let index = 0; index < 150; index += 1) {
      const held = grant("fixture_card_1", { expiresAtMs: now + 1 });
      expect(store.hold(held)).toBe(true);
      held.used = true;
      now += 1;
    }
    expect(store.velocity("fixture_card_1").holds).toBe(100);
    // Two cards are remembered; a third evicts the one touched longest ago.
    store.recordClaim("fixture_auth_2", claim(grant("fixture_card_2")));
    store.recordClaim("fixture_auth_3", claim(grant("fixture_card_3")));
    expect(store.velocity("fixture_card_1")).toEqual({ window_seconds: 600, holds: 0, claims: 0 });
    expect(store.velocity("fixture_card_2").claims).toBe(1);
    expect(store.velocity("fixture_card_3").claims).toBe(1);
    // Touching a card again makes it the freshest.
    store.recordClaim("fixture_auth_4", claim(grant("fixture_card_2")));
    store.recordClaim("fixture_auth_5", claim(grant("fixture_card_4")));
    expect(store.velocity("fixture_card_3").claims).toBe(0);
    expect(store.velocity("fixture_card_2").claims).toBe(2);
  });
});
