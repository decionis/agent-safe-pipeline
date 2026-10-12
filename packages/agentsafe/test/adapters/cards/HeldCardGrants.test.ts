import type {
  HeldExecution,
  SafeExecutor,
  VerifiedAuthorization,
} from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { prepareCardPurchase } from "../../../src/adapters/cards/CardEffect.js";
import type { CardClaimInput } from "../../../src/adapters/cards/CardHoldStore.js";
import {
  HeldCardGrants,
  type CardApproval,
  type HeldCardGrant,
} from "../../../src/adapters/cards/HeldCardGrants.js";

const NOW = 1_800_000_000_000;
let intents = 0;

function grant(
  cardTokenRef: string,
  overrides: Partial<HeldCardGrant> & { readonly merchantId?: string } = {},
): HeldCardGrant {
  intents += 1;
  const merchantId = overrides.merchantId ?? "fixture_m";
  const purchase = { cardTokenRef, amountMinor: 100, currency: "EUR", merchantId };
  return {
    cardTokenRef,
    amountMinor: 100,
    currency: "EUR",
    merchantId,
    mcc: null,
    expiresAtMs: NOW + 60_000,
    used: false,
    purchase,
    prepared: prepareCardPurchase(purchase),
    held: { captured: { intent: { intentId: `fixture_intent_${intents}` } } } as HeldExecution,
    executor: {} as SafeExecutor,
    ...overrides,
  };
}

const key = (cardTokenRef: string, merchantId = "fixture_m") => ({ cardTokenRef, merchantId });

function claim(held: HeldCardGrant): CardClaimInput {
  return {
    grant: held,
    request: {
      authorization_id: "fixture_auth",
      card_token_ref: held.cardTokenRef,
      amount_minor: 100,
      currency: "EUR",
      merchant_id: held.merchantId,
    },
    authorization: {} as VerifiedAuthorization,
    leaseExpiresAtMs: NOW + 30_000,
    answer: { decision: "APPROVE" } as CardApproval,
    material: null,
  };
}

describe("HeldCardGrants", () => {
  it("keeps one spendable hold per card and merchant, and replaces one that is spent or expired", async () => {
    let now = NOW;
    const store = new HeldCardGrants({ clock: () => now });
    const first = grant("fixture_card_1");
    expect(await store.hold(first)).toBe(true);
    expect(await store.spendable(key("fixture_card_1"))).toBe(true);
    expect(await store.hold(grant("fixture_card_1"))).toBe(false);
    // The same card at another merchant holds in parallel.
    expect(await store.hold(grant("fixture_card_1", { merchantId: "fixture_other" }))).toBe(true);
    expect(await store.spendable(key("fixture_card_1", "fixture_other"))).toBe(true);
    const record = await store.grant(key("fixture_card_1"));
    expect(record).toMatchObject({ used: false, intentId: first.held.captured.intent.intentId });
    expect(await record?.open()).toBe(first);
    expect(await store.spend(first)).toBe(true);
    expect(await store.spend(first)).toBe(false);
    expect((await store.grant(key("fixture_card_1")))?.used).toBe(true);
    expect(await store.spendable(key("fixture_card_1"))).toBe(false);
    const second = grant("fixture_card_1");
    expect(await store.hold(second)).toBe(true);
    expect(await (await store.grant(key("fixture_card_1")))?.open()).toBe(second);
    // A grant the store no longer holds cannot be spent through it.
    expect(await store.spend(first)).toBe(false);
    now = NOW + 60_000;
    expect(await store.spendable(key("fixture_card_1"))).toBe(false);
    expect(await store.hold(grant("fixture_card_1", { expiresAtMs: now + 1 }))).toBe(true);
    expect(await store.spendable(key("fixture_card_2"))).toBe(false);
    expect(await store.grant(key("fixture_card_2"))).toBeUndefined();
  });

  it("remembers an expired hold as long as a claim, then forgets it", async () => {
    let now = NOW;
    const store = new HeldCardGrants({ clock: () => now, claimRetentionMs: 1_000 });
    await store.hold(grant("fixture_card_1", { expiresAtMs: NOW + 10 }));
    now = NOW + 1_009;
    expect(await store.grant(key("fixture_card_1"))).toBeDefined();
    now = NOW + 1_010;
    expect(await store.grant(key("fixture_card_1"))).toBeUndefined();
    expect(store.size).toEqual({ holds: 0, claims: 0 });
  });

  it("refuses a hold beyond its bound, and forgets the oldest claim beyond it", async () => {
    let now = NOW;
    const store = new HeldCardGrants({ clock: () => now, maxEntries: 1, claimRetentionMs: 100 });
    expect(await store.hold(grant("fixture_card_1"))).toBe(true);
    expect(await store.hold(grant("fixture_card_2"))).toBe(false);
    const recorded = await store.recordClaim("fixture_auth_1", claim(grant("fixture_card_1")));
    expect(recorded).toMatchObject({ settled: false, retainUntilMs: NOW + 100 });
    expect(await store.claimed("fixture_auth_1")).toBe(recorded);
    await store.recordClaim("fixture_auth_2", claim(grant("fixture_card_1")));
    expect(await store.claimed("fixture_auth_1")).toBeUndefined();
    expect(await store.claimed("fixture_auth_2")).toBeDefined();
    now = NOW + 100;
    expect(await store.claimed("fixture_auth_2")).toBeUndefined();
  });

  it("settles a claim once and amends an open one", async () => {
    const store = new HeldCardGrants({ clock: () => NOW });
    const recorded = await store.recordClaim("fixture_auth_1", claim(grant("fixture_card_1")));
    const more = { ...recorded.request, amount_minor: 150 };
    expect(await store.amend("fixture_auth_1", more)).toBe(true);
    expect((await store.claimed("fixture_auth_1"))?.request).toEqual(more);
    expect(await store.settle("fixture_auth_1")).toBe(true);
    expect(await store.settle("fixture_auth_1")).toBe(false);
    expect(await store.amend("fixture_auth_1", more)).toBe(false);
    expect(await store.settle("fixture_auth_unknown")).toBe(false);
    expect(await store.amend("fixture_auth_unknown", more)).toBe(false);
    expect((await store.claimed("fixture_auth_1"))?.settled).toBe(true);
  });

  it("defaults to the wall clock, ten thousand entries and fifteen minutes, and has nothing to start or sweep", async () => {
    const store = new HeldCardGrants();
    expect(store.kind).toBe("memory");
    const recorded = await store.recordClaim("fixture_auth_1", claim(grant("fixture_card_1")));
    expect(recorded.retainUntilMs - Date.now()).toBeGreaterThan(15 * 60_000 - 1_000);
    expect(recorded.retainUntilMs - Date.now()).toBeLessThanOrEqual(15 * 60_000);
    expect(await store.hold(grant("fixture_card_1", { expiresAtMs: Date.now() + 60_000 }))).toBe(
      true,
    );
    await expect(store.ready()).resolves.toBeUndefined();
    await expect(store.cleanup()).resolves.toBeUndefined();
    await expect(store.close()).resolves.toBeUndefined();
  });

  it("counts a card's holds and claims over the window, across merchants, and nothing older", async () => {
    let now = NOW;
    const store = new HeldCardGrants({ clock: () => now });
    expect(await store.velocity("fixture_card_1")).toEqual({
      window_seconds: 600,
      holds: 0,
      claims: 0,
    });
    const first = grant("fixture_card_1");
    expect(await store.hold(first)).toBe(true);
    await store.recordClaim("fixture_auth_1", claim(first));
    first.used = true;
    now += 60_000;
    expect(
      await store.hold(
        grant("fixture_card_1", { merchantId: "fixture_m2", expiresAtMs: now + 60_000 }),
      ),
    ).toBe(true);
    expect(await store.velocity("fixture_card_1")).toEqual({
      window_seconds: 600,
      holds: 2,
      claims: 1,
    });
    expect(await store.velocity("fixture_card_2")).toEqual({
      window_seconds: 600,
      holds: 0,
      claims: 0,
    });
    // A refused hold is not activity.
    expect(
      await store.hold(
        grant("fixture_card_1", { merchantId: "fixture_m2", expiresAtMs: now + 60_000 }),
      ),
    ).toBe(false);
    expect((await store.velocity("fixture_card_1")).holds).toBe(2);
    // The window moves: the first hold and its claim fall out together.
    now = NOW + 600_000;
    expect(await store.velocity("fixture_card_1")).toEqual({
      window_seconds: 600,
      holds: 1,
      claims: 0,
    });
    expect(await store.velocity("fixture_card_1", 30_000)).toEqual({
      window_seconds: 30,
      holds: 0,
      claims: 0,
    });
    now = NOW + 660_000;
    expect(await store.velocity("fixture_card_1")).toEqual({
      window_seconds: 600,
      holds: 0,
      claims: 0,
    });
  });

  it("bounds what it remembers per card and across cards, forgetting the stalest card first", async () => {
    let now = NOW;
    const store = new HeldCardGrants({ clock: () => now, maxEntries: 2 });
    for (let index = 0; index < 150; index += 1) {
      const held = grant("fixture_card_1", { expiresAtMs: now + 1 });
      expect(await store.hold(held)).toBe(true);
      held.used = true;
      now += 1;
    }
    expect((await store.velocity("fixture_card_1")).holds).toBe(100);
    // Two cards are remembered; a third evicts the one touched longest ago.
    await store.recordClaim("fixture_auth_2", claim(grant("fixture_card_2")));
    await store.recordClaim("fixture_auth_3", claim(grant("fixture_card_3")));
    expect(await store.velocity("fixture_card_1")).toEqual({
      window_seconds: 600,
      holds: 0,
      claims: 0,
    });
    expect((await store.velocity("fixture_card_2")).claims).toBe(1);
    expect((await store.velocity("fixture_card_3")).claims).toBe(1);
    // Touching a card again makes it the freshest.
    await store.recordClaim("fixture_auth_4", claim(grant("fixture_card_2")));
    await store.recordClaim("fixture_auth_5", claim(grant("fixture_card_4")));
    expect((await store.velocity("fixture_card_3")).claims).toBe(0);
    expect((await store.velocity("fixture_card_2")).claims).toBe(2);
  });
});
