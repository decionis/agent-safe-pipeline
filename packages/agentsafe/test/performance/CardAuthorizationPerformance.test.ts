import { performance } from "node:perf_hooks";
import type { HeldExecution, SafeExecutor } from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { matchCardAuthorization } from "../../src/adapters/cards/CardAuthorizationMatcher.js";
import { prepareCardPurchase } from "../../src/adapters/cards/CardEffect.js";
import type { HeldCardGrant } from "../../src/adapters/cards/CardHoldStore.js";
import { HeldCardGrants } from "../../src/adapters/cards/HeldCardGrants.js";

/**
 * The card path's own cost, measured: what this process adds between the
 * issuer's authorization arriving and the claim leaving. The claim's round
 * trip to the authority is the network's, and is measured in a deployment,
 * not here; the figures published for the hook say which is which.
 *
 * The budgets asserted are deliberately wide of the figures measured on a
 * quiet machine (tens of microseconds for a match, well under a millisecond
 * in the store), because the suite also runs under the mutation gate's
 * instrumentation and on loaded runners, where the same code is slower by
 * an order of magnitude and a tight budget would fail for no reason.
 */
function percentile(samples: number[], p: number): number {
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor((sorted.length * p) / 100))] ?? 0;
}

function grant(index: number): HeldCardGrant {
  const purchase = {
    cardTokenRef: `fixture_card_ref_${index}`,
    amountMinor: 4_250,
    currency: "EUR",
    merchantId: "fixture_merchant_17",
  };
  return {
    ...purchase,
    mcc: null,
    expiresAtMs: Date.now() + 120_000,
    used: false,
    purchase,
    prepared: prepareCardPurchase(purchase),
    held: { captured: { intent: { intentId: `fixture_intent_${index}` } } } as HeldExecution,
    executor: {} as SafeExecutor,
  };
}

describe("card authorization performance", () => {
  it("matches an authorization to a held grant in microseconds", () => {
    const held = grant(1);
    const view = {
      cardTokenRef: held.cardTokenRef,
      amountMinor: 4_000,
      currency: "EUR",
      merchantId: held.merchantId,
      mcc: "5812",
    };
    const samples: number[] = [];
    for (let index = 0; index < 100_000; index += 1) {
      const startedAt = performance.now();
      const match = matchCardAuthorization(held, view, Date.now());
      samples.push(performance.now() - startedAt);
      if (match.decision !== "MATCHED") throw new Error(match.code);
    }
    // One hundred thousand matches: a millisecond at the 99th percentile is the budget;
    // tens of microseconds is what a quiet machine measures.
    expect(percentile(samples, 99)).toBeLessThan(1);
    expect(percentile(samples, 50)).toBeLessThan(0.25);
  });

  it("holds, finds and spends ten thousand grants in the in-memory store inside the hook's budget", async () => {
    const store = new HeldCardGrants();
    const holds: number[] = [];
    const lookups: number[] = [];
    for (let index = 0; index < 10_000; index += 1) {
      const held = grant(index);
      let startedAt = performance.now();
      const stored = await store.hold(held);
      holds.push(performance.now() - startedAt);
      if (!stored) throw new Error("hold refused");
      startedAt = performance.now();
      const record = await store.grant({
        cardTokenRef: held.cardTokenRef,
        merchantId: held.merchantId,
      });
      const opened = await record?.open();
      const spent = opened === null || opened === undefined ? false : await store.spend(opened);
      lookups.push(performance.now() - startedAt);
      if (!spent) throw new Error("spend refused");
    }
    // The in-process part of the hook, with ten thousand holds in the store: a few
    // milliseconds at the 99th percentile is the budget; a quiet machine measures well under one.
    expect(percentile(holds, 99)).toBeLessThan(5);
    expect(percentile(lookups, 99)).toBeLessThan(5);
    expect(store.size.holds).toBe(10_000);
  });
});
