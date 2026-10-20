import type { CapturedIntent } from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { CardOutcomes } from "../../src/outcomes/CardOutcomes.js";
import { InMemoryCardOutcomeLedger } from "../../src/outcomes/CardOutcomeLedger.js";
import type { ActionResponse } from "../../src/service/Requests.js";
import { FACT_INTENT, FACT_TENANT, ORG_ID, PRODUCER_TOKEN } from "../support/CardOutcomeFacts.js";
import { collectedEvents } from "../support/Environment.js";

const fetchNothing = (async () => {
  await Promise.resolve();
  throw new Error("no network in this test");
}) as typeof fetch;

function outcomes(ledger = new InMemoryCardOutcomeLedger()): {
  readonly subject: CardOutcomes;
  readonly ledger: InMemoryCardOutcomeLedger;
} {
  const subject = CardOutcomes.create({
    config: { mode: "record", dir: "/nonexistent-is-never-opened" },
    authorityUrl: "https://authority.decionis.example",
    token: () => PRODUCER_TOKEN,
    fetch: fetchNothing,
    events: collectedEvents(),
    ledger,
  });
  if (subject === null) throw new Error("recording is on");
  return { subject, ledger };
}

function captured(action: string, parameters: Record<string, unknown>): CapturedIntent {
  return {
    intent: {
      intentId: FACT_INTENT,
      tenantId: FACT_TENANT,
      action,
      parameters,
      expiresAt: "2026-10-12T12:05:00.000Z",
    },
    intentHash: `sha256:${"0".repeat(64)}`,
  } as unknown as CapturedIntent;
}

const PURCHASE = captured("card.purchase", {
  cardTokenRef: "fixture_card_ref_1",
  amountMinor: 4_250,
  currency: "EUR",
  merchantId: "fixture_merchant_1",
});

function answer(overrides: Partial<ActionResponse> = {}): ActionResponse {
  return {
    mode: "ENFORCEMENT",
    intent_id: FACT_INTENT,
    intent_hash: `sha256:${"0".repeat(64)}`,
    verdict: "ALLOW",
    decision_id: "fixture_decision_1",
    dossier_id: "fixture_dossier_1",
    reason_codes: [],
    fail_closed: false,
    outcome: "HELD_FOR_AUTHORIZATION",
    executed: false,
    authorization: null,
    finalization: null,
    result: { status: "HELD_FOR_AUTHORIZATION", expires_at: "2026-10-12T12:04:00.000Z" },
    effect: null,
    recovery: null,
    escalation: null,
    ...overrides,
  };
}

describe("the card path's outcome recording", () => {
  it("is nothing at all while outcomes are off", () => {
    expect(
      CardOutcomes.create({
        config: { mode: "off" },
        authorityUrl: "https://authority.decionis.example",
        token: () => PRODUCER_TOKEN,
        fetch: fetchNothing,
        events: collectedEvents(),
      }),
    ).toBeNull();
    const publishing = CardOutcomes.create({
      config: { mode: "publish", dir: "/unused", orgId: ORG_ID, intervalSeconds: 3_600 },
      authorityUrl: "https://authority.decionis.example",
      token: () => PRODUCER_TOKEN,
      fetch: fetchNothing,
      events: collectedEvents(),
      ledger: new InMemoryCardOutcomeLedger(),
      clock: () => new Date(Date.parse("2026-10-12T13:00:00.000Z")),
    });
    expect(publishing).not.toBeNull();
    publishing?.stop();
  });

  it("records card purchases only, decisions the authority took only, and resolutions only", async () => {
    const { subject, ledger } = outcomes();
    subject.decided(captured("forward_request", { amountMinor: 1 }), answer());
    subject.decided(PURCHASE, answer({ verdict: null }));
    subject.decided(PURCHASE, answer({ verdict: "BLOCK", fail_closed: true }));
    subject.decided(captured("card.purchase", { cardTokenRef: "4111111111111111" }), answer());
    subject.resumed(captured("forward_request", {}), answer(), "PRESENCE");
    subject.resumed(PURCHASE, answer({ verdict: "ESCALATE" }), "PRESENCE");
    await subject.flush();
    expect(ledger.all).toEqual([]);

    subject.decided(PURCHASE, answer({ result: null }));
    subject.decided(PURCHASE, answer({ outcome: "BLOCKED", verdict: "BLOCK", result: null }));
    subject.resumed(PURCHASE, answer({ result: { expires_at: 7 } }), "ATTESTATION");
    subject.settled(FACT_INTENT, "COMMITTED", "not-a-digest");
    await subject.flush();
    expect(ledger.all).toMatchObject([
      { kind: "DECIDED", verdict: "ALLOW", held_until: null, amount_minor: 4_250 },
      { kind: "DECIDED", verdict: "BLOCK", held_until: null },
      { kind: "RESUMED", via: "ATTESTATION", held_until: null },
      { kind: "SETTLED", outcome: "COMMITTED", receipt_digest: null },
    ]);
    expect(JSON.stringify(ledger.all)).not.toContain("fixture_card_ref_1");
    expect(JSON.stringify(ledger.all)).not.toContain("fixture_merchant_1");
    // Recording only: there is nothing to publish, and starting and stopping does nothing.
    subject.start();
    subject.stop();
    expect(await subject.publish()).toBeNull();
  });
});
