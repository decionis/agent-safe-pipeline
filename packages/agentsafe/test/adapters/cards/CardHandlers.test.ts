import { ActionRegistry, IntentCapture } from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { cardHandlers } from "../../../src/adapters/cards/CardHandlers.js";
import type { HandlerRegistrationContext } from "../../../src/handlers/HandlerRegistration.js";

describe("cardHandlers", () => {
  it("registers card.purchase, which is never dispatched and has no one to reconcile with", async () => {
    const registry = new ActionRegistry();
    const names = cardHandlers()({ registry } as unknown as HandlerRegistrationContext);
    registry.seal();
    expect(names).toEqual(["card.purchase"]);
    const captured = new IntentCapture({ ttlSeconds: 60 }).capture(
      {
        action: "card.purchase",
        target: "card:fixture_card_ref_0042",
        parameters: {
          cardTokenRef: "fixture_card_ref_0042",
          amountMinor: 100,
          currency: "EUR",
          merchantId: "fixture_merchant_17",
        },
      },
      {
        tenantId: "00000000-0000-4000-8000-000000000007",
        actor: { id: "synthetic-shopping-agent", type: "AI_AGENT" },
        downstreamTarget: { system: "synthetic-issuer", operation: "card_purchase" },
        idempotencyKey: "fixture-card-1",
        context: {},
      },
    );
    expect(() => registry.validate(captured)).not.toThrow();
    const attempt = await registry.executeTracked(captured, {
      decisionId: "d",
      dossierId: "o",
      grantId: "g",
      intentHash: captured.intentHash,
      expiresAt: captured.intent.expiresAt,
    });
    expect(attempt).toEqual({ status: "FAILED_BEFORE_DISPATCH" });
    expect(await registry.reconcile(captured, "fixture-card-1")).toEqual({ status: "UNKNOWN" });
  });
});
