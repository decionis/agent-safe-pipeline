import { describe, expect, it } from "vitest";
import { createFixtureAuthorityPair } from "../../src/decision/FixtureDecisionAuthority.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import { ShadowPipeline } from "../../src/shadow/ShadowPipeline.js";

describe("ShadowPipeline", () => {
  it("labels the existing execution and hypothetical decision as shadow", async () => {
    const intent = new IntentCapture().capture(
      { action: "refund_order", target: "order:1", parameters: { amount: 350 } },
      {
        tenantId: "00000000-0000-4000-8000-000000000002",
        actor: { id: "agent", type: "AI_AGENT" },
        downstreamTarget: { system: "shopify", operation: "refund" },
        idempotencyKey: "shadow-1",
        context: {},
      },
    );
    const pair = createFixtureAuthorityPair(() => "ESCALATE", {
      unsafeAllowDevelopmentFixture: true,
    });
    const result = await new ShadowPipeline(pair.authority).compare(intent, async () => "executed");

    expect(result).toMatchObject({
      mode: "SHADOW",
      productionResult: "executed",
      hypotheticalDecision: { verdict: "ESCALATE" },
    });
  });
});
