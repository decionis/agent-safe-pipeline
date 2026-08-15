import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

describe("IntentCapture performance", () => {
  it("rejects adversarial nesting without recursive traversal", () => {
    let parameters: Record<string, unknown> = {};
    for (let index = 0; index < 50_000; index += 1) parameters = { nested: parameters };
    const startedAt = performance.now();

    expect(() =>
      new IntentCapture().capture(
        { action: "refund_order", target: "order:1", parameters: parameters as never },
        {
          tenantId: "00000000-0000-4000-8000-000000000002",
          actor: { id: "synthetic-performance-agent", type: "AI_AGENT" },
          downstreamTarget: { system: "shopify", operation: "refund" },
          idempotencyKey: "performance-depth",
          context: {},
        },
      ),
    ).toThrow("INTENT_TOO_DEEP");
    expect(performance.now() - startedAt).toBeLessThan(1_000);
  });
});
