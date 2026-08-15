import { z } from "zod";
import { describe, expect, it, vi } from "vitest";
import { ActionRegistry } from "../../src/execution/ActionRegistry.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

function captured(action = "refund_order") {
  return new IntentCapture().capture(
    { action, target: "shopify:order:1", parameters: { amount: 10 } },
    {
      tenantId: "00000000-0000-4000-8000-000000000002",
      actor: { id: "synthetic-refund-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "shopify", operation: "refund" },
      idempotencyKey: `registry-${action}`,
      context: {},
    },
  );
}

const authorization = {
  decisionId: "decision-1",
  dossierId: "dossier-1",
  grantId: "grant-1",
  intentHash: `sha256:${"1".repeat(64)}`,
  expiresAt: "2030-01-01T00:00:00.000Z",
};

describe("ActionRegistry", () => {
  it("rejects duplicate and post-seal registration", () => {
    const handler = {
      parametersSchema: z.object({ amount: z.number() }),
      execute: vi.fn(),
    };
    const registry = new ActionRegistry().register("refund_order", handler);
    expect(() => registry.register("refund_order", handler)).toThrow("ACTION_ALREADY_REGISTERED");
    expect(registry.has("refund_order")).toBe(true);
    expect(registry.has("unknown")).toBe(false);
    registry.seal();
    expect(() => registry.register("another_action", handler)).toThrow("ACTION_REGISTRY_SEALED");
  });

  it("requires a sealed registry and a registered action", async () => {
    const handler = {
      parametersSchema: z.object({ amount: z.number() }),
      execute: vi.fn(),
    };
    const unsealed = new ActionRegistry().register("refund_order", handler);
    expect(() => unsealed.validate(captured())).toThrow("ACTION_REGISTRY_NOT_SEALED");
    await expect(unsealed.execute(captured(), authorization)).rejects.toThrow(
      "ACTION_REGISTRY_NOT_SEALED",
    );

    const sealed = new ActionRegistry().seal();
    expect(() => sealed.validate(captured("unknown_action"))).toThrow("ACTION_NOT_REGISTERED");
    await expect(sealed.execute(captured("unknown_action"), authorization)).rejects.toThrow(
      "ACTION_NOT_REGISTERED",
    );
  });

  it("returns a stable error for parameters rejected by the trusted schema", async () => {
    const registry = new ActionRegistry()
      .register("refund_order", {
        parametersSchema: z.object({ amount: z.number().positive() }),
        execute: vi.fn(),
      })
      .seal();
    const invalid = new IntentCapture().capture(
      { action: "refund_order", target: "shopify:order:1", parameters: { amount: -1 } },
      {
        tenantId: "00000000-0000-4000-8000-000000000002",
        actor: { id: "synthetic-refund-agent", type: "AI_AGENT" },
        downstreamTarget: { system: "shopify", operation: "refund" },
        idempotencyKey: "registry-invalid",
        context: {},
      },
    );

    expect(() => registry.validate(invalid)).toThrow("ACTION_PARAMETERS_INVALID");
    await expect(registry.execute(invalid, authorization)).rejects.toThrow(
      "ACTION_PARAMETERS_INVALID",
    );
  });
});
