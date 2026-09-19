import { z } from "zod";
import { describe, expect, it, vi } from "vitest";
import {
  ActionRegistry,
  ProviderRefusal,
  type ProviderDispatch,
} from "../../src/execution/ActionRegistry.js";
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

  it("allows only one provider dispatch and exposes the trusted idempotency key", async () => {
    const operation = vi.fn(async (idempotencyKey: string) => idempotencyKey);
    const registry = new ActionRegistry()
      .register("refund_order", {
        parametersSchema: z.object({ amount: z.number() }),
        execute: async ({ dispatch }) => {
          const result = await dispatch.run(operation);
          await expect(dispatch.run(operation)).rejects.toThrow(
            "PROVIDER_DISPATCH_ALREADY_STARTED",
          );
          return result;
        },
      })
      .seal();
    const intent = captured();

    await expect(registry.executeTracked(intent, authorization)).resolves.toMatchObject({
      status: "COMPLETED",
      result: intent.intent.idempotencyKey,
    });
    expect(operation).toHaveBeenCalledTimes(1);
    expect(operation).toHaveBeenCalledWith(intent.intent.idempotencyKey);
  });

  it("carries the provider's receipt on every attempt after the dispatch, and refuses one before it", async () => {
    const RECEIPT = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJnMSJ9.c2ln";
    const attempts = async (body: (dispatch: ProviderDispatch) => Promise<unknown>) => {
      const registry = new ActionRegistry()
        .register("refund_order", {
          parametersSchema: z.object({ amount: z.number() }),
          execute: async ({ dispatch }) => await body(dispatch),
        })
        .seal();
      return await registry.executeTracked(captured(), authorization);
    };
    await expect(
      attempts(async (dispatch) =>
        dispatch.run(() => {
          dispatch.receipt(RECEIPT);
          return "done";
        }),
      ),
    ).resolves.toEqual({ status: "COMPLETED", result: "done", receipt: RECEIPT });
    await expect(attempts(async (dispatch) => dispatch.run(() => "done"))).resolves.toEqual({
      status: "COMPLETED",
      result: "done",
      receipt: null,
    });
    await expect(
      attempts(async (dispatch) =>
        dispatch.run(() => {
          dispatch.receipt(RECEIPT);
          throw new ProviderRefusal("INSUFFICIENT_FUNDS");
        }),
      ),
    ).resolves.toEqual({
      status: "REFUSED_AFTER_DISPATCH",
      reason: "INSUFFICIENT_FUNDS",
      receipt: RECEIPT,
    });
    await expect(
      attempts(async (dispatch) =>
        dispatch.run(() => {
          dispatch.receipt(RECEIPT);
          throw new Error("lost");
        }),
      ),
    ).resolves.toEqual({ status: "UNKNOWN_AFTER_DISPATCH", receipt: RECEIPT });
    // Before the dispatch there is nothing a receipt could describe; the
    // handler's mistake is a failure before dispatch, never a receipt.
    await expect(
      attempts(async (dispatch) => {
        dispatch.receipt(RECEIPT);
        return "never";
      }),
    ).resolves.toEqual({ status: "FAILED_BEFORE_DISPATCH" });
  });

  it("converts malformed or rejected reconciliation into UNKNOWN", async () => {
    const reconcile = vi
      .fn()
      .mockResolvedValueOnce({ status: "COMPLETED" })
      .mockRejectedValueOnce(new Error("private provider response"));
    const registry = new ActionRegistry()
      .register("refund_order", {
        parametersSchema: z.object({ amount: z.number() }),
        execute: vi.fn(),
        reconcile,
      })
      .seal();
    const intent = captured();

    await expect(registry.reconcile(intent, intent.intent.idempotencyKey)).resolves.toEqual({
      status: "UNKNOWN",
    });
    await expect(registry.reconcile(intent, intent.intent.idempotencyKey)).resolves.toEqual({
      status: "UNKNOWN",
    });
    await expect(registry.reconcile(intent, "different-key")).rejects.toThrow(
      "RECONCILIATION_BINDING_MISMATCH",
    );
  });
});
