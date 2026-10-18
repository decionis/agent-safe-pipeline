import { createHash } from "node:crypto";
import { z } from "zod";
import { describe, expect, it } from "vitest";
import { ActionRegistry, PreDispatchRefusal } from "../../src/execution/ActionRegistry.js";
import { MonotonicDeadline } from "../../src/execution/ExecutionDeadline.js";
import { RegistryExecutor } from "../../src/execution/RegistryExecutor.js";
import { CanonicalIntentHasher } from "../../src/intent/CanonicalIntentHasher.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

function capture(expectedEffectDigest?: `sha256:${string}`) {
  return new IntentCapture().capture(
    { action: "refund_order", target: "shop:order:1", parameters: { amount: 5 } },
    {
      tenantId: "00000000-0000-4000-8000-000000000007",
      actor: { id: "synthetic-registry-agent", type: "agent" },
      downstreamTarget: { system: "shop", operation: "refund" },
      idempotencyKey: "refund-5",
      context: {},
      ...(expectedEffectDigest === undefined ? {} : { expectedEffectDigest }),
    },
  );
}

const authorization = (intentHash: string) =>
  Object.freeze({
    decisionId: "decision-1",
    dossierId: "dossier-1",
    grantId: "grant-1",
    intentHash,
    expiresAt: "2099-01-01T00:00:00.000Z",
  });

function registryWith(execute: () => unknown) {
  return new ActionRegistry()
    .register("refund_order", {
      parametersSchema: z.object({ amount: z.number() }),
      execute: execute as never,
    })
    .seal();
}

describe("RegistryExecutor", () => {
  it("describes itself as the registry, with nothing to state about a connection", async () => {
    const executor = new RegistryExecutor(registryWith(() => 1));
    expect(executor).toMatchObject({
      platform: "action-registry",
      version: "registry/1",
      style: "dispatch",
      actionTypes: [],
    });
    expect(await executor.capabilities()).toEqual([]);
  });

  it("prepares exactly the captured intent, its effect commitment included", async () => {
    const executor = new RegistryExecutor(registryWith(() => 1));
    const plain = capture();
    const canonical = CanonicalIntentHasher.stringify({ amount: 5 });
    expect(await executor.prepare(plain)).toEqual({
      actionType: "refund_order",
      proposal: { action: "refund_order", target: "shop:order:1", parameters: { amount: 5 } },
      downstreamTarget: { system: "shop", operation: "refund" },
      idempotencyKey: "refund-5",
      expectedEffectDigest: null,
      requestDigest: `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`,
      facts: {},
    });
    const committed = capture(`sha256:${"c".repeat(64)}`);
    expect((await executor.prepare(committed)).expectedEffectDigest).toBe(
      `sha256:${"c".repeat(64)}`,
    );
  });

  it("carries what the registry reports, verbatim, and reads only a dispatch", async () => {
    const intent = capture();
    const run = (registry: ActionRegistry) =>
      new RegistryExecutor(registry).execute({
        action: intent,
        prepared: {} as never,
        intent,
        scope: null,
        authorization: authorization(intent.intentHash),
        idempotencyKey: "refund-5",
        deadline: MonotonicDeadline.after(1_000),
        dispatch: {} as never,
      });
    expect(
      await run(
        registryWith(() => {
          throw new PreDispatchRefusal("PAYLOAD_BINDING_MISMATCH");
        }),
      ),
    ).toEqual({ kind: "NOT_DISPATCHED", code: "PAYLOAD_BINDING_MISMATCH" });
    const executor = new RegistryExecutor(registryWith(() => 1));
    expect(
      await executor.observe({
        kind: "DISPATCHED",
        receipt: { status: "FAILED_BEFORE_DISPATCH" },
      }),
    ).toEqual({ status: "INDETERMINATE", reason: null, result: null });
    expect(
      await executor.observe({
        kind: "DISPATCHED",
        receipt: { status: "UNKNOWN_AFTER_DISPATCH", receipt: "r.e.c" },
      }),
    ).toEqual({ status: "INDETERMINATE", reason: null, result: null, signedReceipt: "r.e.c" });
    expect(
      await executor.observe({
        kind: "DISPATCHED",
        receipt: { status: "REFUSED_AFTER_DISPATCH", reason: "NO", receipt: null },
      }),
    ).toEqual({ status: "FAILED", reason: "NO", result: null, signedReceipt: null });
  });
});
