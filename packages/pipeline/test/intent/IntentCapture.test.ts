import { describe, expect, it } from "vitest";
import { CanonicalIntentHasher } from "../../src/intent/CanonicalIntentHasher.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import type { AgentProposal, TrustedIntentContext } from "../../src/intent/ExecutionIntent.js";

const fixedId = "00000000-0000-4000-8000-000000000001";
const fixedDate = new Date("2026-08-14T10:00:00.000Z");

function trusted(): TrustedIntentContext {
  return {
    tenantId: "00000000-0000-4000-8000-000000000002",
    actor: { id: "synthetic-refund-agent", type: "AI_AGENT", runtime: "mcp" },
    downstreamTarget: {
      system: "shopify",
      operation: "refund",
      endpoint: "POST /orders/refunds",
    },
    context: { source: "test" },
    correlationId: "corr-1",
    idempotencyKey: "refund-58291-v1",
  };
}

function capture(proposal: AgentProposal) {
  return new IntentCapture({ clock: () => fixedDate, createId: () => fixedId }).capture(
    proposal,
    trusted(),
  );
}

describe("IntentCapture", () => {
  it("produces the same canonical hash regardless of object insertion order", () => {
    const first = capture({
      action: "refund_order",
      target: "shopify:order:58291",
      parameters: { amount: 18400, currency: "USD" },
    });
    const second = capture({
      action: "refund_order",
      target: "shopify:order:58291",
      parameters: { currency: "USD", amount: 18400 },
    });

    expect(first.intentHash).toBe(second.intentHash);
    expect(first.canonicalIntent).toBe(second.canonicalIntent);
    expect(first.intentHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(Object.isFrozen(first.intent)).toBe(true);
    expect(Object.isFrozen(first.intent.parameters)).toBe(true);
  });

  it("changes the authorization binding when any action parameter changes", () => {
    const approved = capture({
      action: "refund_order",
      target: "shopify:order:58291",
      parameters: { amount: 18400 },
    });
    const manipulated = capture({
      action: "refund_order",
      target: "shopify:order:58291",
      parameters: { amount: 50000 },
    });

    expect(manipulated.intentHash).not.toBe(approved.intentHash);
  });

  it("rejects agent-supplied authorization fields", () => {
    expect(() =>
      capture({
        action: "refund_order",
        target: "shopify:order:58291",
        parameters: {},
        authorized: true,
      } as AgentProposal),
    ).toThrow();
  });

  it("rejects unsafe keys, excessive nesting, and oversized canonical payloads", () => {
    const unsafe = JSON.parse(
      '{"safe":{"__proto__":{"polluted":true}}}',
    ) as AgentProposal["parameters"];
    expect(() =>
      capture({ action: "refund_order", target: "order:1", parameters: unsafe }),
    ).toThrow("UNSAFE_INTENT_KEY");

    let nested: Record<string, unknown> = {};
    for (let index = 0; index < 22; index += 1) nested = { nested };
    expect(() =>
      capture({ action: "refund_order", target: "order:1", parameters: nested as never }),
    ).toThrow("INTENT_TOO_DEEP");

    const hasher = new CanonicalIntentHasher({ maxBytes: 200 });
    const limited = new IntentCapture({
      hasher,
      clock: () => fixedDate,
      createId: () => fixedId,
    });
    expect(() =>
      limited.capture(
        { action: "refund_order", target: "order:1", parameters: { note: "x".repeat(300) } },
        trusted(),
      ),
    ).toThrow("INTENT_TOO_LARGE");
  });
});
