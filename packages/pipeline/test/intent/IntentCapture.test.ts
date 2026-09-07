import { describe, expect, it } from "vitest";
import { AuditRecorder, type AuditEventV1 } from "../../src/audit/AuditRecorder.js";
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

function capture(proposal: AgentProposal, context = trusted()) {
  return new IntentCapture({ clock: () => fixedDate, createId: () => fixedId }).capture(
    proposal,
    context,
  );
}

describe("IntentCapture", () => {
  it("can await a bounded capture audit event", async () => {
    const events: AuditEventV1[] = [];
    const audit = new AuditRecorder({
      sink: {
        write: (event) => {
          events.push(event);
        },
      },
    });
    const intentCapture = new IntentCapture({
      audit,
      clock: () => fixedDate,
      createId: () => fixedId,
    });

    const intent = await intentCapture.captureAndAudit(
      { action: "refund_order", target: "shopify:order:58291", parameters: {} },
      trusted(),
    );

    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      eventType: "INTENT_CAPTURED",
      correlation: { intentHash: intent.intentHash },
    });
  });

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

  it("binds the trusted idempotency key into the canonical intent hash", () => {
    const proposal = {
      action: "refund_order",
      target: "shopify:order:58291",
      parameters: { amount: 18400 },
    };
    const approved = capture(proposal);
    const replayedAsNewOperation = capture(proposal, {
      ...trusted(),
      idempotencyKey: "refund-58291-v2",
    });

    expect(replayedAsNewOperation.intentHash).not.toBe(approved.intentHash);
    const binding = JSON.parse(approved.canonicalIntent) as Record<string, unknown>;
    // The Decionis ExecutionIntentBinding contract has no top-level idempotency
    // field, so the key stays hash-bound inside the trusted context.
    expect("idempotency_key" in binding).toBe(false);
    expect(binding.context).toEqual({ source: "test", idempotency_key: "refund-58291-v1" });
    expect(Object.keys(binding)).toEqual([
      "action",
      "actor",
      "captured_at",
      "context",
      "downstream_target",
      "expires_at",
      "intent_id",
      "protocol_version",
      "tenant_id",
    ]);
  });

  it("reserves the context idempotency key for the trusted runtime", () => {
    expect(() =>
      capture(
        { action: "refund_order", target: "shopify:order:58291", parameters: {} },
        { ...trusted(), context: { idempotency_key: "spoofed" } },
      ),
    ).toThrow("INTENT_CONTEXT_KEY_RESERVED");

    const environment = capture(
      { action: "refund_order", target: "shopify:order:58291", parameters: {} },
      {
        ...trusted(),
        downstreamTarget: { system: "shopify", operation: "refund", environment: "staging" },
      },
    );
    expect(JSON.parse(environment.canonicalIntent)).toMatchObject({
      downstream_target: { environment: "staging" },
    });
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

  it("rejects unsafe keys, cycles, excessive nesting, and oversized canonical payloads", () => {
    const unsafe = JSON.parse(
      '{"safe":{"__proto__":{"polluted":true}}}',
    ) as AgentProposal["parameters"];
    expect(() =>
      capture({ action: "refund_order", target: "order:1", parameters: unsafe }),
    ).toThrow("UNSAFE_INTENT_KEY");

    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() =>
      capture({ action: "refund_order", target: "order:1", parameters: cyclic as never }),
    ).toThrow("CYCLIC_INTENT");

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

  it("rejects non-JSON objects and excessive entry or array counts before schema parsing", () => {
    expect(() =>
      capture({ action: "refund_order", target: "order:1", parameters: new Date() as never }),
    ).toThrow("INVALID_JSON_OBJECT");

    const entryLimited = new IntentCapture({
      hasher: new CanonicalIntentHasher({ maxEntries: 2 }),
      clock: () => fixedDate,
      createId: () => fixedId,
    });
    expect(() =>
      entryLimited.capture(
        { action: "refund_order", target: "order:1", parameters: { a: 1, b: 2, c: 3 } },
        trusted(),
      ),
    ).toThrow("INTENT_TOO_COMPLEX");

    const arrayLimited = new IntentCapture({
      hasher: new CanonicalIntentHasher({ maxArrayLength: 2 }),
      clock: () => fixedDate,
      createId: () => fixedId,
    });
    expect(() =>
      arrayLimited.capture(
        { action: "refund_order", target: "order:1", parameters: { values: [1, 2, 3] } },
        trusted(),
      ),
    ).toThrow("INTENT_ARRAY_TOO_LARGE");

    const arrayEntryLimited = new IntentCapture({
      hasher: new CanonicalIntentHasher({ maxEntries: 5 }),
      clock: () => fixedDate,
      createId: () => fixedId,
    });
    expect(() =>
      arrayEntryLimited.capture(
        { action: "refund_order", target: "order:1", parameters: { values: [1, 2] } },
        trusted(),
      ),
    ).toThrow("INTENT_TOO_COMPLEX");

    expect(
      capture({ action: "refund_order", target: "order:1", parameters: { values: [1, 2] } }).intent
        .parameters,
    ).toEqual({ values: [1, 2] });

    const shared = { value: 1 };
    expect(
      capture({ action: "refund_order", target: "order:1", parameters: { a: shared, b: shared } })
        .intent.parameters,
    ).toEqual({ a: { value: 1 }, b: { value: 1 } });
  });
});
