import { describe, expect, it, vi } from "vitest";
import { DecionisGate } from "../../src/decision/DecionisGate.js";
import type { ManagedEscalationState } from "../../src/decision/DecisionAuthority.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

const NOW = Date.parse("2030-01-01T00:00:00.000Z");
const chain = { chain_id: "synthetic-presence-chain", tier_count: 2, tiers_approved: 0 };
const tier = { tier: 1, tier_count: 2, principal_id: "synthetic-human" };

function fixture(
  progress: Record<string, unknown>,
  state: "AWAITING_APPROVER" | "FAILED" | "GRANT_READY" = "AWAITING_APPROVER",
) {
  const captured = new IntentCapture({ clock: () => new Date(NOW), ttlSeconds: 300 }).capture(
    { action: "http.post", target: "POST /live-proof/synthetic", parameters: { amount: 1 } },
    {
      tenantId: "00000000-0000-4000-8000-000000000003",
      actor: { id: "synthetic-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "synthetic-api", operation: "http.post" },
      idempotencyKey: "synthetic-managed-chain-1",
      context: {},
    },
  );
  const outcome =
    state === "FAILED" ? "ERROR" : state === "GRANT_READY" ? "ALLOW" : "ESCALATE_PENDING";
  const reasonCodes = state === "FAILED" ? ["PRESENCE_DELIVERY_FAILED"] : ["PRESENCE_PENDING"];
  const summary = {
    escalation_id: "synthetic-escalation",
    intent_id: captured.intent.intentId,
    status: state,
    outcome,
    expires_at: captured.intent.expiresAt,
    reason_codes: reasonCodes,
    ...progress,
  };
  const initial = {
    decision_id: "synthetic-decision",
    chain_id: "synthetic-decision-chain",
    status: "ESCALATE",
    should_execute: false,
    reason_codes: ["PRESENCE_REQUIRED"],
    action_hash: captured.intentHash,
    mode: "ENFORCEMENT",
    execution_token: null,
    execution_token_expires_at: null,
    dossier_id: "synthetic-dossier",
    dossier_url: "/v1/protocol/dossiers/synthetic-dossier",
    managed_escalation: summary,
  };
  const status: Record<string, unknown> = {
    ...summary,
    action_hash: captured.intentHash,
    decision: null,
  };
  const fetchMock = vi.fn<typeof fetch>(
    async (url) => new Response(JSON.stringify(String(url).endsWith("/grants") ? initial : status)),
  );
  const gate = new DecionisGate({
    baseUrl: "http://127.0.0.1:3001",
    apiKey: "synthetic-test-key",
    allowInsecureLoopback: true,
    fetch: fetchMock,
  });
  const expected: ManagedEscalationState = {
    escalationId: "synthetic-escalation",
    intentId: captured.intent.intentId,
    status: "AWAITING_APPROVER",
    outcome: "ESCALATE_PENDING",
    expiresAt: captured.intent.expiresAt,
    reasonCodes: ["PRESENCE_PENDING"],
  };
  return { captured, gate, expected, initial, status };
}

describe("managed approval progress on the authority wire", () => {
  it.each([
    { approval_chain: chain },
    { approval_tier: tier },
    { approval_chain: { ...chain, tiers_approved: 2 } },
    { approval_chain: { ...chain, tier_count: 5, tiers_approved: 5 } },
    { approval_tier: { ...tier, tier: 5, tier_count: 5 } },
  ])("accepts bounded progress without treating it as approval: %j", async (progress) => {
    const { captured, gate, expected } = fixture(progress);
    const initial = await gate.evaluate(captured, undefined, { escalation: { mode: "MANAGED" } });
    expect(initial).toMatchObject({
      verdict: "ESCALATE",
      authorization: null,
      failClosed: false,
      managedEscalation: expected,
    });
    const status = await gate.getManagedEscalationStatus(captured, expected, { clock: () => NOW });
    expect(status).toMatchObject({
      status: "AWAITING_APPROVER",
      outcome: "ESCALATE_PENDING",
      decision: null,
    });
  });

  it("retains a terminal delivery failure before Presence assigned a chain id", async () => {
    const { captured, gate, expected } = fixture(
      { approval_chain: { ...chain, chain_id: "" } },
      "FAILED",
    );
    const initial = await gate.evaluate(captured, undefined, { escalation: { mode: "MANAGED" } });
    expect(initial.authorization).toBeNull();
    expect(initial.managedEscalation).toMatchObject({
      status: "FAILED",
      outcome: "ERROR",
      reasonCodes: ["PRESENCE_DELIVERY_FAILED"],
    });
    const status = await gate.getManagedEscalationStatus(captured, expected, { clock: () => NOW });
    expect(status).toMatchObject({
      status: "FAILED",
      outcome: "ERROR",
      decision: null,
      reasonCodes: ["PRESENCE_DELIVERY_FAILED"],
    });
  });

  it("cannot replace a verified grant with a completed chain count", async () => {
    const { captured, gate, expected } = fixture(
      { approval_chain: { ...chain, tiers_approved: 2 } },
      "GRANT_READY",
    );
    const status = await gate.getManagedEscalationStatus(captured, expected, { clock: () => NOW });
    expect(status).toMatchObject({
      status: "FAILED",
      outcome: "ERROR",
      decision: null,
      reasonCodes: ["MANAGED_ESCALATION_GRANT_INVALID"],
    });
  });

  it("accepts a bound grant only from the authority's completed-chain decision", async () => {
    const {
      captured,
      gate,
      expected,
      initial,
      status: wire,
    } = fixture({ approval_chain: { ...chain, tiers_approved: 2 } }, "GRANT_READY");
    wire.decision = {
      ...initial,
      status: "ALLOW",
      should_execute: true,
      execution_token: "synthetic-issued-grant",
      execution_token_expires_at: new Date(NOW + 60_000).toISOString(),
      managed_escalation: null,
    };
    const clock = vi.spyOn(Date, "now").mockReturnValue(NOW);
    try {
      const status = await gate.getManagedEscalationStatus(captured, expected, {
        clock: () => NOW,
      });
      expect(status).toMatchObject({
        status: "GRANT_READY",
        outcome: "ALLOW",
        decision: {
          verdict: "ALLOW",
          authorization: { token: "synthetic-issued-grant" },
          failClosed: false,
        },
      });
    } finally {
      clock.mockRestore();
    }
  });

  it("still binds status to the captured action when progress is valid", async () => {
    const { captured, gate, expected, status: wire } = fixture({ approval_chain: chain });
    wire.action_hash = `sha256:${"0".repeat(64)}`;
    const status = await gate.getManagedEscalationStatus(captured, expected, { clock: () => NOW });
    expect(status).toMatchObject({
      status: "FAILED",
      decision: null,
      reasonCodes: ["AUTHORITY_BINDING_MISMATCH"],
    });
  });

  it.each([
    { approval_chain: { ...chain, execution_token: "synthetic-injected-grant" } },
    { approval_chain: { ...chain, tier_count: 0 } },
    { approval_chain: { ...chain, tier_count: 6 } },
    { approval_chain: { ...chain, tiers_approved: -1 } },
    { approval_chain: { ...chain, tiers_approved: 3 } },
    { approval_chain: { ...chain, tiers_approved: 0.5 } },
    { approval_chain: { ...chain, chain_id: "x".repeat(201) } },
    { approval_chain: { ...chain, chain_id: "synthetic\nchain" } },
    { approval_chain: null },
    { approval_tier: { ...tier, approved: true } },
    { approval_tier: { ...tier, tier: 0 } },
    { approval_tier: { ...tier, tier: 3 } },
    { approval_tier: { ...tier, tier_count: 6 } },
    { approval_tier: { ...tier, principal_id: "" } },
    { approval_tier: { ...tier, principal_id: "synthetic\nhuman" } },
    { approval_grant: "synthetic-injected-grant" },
  ])("fails closed on malformed or unknown progress: %j", async (progress) => {
    const { captured, gate, expected } = fixture(progress);
    const initial = await gate.evaluate(captured, undefined, { escalation: { mode: "MANAGED" } });
    expect(initial).toMatchObject({ verdict: "BLOCK", authorization: null, failClosed: true });
    const status = await gate.getManagedEscalationStatus(captured, expected, { clock: () => NOW });
    expect(status).toMatchObject({
      status: "FAILED",
      outcome: "ERROR",
      decision: null,
      reasonCodes: ["MANAGED_ESCALATION_RESPONSE_INVALID"],
    });
  });
});
