import { describe, expect, it, vi } from "vitest";
import {
  PresenceApprovalCoordinator,
  type PresenceApprovalClient,
} from "../../src/approval/PresenceApprovalCoordinator.js";
import type { DecisionAuthority } from "../../src/decision/DecisionAuthority.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

function captured() {
  return new IntentCapture().capture(
    { action: "refund_order", target: "shopify:order:1", parameters: { amount: 350 } },
    {
      tenantId: "00000000-0000-4000-8000-000000000002",
      actor: { id: "synthetic-refund-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "shopify", operation: "refund" },
      idempotencyKey: "refund-1",
      context: {},
    },
  );
}

describe("PresenceApprovalCoordinator", () => {
  it("binds the intent hash into the approval and requires Decionis re-authorization", async () => {
    const intent = captured();
    const gate = vi.fn(
      async (request: Parameters<PresenceApprovalClient["gate"]>[0], idempotencyKey: string) => {
        void request;
        void idempotencyKey;
        return {
          verdict: "HUMAN_REQUIRED" as const,
          request_id: "synthetic-presence-request-1",
          approval_url: "https://presence.example/approve",
        };
      },
    );
    const outcome = vi.fn(async () => ({
      verdict: "PROCEED" as const,
      request_id: "synthetic-presence-request-1",
      receipt_dossier_id: "synthetic-presence-dossier-1",
    }));
    const evaluate = vi.fn(async () => ({
      verdict: "ALLOW" as const,
      decisionId: "decionis-2",
      dossierId: "dossier-2",
      intentHash: intent.intentHash,
      reasonCodes: [],
      authorization: { token: "token", expiresAt: "2026-08-14T10:00:30.000Z" },
      failClosed: false,
    }));
    const coordinator = new PresenceApprovalCoordinator(
      { gate, outcome },
      { evaluate } as DecisionAuthority,
      "Acme",
      "synthetic-approver-1",
    );

    const handoff = await coordinator.request(intent);
    const decision = await coordinator.resolveAndReauthorize(intent, handoff);

    expect(decision.verdict).toBe("ALLOW");
    expect(JSON.stringify(gate.mock.calls[0]?.[0])).toContain(intent.intentHash);
    expect(evaluate).toHaveBeenCalledWith(intent, {
      humanApproval: {
        provider: "presence",
        requestId: "synthetic-presence-request-1",
        receiptDossierId: "synthetic-presence-dossier-1",
      },
    });
  });

  it("fails closed when Presence denies or returns no independently verifiable proof", async () => {
    const intent = captured();
    const evaluate = vi.fn();
    const denied = new PresenceApprovalCoordinator(
      {
        gate: async () => ({ verdict: "DENIED" }),
        outcome: async () => ({ verdict: "DENIED" }),
      },
      { evaluate } as DecisionAuthority,
      "Acme",
      "synthetic-approver-1",
    );
    expect(await denied.resolveAndReauthorize(intent, { verdict: "DENIED" })).toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
    });

    expect(await denied.resolveAndReauthorize(intent, { verdict: "PROCEED" })).toMatchObject({
      verdict: "BLOCK",
      reasonCodes: ["PRESENCE_PROOF_MISSING"],
    });
    expect(evaluate).not.toHaveBeenCalled();
  });

  it("rejects proof-only approval evidence because the authority requires a receipt", async () => {
    const intent = captured();
    const evaluate = vi.fn(async () => ({
      verdict: "BLOCK" as const,
      decisionId: "decionis-3",
      dossierId: "dossier-3",
      intentHash: intent.intentHash,
      reasonCodes: ["POLICY_BLOCK"],
      authorization: null,
      failClosed: false,
    }));
    const coordinator = new PresenceApprovalCoordinator(
      { gate: vi.fn(), outcome: vi.fn() },
      { evaluate } as DecisionAuthority,
      "Acme",
      "synthetic-approver-1",
    );
    const result = await coordinator.resolveAndReauthorize(intent, {
      verdict: "PROCEED",
      decision_id: "presence-decision-1",
      proof: "signed-presence-proof",
    });

    expect(result).toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      reasonCodes: ["PRESENCE_PROOF_MISSING"],
    });
    expect(evaluate).not.toHaveBeenCalled();
  });
});
