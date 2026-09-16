import {
  ActionRegistry,
  IntentCapture,
  PresenceApprovalCoordinator,
  SafeExecutor,
  createFixtureAuthorityPair,
  createGate,
  printDecision,
} from "@decionis/agent-safe-pipeline";
import { z } from "zod";

const proposal = {
  action: "refund_order",
  target: "shopify:order:synthetic-1001",
  parameters: { amountMinor: 35_000, currency: "USD", orderId: "synthetic-1001" },
};
const amount = proposal.parameters.amountMinor;

// With no DECIONIS_API_KEY this is the fixture pair, exactly as before. With
// one, Decionis evaluates the same intent beside it and leaves a signed record.
const gate = createGate({
  local: createFixtureAuthorityPair(
    (_intent, evidence) => {
      if (amount > 100_000) return "BLOCK";
      if (amount <= 10_000 || evidence?.humanApproval?.receiptDossierId !== undefined) {
        return "ALLOW";
      }
      return "ESCALATE";
    },
    { unsafeAllowDevelopmentFixture: true },
  ),
  tenantId: "00000000-0000-4000-8000-000000000002",
});
const captured = new IntentCapture().capture(proposal, {
  tenantId: gate.tenantId,
  actor: { id: "synthetic-refund-agent", type: "AI_AGENT" },
  downstreamTarget: { system: "shopify", operation: "refund" },
  idempotencyKey: "refund-synthetic-1001-v1",
  context: { source: "shopify-refund-example" },
});

let decision = await gate.authority.evaluate(captured);
if (decision.verdict === "ESCALATE") {
  const coordinator = new PresenceApprovalCoordinator(
    {
      gate: async () => ({
        verdict: "HUMAN_REQUIRED",
        request_id: "synthetic-presence-request",
        approval_url: "https://presence.example.invalid/approve",
      }),
      outcome: async () => ({
        verdict: "PROCEED",
        request_id: "synthetic-presence-request",
        receipt_dossier_id: "synthetic-presence-receipt",
      }),
    },
    gate.authority,
    "Synthetic Shop",
    "synthetic-approver",
  );
  decision = await coordinator.resolveAndReauthorize(captured, await coordinator.request(captured));
}

const registry = new ActionRegistry()
  .register("refund_order", {
    parametersSchema: z
      .object({
        amountMinor: z.number().int().positive(),
        currency: z.literal("USD"),
        orderId: z.string(),
      })
      .strict(),
    execute: async ({ parameters, dispatch }) =>
      await dispatch.run(async (idempotencyKey) => ({
        providerRequest: {
          orderId: parameters.orderId,
          amountMinor: parameters.amountMinor,
          idempotencyKey,
        },
      })),
  })
  .seal();
const result = await new SafeExecutor(registry, gate.verifier).run(captured, decision);

process.stdout.write(
  `${JSON.stringify(
    {
      intentHash: captured.intentHash,
      decision: {
        verdict: decision.verdict,
        decisionId: decision.decisionId,
        dossierId: decision.dossierId,
      },
      result,
    },
    null,
    2,
  )}\n`,
);
printDecision(decision);
