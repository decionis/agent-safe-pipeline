import {
  ActionRegistry,
  IntentCapture,
  PresenceApprovalCoordinator,
  SafeExecutor,
  createFixtureAuthorityPair,
} from "@decionis/agent-safe-pipeline";
import { z } from "zod";

const captured = new IntentCapture().capture(
  {
    action: "refund_order",
    target: "shopify:order:synthetic-1001",
    parameters: { amountMinor: 35_000, currency: "USD", orderId: "synthetic-1001" },
  },
  {
    tenantId: "00000000-0000-4000-8000-000000000002",
    actor: { id: "refund-agent", type: "AI_AGENT" },
    downstreamTarget: { system: "shopify", operation: "refund" },
    idempotencyKey: "refund-synthetic-1001-v1",
    context: { source: "shopify-refund-example" },
  },
);

const amount = Number(captured.intent.parameters.amountMinor);
const { authority, verifier } = createFixtureAuthorityPair(
  (_intent, evidence) => {
    if (amount > 100_000) return "BLOCK";
    if (amount <= 10_000 || evidence?.humanApproval?.receiptDossierId !== undefined) return "ALLOW";
    return "ESCALATE";
  },
  { unsafeAllowDevelopmentFixture: true },
);

let decision = await authority.evaluate(captured);
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
    authority,
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
    execute: ({ parameters, authorization }) => ({
      providerRequest: {
        orderId: parameters.orderId,
        amountMinor: parameters.amountMinor,
        idempotencyKey: authorization.grantId,
      },
    }),
  })
  .seal();
const result = await new SafeExecutor(registry, verifier).run(captured, decision);

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
