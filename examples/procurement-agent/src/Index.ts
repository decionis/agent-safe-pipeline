import {
  ActionRegistry,
  IntentCapture,
  SafeExecutor,
  createFixtureAuthorityPair,
  createHostedGate,
  printHostedOutcome,
} from "@decionis/agent-safe-pipeline";
import { z } from "zod";

const purchaseAmountMinor = 480_000;
const remainingBudgetMinor = 500_000;
const requestedConcurrentUsers = 4;
const existingSoftware = [
  { productId: "synthetic-legacy-suite-a", availableConcurrentUsers: 2 },
  { productId: "synthetic-legacy-suite-b", availableConcurrentUsers: 3 },
];
const availableConcurrentUsers = existingSoftware.reduce(
  (total, software) => total + software.availableConcurrentUsers,
  0,
);
const withinBudget = purchaseAmountMinor <= remainingBudgetMinor;
const existingCapacityCanAccommodateRequest = availableConcurrentUsers >= requestedConcurrentUsers;

// With nothing set this is the fixture pair, as before; with DECIONIS_HOSTED=1
// Decionis evaluates the same purchase beside it and leaves a signed record.
const gate = await createHostedGate({
  local: createFixtureAuthorityPair(
    () => {
      if (!withinBudget) return "BLOCK";
      if (existingCapacityCanAccommodateRequest) return "ESCALATE";
      return "ALLOW";
    },
    { unsafeAllowDevelopmentFixture: true },
  ),
  tenantId: "00000000-0000-4000-8000-000000000004",
  source: { repo: "decionis/agent-safe-pipeline", example: "procurement-agent", surface: "github" },
});

const captured = new IntentCapture().capture(
  {
    action: "purchase_software",
    target: "procurement:software:synthetic-collaboration-suite",
    parameters: {
      productId: "synthetic-collaboration-suite",
      amountMinor: purchaseAmountMinor,
      currency: "USD",
      requestedConcurrentUsers,
    },
  },
  {
    tenantId: gate.tenantId,
    actor: { id: "synthetic-procurement-agent", type: "AI_AGENT" },
    downstreamTarget: { system: "procurement", operation: "purchase_software" },
    idempotencyKey: "procurement-synthetic-collaboration-suite-v1",
    context: {
      source: "procurement-example",
      remainingBudgetMinor,
      existingSoftware,
    },
  },
);

const registry = new ActionRegistry()
  .register("purchase_software", {
    parametersSchema: z
      .object({
        productId: z.string(),
        amountMinor: z.number().int().positive(),
        currency: z.literal("USD"),
        requestedConcurrentUsers: z.number().int().positive(),
      })
      .strict(),
    execute: async ({ parameters, dispatch }) =>
      await dispatch.run(async () => ({
        purchaseOrderCreated: true,
        productId: parameters.productId,
        amountMinor: parameters.amountMinor,
      })),
  })
  .seal();

const decision = await gate.authority.evaluate(captured);
const procurementDecision = decision.verdict === "ESCALATE" ? "HOLD" : decision.verdict;
const execution = await new SafeExecutor(registry, gate.verifier).run(captured, decision);

process.stdout.write(
  `${JSON.stringify(
    {
      proposal: {
        productId: captured.intent.parameters.productId,
        amountMinor: purchaseAmountMinor,
        currency: "USD",
        requestedConcurrentUsers,
      },
      policyFacts: {
        remainingBudgetMinor,
        withinBudget,
        existingSoftware,
        availableConcurrentUsers,
        existingCapacityCanAccommodateRequest,
      },
      decision: {
        procurementDecision,
        enforcementVerdict: decision.verdict,
        reasonCode:
          procurementDecision === "HOLD"
            ? "EXISTING_SOFTWARE_CAPACITY_REVIEW"
            : decision.reasonCodes[0],
      },
      execution,
    },
    null,
    2,
  )}\n`,
);
await printHostedOutcome(gate, decision);
