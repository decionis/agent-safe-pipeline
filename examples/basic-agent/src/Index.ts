import {
  ActionRegistry,
  IntentCapture,
  SafeExecutor,
  createFixtureAuthorityPair,
  createGate,
  printDecision,
} from "@decionis/agent-safe-pipeline";
import { z } from "zod";

// With no DECIONIS_API_KEY this is the fixture pair, exactly as before. With
// one, Decionis evaluates the same intent beside it and leaves a signed record.
const gate = createGate({
  local: createFixtureAuthorityPair(() => "BLOCK", { unsafeAllowDevelopmentFixture: true }),
  tenantId: "00000000-0000-4000-8000-000000000001",
  // Client identification on hosted calls only: which example a key was first used from.
  source: { repo: "decionis/agent-safe-pipeline", example: "basic-agent" },
});
const captured = new IntentCapture().capture(
  {
    action: "delete_customer",
    target: "crm:customer:synthetic-42",
    parameters: { customerId: "synthetic-42" },
  },
  {
    tenantId: gate.tenantId,
    actor: { id: "synthetic-demo-agent", type: "AI_AGENT" },
    downstreamTarget: { system: "crm", operation: "delete_customer" },
    idempotencyKey: "basic-delete-synthetic-42",
    context: { source: "basic-example" },
  },
);

const registry = new ActionRegistry()
  .register("delete_customer", {
    parametersSchema: z.object({ customerId: z.string() }).strict(),
    execute: async ({ parameters, dispatch }) =>
      await dispatch.run(async () => ({ deleted: parameters.customerId })),
  })
  .seal();
const decision = await gate.authority.evaluate(captured);
const result = await new SafeExecutor(registry, gate.verifier).run(captured, decision);

process.stdout.write(
  `${JSON.stringify(
    {
      proposal: `${captured.intent.action} ${captured.intent.target}`,
      intentHash: captured.intentHash,
      verdict: decision.verdict,
      execution: result,
    },
    null,
    2,
  )}\n`,
);
printDecision(decision);
