import {
  ActionRegistry,
  IntentCapture,
  SafeExecutor,
  createFixtureAuthorityPair,
} from "@decionis/agent-safe-pipeline";
import { z } from "zod";

const captured = new IntentCapture().capture(
  {
    action: "delete_customer",
    target: "crm:customer:synthetic-42",
    parameters: { customerId: "synthetic-42" },
  },
  {
    tenantId: "00000000-0000-4000-8000-000000000001",
    actor: { id: "synthetic-demo-agent", type: "AI_AGENT" },
    downstreamTarget: { system: "crm", operation: "delete_customer" },
    idempotencyKey: "basic-delete-synthetic-42",
    context: { source: "basic-example" },
  },
);

const { authority, verifier } = createFixtureAuthorityPair(() => "BLOCK", {
  unsafeAllowDevelopmentFixture: true,
});
const registry = new ActionRegistry()
  .register("delete_customer", {
    parametersSchema: z.object({ customerId: z.string() }).strict(),
    execute: ({ parameters }) => ({ deleted: parameters.customerId }),
  })
  .seal();
const decision = await authority.evaluate(captured);
const result = await new SafeExecutor(registry, verifier).run(captured, decision);

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
