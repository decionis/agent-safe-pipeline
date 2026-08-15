import {
  ActionRegistry,
  IntentCapture,
  SafeExecutor,
  createFixtureAuthorityPair,
} from "@decionis/agent-safe-pipeline";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "agent-safe-mcp-example", version: "0.1.0" });
const capture = new IntentCapture();
const { authority, verifier } = createFixtureAuthorityPair(() => "BLOCK", {
  unsafeAllowDevelopmentFixture: true,
});
const registry = new ActionRegistry()
  .register("delete_customer", {
    parametersSchema: z.object({ customerId: z.string().min(1).max(120) }).strict(),
    execute: ({ parameters }) => ({ deleted: parameters.customerId }),
  })
  .seal();
const executor = new SafeExecutor(registry, verifier);

server.registerTool(
  "delete_customer",
  {
    description: "Propose deleting a customer through an independent policy gate.",
    inputSchema: { customerId: z.string().min(1).max(120) },
  },
  async ({ customerId }) => {
    const captured = capture.capture(
      {
        action: "delete_customer",
        target: `crm:customer:${customerId}`,
        parameters: { customerId },
      },
      {
        tenantId: "00000000-0000-4000-8000-000000000004",
        actor: { id: "synthetic-mcp-agent", type: "AI_AGENT" },
        downstreamTarget: { system: "crm", operation: "delete_customer" },
        idempotencyKey: `mcp-delete-${customerId}`,
        context: { transport: "mcp-stdio" },
      },
    );
    const decision = await authority.evaluate(captured);
    const execution = await executor.run(captured, decision);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            intentHash: captured.intentHash,
            verdict: decision.verdict,
            execution,
          }),
        },
      ],
      isError: !execution.executed,
    };
  },
);

await server.connect(new StdioServerTransport());
