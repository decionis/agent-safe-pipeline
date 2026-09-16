import {
  ActionRegistry,
  IntentCapture,
  SafeExecutor,
  createFixtureAuthorityPair,
  createGate,
  printDecision,
} from "@decionis/agent-safe-pipeline";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "agent-safe-mcp-example", version: "0.1.0" });
const capture = new IntentCapture();
// With no DECIONIS_API_KEY this is the fixture pair, exactly as before. With
// one, Decionis evaluates the same intent beside it and leaves a signed record.
const gate = createGate({
  local: createFixtureAuthorityPair(() => "BLOCK", { unsafeAllowDevelopmentFixture: true }),
  tenantId: "00000000-0000-4000-8000-000000000004",
  // Client identification on hosted calls only: which example a key was first used from.
  source: { repo: "decionis/agent-safe-pipeline", example: "mcp-tool-gate" },
});
const registry = new ActionRegistry()
  .register("delete_customer", {
    parametersSchema: z.object({ customerId: z.string().min(1).max(120) }).strict(),
    execute: async ({ parameters, dispatch }) =>
      await dispatch.run(async () => ({ deleted: parameters.customerId })),
  })
  .seal();
const executor = new SafeExecutor(registry, gate.verifier);

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
        tenantId: gate.tenantId,
        actor: { id: "synthetic-mcp-agent", type: "AI_AGENT" },
        downstreamTarget: { system: "crm", operation: "delete_customer" },
        idempotencyKey: `mcp-delete-${customerId}`,
        context: { transport: "mcp-stdio" },
      },
    );
    const decision = await gate.authority.evaluate(captured);
    const execution = await executor.run(captured, decision);
    // stdout is the MCP transport; the operator-facing lines go to stderr.
    printDecision(decision, { out: process.stderr });
    const hosted = decision.hosted;
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
      ...(hosted === undefined
        ? {}
        : {
            _meta: {
              "decionis/verdict": hosted.verdict,
              "decionis/mode": hosted.mode,
              "decionis/dossier_id": hosted.dossierId,
              ...(hosted.dossierId === null
                ? {}
                : {
                    "decionis/record": `/v1/protocol/dossiers/${encodeURIComponent(hosted.dossierId)}?org_id=${encodeURIComponent(gate.tenantId)}`,
                    "decionis/verify": `pnpm decionis:verify ${hosted.dossierId}`,
                  }),
            },
          }),
    };
  },
);

await server.connect(new StdioServerTransport());
