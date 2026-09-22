import {
  createFixtureAuthorityPair,
  createHostedGate,
  type JsonObject,
} from "@decionis/agent-safe-pipeline";
import { McpGuard } from "@decionis/agentsafe";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "agent-safe-mcp-example", version: "0.1.0" });
// With no DECIONIS_API_KEY this is the fixture pair, exactly as before. With
// one, Decionis evaluates the same intent beside it and leaves a signed record.
const gate = await createHostedGate({
  local: createFixtureAuthorityPair(() => "BLOCK", { unsafeAllowDevelopmentFixture: true }),
  tenantId: "00000000-0000-4000-8000-000000000004",
  // Client identification on hosted calls only: which example a key was first used from.
  source: { repo: "decionis/agent-safe-pipeline", example: "mcp-tool-gate", surface: "github" },
});

const customerId = z.string().min(1).max(120);

/**
 * MCP has already decided how the model calls this tool. The guard decides
 * whether this exact invocation may run: it turns the tool and its arguments
 * into an Agent-Safe intent, asks the authority, claims the grant once, and
 * only then reaches the tool. Nothing here is an MCP registry or a
 * replacement for MCP's own authentication.
 */
const guard = new McpGuard({
  tools: [
    {
      binding: {
        tool: "delete_customer",
        action: "delete_customer",
        system: "crm",
        operation: "delete_customer",
        // The target is derived from the arguments, never accepted from the caller.
        target: "crm:customer:{customerId}",
        consequential: ["customerId"],
        argumentsSchema: z.object({ customerId }).strict() as unknown as z.ZodType<JsonObject>,
      },
      invoke: async (args: JsonObject) => ({ deleted: args["customerId"] }),
    },
  ],
  authority: gate.authority,
  verifier: gate.verifier,
  tenantId: gate.tenantId,
  actor: { id: "synthetic-mcp-agent", type: "AI_AGENT", runtime: "mcp" },
});

server.registerTool(
  "delete_customer",
  {
    description: "Propose deleting a customer through an independent policy gate.",
    inputSchema: { customerId },
  },
  async (args, extra) => {
    const outcome = await guard.guard({
      tool: "delete_customer",
      arguments: args as unknown as JsonObject,
      transport: "stdio",
      ...(typeof extra?.requestId === "string" ? { correlationId: extra.requestId } : {}),
    });
    // stdout is the MCP transport; the operator-facing lines go to stderr.
    process.stderr.write(
      `${outcome.executed === true ? "executed" : outcome.executed === null ? "outcome unknown" : `refused: ${outcome.reason}`}\n`,
    );
    return {
      content: [{ type: "text", text: JSON.stringify(outcome) }],
      isError: outcome.executed !== true,
      ...(outcome.dossierId === null
        ? {}
        : {
            _meta: {
              "decionis/verdict": outcome.verdict,
              "decionis/dossier_id": outcome.dossierId,
              "decionis/record": `/v1/protocol/dossiers/${encodeURIComponent(outcome.dossierId)}?org_id=${encodeURIComponent(gate.tenantId)}`,
              "decionis/verify": `pnpm decionis:verify ${outcome.dossierId}`,
            },
          }),
    };
  },
);

await server.connect(new StdioServerTransport());
