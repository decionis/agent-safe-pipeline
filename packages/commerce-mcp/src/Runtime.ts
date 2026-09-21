import { runtimeAccess, type AccessDependencies } from "./Access.js";
import { CommerceGateClient } from "./CommerceGateClient.js";
import { CommerceGateConfiguration } from "./Configuration.js";
import { HistoricalClient } from "./HistoricalClient.js";
import { HistoricalTools, HISTORICAL_MCP_INSTRUCTIONS } from "./HistoricalTools.js";
import { createMcpHandler, COMMERCEGATE_MCP_INSTRUCTIONS } from "./Server.js";
import { CommerceGateTools } from "./Tools.js";

/** Managed HTTP adds historical assessment without replacing the existing contract. */
export function createRuntimeHandler(
  environment: Record<string, string | undefined>,
  transport: string,
  dependencies: AccessDependencies = {},
) {
  if (transport !== "http" && transport !== "stdio")
    throw new Error("MCP_TRANSPORT must be stdio or http.");
  const configuration = new CommerceGateConfiguration(
    environment,
    runtimeAccess(environment, transport, dependencies),
  );
  const tools = new CommerceGateTools(
    configuration,
    new CommerceGateClient(configuration, dependencies.fetch),
  ).build();
  if (transport === "http") {
    const describe = tools[0].handler;
    tools[0] = {
      ...tools[0],
      handler: async (args) => {
        const result = await describe(args);
        if (result.isError) return result;
        const structuredContent = {
          ...result.structuredContent,
          tools: tools.map((tool) => tool.name),
          historical_assessment: {
            window_days: 90,
            trial_days: 14,
            trial_data: "synthetic",
            entitlement_authority: "server_verified_aws_grant",
            data_sources: ["synthetic", "connected_store"],
            requires_gateway: "/aws",
            caller_supplied_transactions: false,
            dates_and_policy_are_server_bound: true,
            signed_proof_only_when_available: true,
          },
        };
        return {
          ...result,
          structuredContent,
          content: [{ type: "text" as const, text: JSON.stringify(structuredContent) }],
        };
      },
    };
    tools.push(
      ...new HistoricalTools(new HistoricalClient(configuration, dependencies.fetch)).build(),
    );
    return createMcpHandler(
      tools,
      `${COMMERCEGATE_MCP_INSTRUCTIONS} ${HISTORICAL_MCP_INSTRUCTIONS}`,
    );
  }
  return createMcpHandler(tools);
}
