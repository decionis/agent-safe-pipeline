#!/usr/bin/env node

import { CommerceGateClient } from "./CommerceGateClient.js";
import { CommerceGateConfiguration } from "./Configuration.js";
import { CommerceGateHttpServer, DEFAULT_HTTP_HOST, DEFAULT_HTTP_PORT } from "./Http.js";
import { createMcpHandler, CommerceGateStdioServer } from "./Server.js";
import { CommerceGateTools } from "./Tools.js";

const configuration = new CommerceGateConfiguration();
const client = new CommerceGateClient(configuration);
const tools = new CommerceGateTools(configuration, client).build();
const handler = createMcpHandler(tools);

// Stdio for a desktop or a local agent; streamable HTTP (`--http`, or
// MCP_TRANSPORT=http) for a container Amazon Bedrock AgentCore Runtime proxies
// to, on 0.0.0.0:8000/mcp with /ping as its health check.
const transport = process.argv.includes("--http")
  ? "http"
  : (process.env.MCP_TRANSPORT ?? "stdio").trim().toLowerCase();
if (transport === "http") {
  const port = Number.parseInt(process.env.PORT ?? String(DEFAULT_HTTP_PORT), 10);
  const host = process.env.HOST?.trim() || DEFAULT_HTTP_HOST;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`PORT must be a port number, got ${process.env.PORT}`);
  }
  const server = await new CommerceGateHttpServer(handler, { port, host }).listen();
  const stop = () => server.close(() => process.exit(0));
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  process.stderr.write(`commercegate-mcp listening on http://${host}:${port}/mcp\n`);
} else if (transport === "stdio") {
  await CommerceGateStdioServer.run(handler);
} else {
  throw new Error(`MCP_TRANSPORT must be stdio or http, got ${transport}`);
}
