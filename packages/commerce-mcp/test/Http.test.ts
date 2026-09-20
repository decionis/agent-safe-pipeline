import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import { CommerceGateHttpServer } from "../src/Http.js";
import { createMcpHandler, MCP_SERVER_BUSY_CODE } from "../src/Server.js";
import type { ToolDefinition } from "../src/Tools.js";

const echoTool: ToolDefinition = {
  name: "echo",
  title: "Echo",
  description: "Use this to echo a test value.",
  inputSchema: { type: "object" },
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  handler: async (args) => ({
    content: [{ type: "text", text: JSON.stringify(args) }],
    structuredContent: args,
  }),
};

let server: Server | null = null;

async function start(
  options: ConstructorParameters<typeof CommerceGateHttpServer>[1] = {},
  handler = createMcpHandler([echoTool]),
): Promise<string> {
  server = await new CommerceGateHttpServer(handler, {
    ...options,
    port: 0,
    host: "127.0.0.1",
  }).listen();
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}`;
}

async function post(base: string, body: unknown, headers: Record<string, string> = {}) {
  return fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

afterEach(async () => {
  await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
  server = null;
});

describe("CommerceGateHttpServer (streamable HTTP for AgentCore Runtime)", () => {
  it("answers /ping, initialize, tools/list and tools/call on POST /mcp, echoing the session", async () => {
    const base = await start();
    const ping = await fetch(`${base}/ping`);
    expect(ping.status).toBe(200);
    expect(await ping.json()).toEqual({ status: "Healthy" });

    const init = await post(
      base,
      { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } },
      { "mcp-session-id": "sess-1" },
    );
    expect(init.status).toBe(200);
    expect(init.headers.get("mcp-session-id")).toBe("sess-1");
    expect(init.headers.get("cache-control")).toBe("no-store");
    expect(await init.json()).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      result: { serverInfo: { name: "commercegate" }, capabilities: { tools: {} } },
    });

    const list = await post(base, { jsonrpc: "2.0", id: 2, method: "tools/list" });
    expect((await list.json()).result.tools.map((tool: { name: string }) => tool.name)).toEqual([
      "echo",
    ]);

    const call = await post(base, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "echo", arguments: { hello: "agentcore" } },
    });
    expect(call.status).toBe(200);
    expect((await call.json()).result.structuredContent).toEqual({ hello: "agentcore" });
  });

  it("answers a batch as a batch, and a notification-only post with 202", async () => {
    const base = await start();
    const batch = await post(base, [
      { jsonrpc: "2.0", id: "a", method: "ping" },
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: "b", method: "nope" },
    ]);
    expect(batch.status).toBe(200);
    const answers = await batch.json();
    expect(answers).toHaveLength(2);
    expect(answers[0]).toEqual({ jsonrpc: "2.0", id: "a", result: {} });
    expect(answers[1].error.code).toBe(-32601);

    const quiet = await post(base, { jsonrpc: "2.0", method: "notifications/initialized" });
    expect(quiet.status).toBe(202);
  });

  it("refuses what it must: other paths, other methods, other media, bad JSON, oversized bodies", async () => {
    const base = await start({ maximumRequestBytes: 256 });
    expect((await fetch(`${base}/anything`)).status).toBe(404);
    const get = await fetch(`${base}/mcp`);
    expect(get.status).toBe(405);
    expect(get.headers.get("allow")).toBe("POST");
    expect((await fetch(`${base}/mcp`, { method: "DELETE" })).status).toBe(405);
    expect((await fetch(`${base}/ping`, { method: "POST" })).status).toBe(405);
    expect(
      (
        await fetch(`${base}/mcp`, {
          method: "POST",
          headers: { "content-type": "text/plain" },
          body: "{}",
        })
      ).status,
    ).toBe(415);
    const bad = await post(base, "{not json");
    expect(bad.status).toBe(400);
    expect((await bad.json()).error.code).toBe(-32700);
    const big = await post(base, {
      jsonrpc: "2.0",
      id: 1,
      method: "ping",
      params: { pad: "x".repeat(300) },
    });
    expect(big.status).toBe(413);
    expect((await post(base, [])).status).toBe(400);
  });

  it("answers busy with 503 and Retry-After instead of queueing past the in-flight limit", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    const base = await start({ maximumInFlight: 1 }, async (message) => {
      await gate;
      return { jsonrpc: "2.0", id: (message as { id: unknown }).id, result: {} };
    });
    const first = post(base, { jsonrpc: "2.0", id: 1, method: "ping" });
    await new Promise((resolve) => setTimeout(resolve, 50));
    const second = await post(base, { jsonrpc: "2.0", id: 2, method: "ping" });
    expect(second.status).toBe(503);
    expect(second.headers.get("retry-after")).toBe("1");
    expect((await second.json()).error.code).toBe(MCP_SERVER_BUSY_CODE);
    release();
    expect((await first).status).toBe(200);
  });
});
