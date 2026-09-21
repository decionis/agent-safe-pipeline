import type { AddressInfo } from "node:net";
import { request, type IncomingMessage, type Server } from "node:http";

import { afterEach, describe, expect, it, vi } from "vitest";

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
  server?.closeAllConnections();
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
    expect(await list.json()).toMatchObject({ result: { tools: [{ name: "echo" }] } });

    const call = await post(base, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "echo", arguments: { hello: "agentcore" } },
    });
    expect(call.status).toBe(200);
    expect(await call.json()).toMatchObject({
      result: { structuredContent: { hello: "agentcore" } },
    });
  });

  it("rejects small and amplification-sized batches without calling a handler", async () => {
    const handler = vi.fn(createMcpHandler([echoTool]));
    const base = await start({}, handler);
    for (const messages of [
      [],
      [{ jsonrpc: "2.0", id: 1, method: "tools/list" }],
      Array.from({ length: 20_000 }, () => ({ jsonrpc: "2.0", id: 1, method: "tools/list" })),
    ]) {
      const batch = await post(base, messages);
      expect(batch.status).toBe(400);
      expect(await batch.json()).toMatchObject({ error: { code: -32600 } });
    }
    expect(handler).not.toHaveBeenCalled();
  });

  it("answers a notification-only post with 202 and no body", async () => {
    const base = await start();
    const quiet = await post(base, { jsonrpc: "2.0", method: "notifications/initialized" });
    expect(quiet.status).toBe(202);
    expect(await quiet.text()).toBe("");
  });

  it("rejects every browser Origin before invoking any handler", async () => {
    const handler = vi.fn(createMcpHandler([echoTool]));
    const base = await start({}, handler);
    for (const origin of ["https://untrusted.invalid", "http://localhost", "null", ""]) {
      const response = await post(base, { jsonrpc: "2.0", id: 1, method: "ping" }, { origin });
      expect(response.status).toBe(403);
      expect(response.headers.get("access-control-allow-origin")).toBeNull();
      expect((await fetch(`${base}/ping`, { headers: { origin } })).status).toBe(403);
    }
    expect(handler).not.toHaveBeenCalled();
    expect((await post(base, { jsonrpc: "2.0", id: 1, method: "ping" })).status).toBe(200);
  });

  it("validates explicit HTTP protocol versions and retains the missing-header fallback", async () => {
    const handler = vi.fn(createMcpHandler([echoTool]));
    const base = await start({}, handler);
    for (const protocol of ["2024-11-05", "2099-01-01", "", "2025-11-25, 2025-06-18"]) {
      const response = await post(
        base,
        { jsonrpc: "2.0", id: 1, method: "ping" },
        { "mcp-protocol-version": protocol },
      );
      expect(response.status).toBe(400);
    }
    expect(handler).not.toHaveBeenCalled();
    for (const protocol of ["2025-03-26", "2025-06-18", "2025-11-25"]) {
      const response = await post(
        base,
        { jsonrpc: "2.0", id: 1, method: "ping" },
        { "mcp-protocol-version": protocol },
      );
      expect(response.status).toBe(200);
    }
    expect((await post(base, { jsonrpc: "2.0", id: 1, method: "ping" })).status).toBe(200);
    const legacy = await post(base, {
      jsonrpc: "2.0",
      id: 2,
      method: "initialize",
      params: { protocolVersion: "2024-11-05" },
    });
    expect(await legacy.json()).toMatchObject({ result: { protocolVersion: "2025-11-25" } });
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
    expect(await bad.json()).toMatchObject({ error: { code: -32700 } });
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
    let enter: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    const entered = new Promise<void>((resolve) => (enter = resolve));
    const base = await start({ maximumInFlight: 1 }, async (message) => {
      enter();
      await gate;
      return { jsonrpc: "2.0", id: (message as { id: unknown }).id, result: {} };
    });
    const first = post(base, { jsonrpc: "2.0", id: 1, method: "ping" });
    await entered;
    const second = await post(base, { jsonrpc: "2.0", id: 2, method: "ping" });
    expect(second.status).toBe(503);
    expect(second.headers.get("retry-after")).toBe("1");
    expect(await second.json()).toMatchObject({ error: { code: MCP_SERVER_BUSY_CODE } });
    release();
    expect((await first).status).toBe(200);
  });

  it("counts unfinished uploads as in-flight and releases admission when they abort", async () => {
    const handler = vi.fn(createMcpHandler([echoTool]));
    const base = await start({ maximumInFlight: 1 }, handler);
    const arriving = new Promise<IncomingMessage>((resolve) => server?.once("request", resolve));
    const upload = request(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": "100" },
    });
    upload.on("error", () => {});
    upload.write("{");
    const incoming = await arriving;
    const blocked = await post(base, { jsonrpc: "2.0", id: 2, method: "ping" });
    expect(blocked.status).toBe(503);
    expect(blocked.headers.get("retry-after")).toBe("1");
    expect(handler).not.toHaveBeenCalled();
    const aborted = new Promise<void>((resolve) => incoming.once("aborted", resolve));
    upload.destroy();
    await aborted;
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect((await post(base, { jsonrpc: "2.0", id: 3, method: "ping" })).status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("releases admission after parse errors, oversized streamed bodies, and handler failures", async () => {
    const handler = vi.fn(createMcpHandler([echoTool]));
    const base = await start({ maximumInFlight: 1, maximumRequestBytes: 128 }, handler);
    expect((await post(base, "{not json")).status).toBe(400);
    const oversizedStatus = await new Promise<number | undefined>((resolve, reject) => {
      const upload = request(
        `${base}/mcp`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
        },
        (response) => {
          response.resume();
          response.once("end", () => resolve(response.statusCode));
        },
      );
      upload.on("error", reject);
      upload.write("{");
      upload.end("x".repeat(256));
    });
    expect(oversizedStatus).toBe(413);
    handler.mockRejectedValueOnce(new Error("synthetic failure"));
    const failure = await post(base, { jsonrpc: "2.0", id: 1, method: "ping" });
    expect(await failure.json()).toMatchObject({ error: { code: -32603 } });
    expect((await post(base, { jsonrpc: "2.0", id: 2, method: "ping" })).status).toBe(200);
  });

  it("keeps serving after malformed request targets and disconnected request bodies", async () => {
    const base = await start();
    const malformedStatus = await new Promise<number | undefined>((resolve, reject) => {
      const malformed = request(base, { path: "//[" }, (response) => {
        response.resume();
        response.on("end", () => resolve(response.statusCode));
      });
      malformed.on("error", reject);
      malformed.end();
    });
    expect(malformedStatus).toBe(400);

    await new Promise<void>((resolve) => {
      const interrupted = request(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", "content-length": "100" },
      });
      interrupted.on("error", () => {});
      interrupted.on("close", resolve);
      interrupted.write("{");
      setTimeout(() => interrupted.destroy(), 20);
    });
    expect((await fetch(`${base}/ping`)).status).toBe(200);
  });
});
