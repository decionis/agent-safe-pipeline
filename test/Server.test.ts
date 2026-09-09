import { PassThrough } from "node:stream";

import { describe, expect, it, vi } from "vitest";

import {
  COMMERCEGATE_MCP_INSTRUCTIONS,
  CommerceGateMcpHandler,
  CommerceGateStdioServer,
  MCP_SERVER_BUSY_CODE,
} from "../src/Server.js";
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

describe("CommerceGateMcpHandler", () => {
  it("initializes with the safety contract and supported protocol version", async () => {
    const handler = new CommerceGateMcpHandler([echoTool]);

    const response = await handler.handle({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18" },
    });

    expect(response).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-06-18",
        serverInfo: { name: "commercegate", version: "0.1.1" },
        instructions: COMMERCEGATE_MCP_INSTRUCTIONS,
      },
    });
    expect(COMMERCEGATE_MCP_INSTRUCTIONS).toContain("never accepts orders");
    expect(COMMERCEGATE_MCP_INSTRUCTIONS).toContain("hard-locked to SHADOW");
  });

  it("lists tool metadata and invokes a tool", async () => {
    const handler = new CommerceGateMcpHandler([echoTool]);

    const listed = await handler.handle({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    const called = await handler.handle({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "echo", arguments: { safe: true } },
    });

    expect(listed).toMatchObject({
      result: { tools: [{ name: "echo", title: "Echo", annotations: { readOnlyHint: true } }] },
    });
    expect(called).toMatchObject({
      result: { structuredContent: { safe: true } },
    });
  });

  it("returns no response for notifications and bounded JSON-RPC errors", async () => {
    const handler = new CommerceGateMcpHandler([echoTool]);

    await expect(
      handler.handle({ jsonrpc: "2.0", method: "notifications/initialized" }),
    ).resolves.toBeNull();
    await expect(
      handler.handle({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "missing" } }),
    ).resolves.toMatchObject({ error: { code: -32602, message: "Unknown tool: missing" } });
    await expect(handler.handle({ no: "rpc" })).resolves.toMatchObject({
      error: { code: -32600 },
    });
  });

  it("redacts an unexpected handler exception", async () => {
    const handler = new CommerceGateMcpHandler([
      {
        ...echoTool,
        handler: async () => {
          throw new Error("credential=top-secret-key");
        },
      },
    ]);

    const response = await handler.handle({
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: { name: "echo" },
    });
    const serialized = JSON.stringify(response);

    expect(serialized).toContain("UNEXPECTED_FAILURE");
    expect(serialized).not.toContain("top-secret-key");
  });
});

describe("CommerceGateStdioServer", () => {
  it("handles newline-delimited JSON and drains before EOF", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    let written = "";
    output.on("data", (chunk) => {
      written += chunk.toString();
    });
    const handler = new CommerceGateMcpHandler([echoTool]);
    const running = CommerceGateStdioServer.run((message) => handler.handle(message), {
      input,
      output,
    });

    input.end(`${JSON.stringify({ jsonrpc: "2.0", id: 9, method: "ping" })}\n`);
    await running;

    expect(JSON.parse(written)).toEqual({ jsonrpc: "2.0", id: 9, result: {} });
  });

  it("rejects an oversized frame before parsing it and resumes at the next newline", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    let written = "";
    output.on("data", (chunk) => {
      written += chunk.toString();
    });
    const handler = vi.fn(async (message: unknown) => {
      const id = typeof message === "object" && message && "id" in message ? message.id : null;
      return { jsonrpc: "2.0", id, result: {} };
    });
    const running = CommerceGateStdioServer.run(handler, {
      input,
      output,
      maximumRequestBytes: 64,
    });
    const valid = JSON.stringify({ jsonrpc: "2.0", id: 10, method: "ping" });

    input.end(`${"x".repeat(65)}\n${valid}\n`);
    await running;

    const responses = written
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(responses).toEqual([
      {
        jsonrpc: "2.0",
        id: null,
        error: { code: -32600, message: "Request exceeds the 1 MiB safety limit" },
      },
      { jsonrpc: "2.0", id: 10, result: {} },
    ]);
    expect(handler).toHaveBeenCalledOnce();
  });

  it("returns a fail-closed busy error instead of exceeding the in-flight cap", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    let written = "";
    let releaseFirst!: () => void;
    let markFirstStarted!: () => void;
    let markBusyWritten!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const firstStarted = new Promise<void>((resolve) => {
      markFirstStarted = resolve;
    });
    const busyWritten = new Promise<void>((resolve) => {
      markBusyWritten = resolve;
    });
    output.on("data", (chunk) => {
      written += chunk.toString();
      if (written.includes(`"code":${MCP_SERVER_BUSY_CODE}`)) markBusyWritten();
    });
    const handler = vi.fn(async (message: unknown) => {
      const id = typeof message === "object" && message && "id" in message ? message.id : null;
      markFirstStarted();
      await firstGate;
      return { jsonrpc: "2.0", id, result: {} };
    });
    const running = CommerceGateStdioServer.run(handler, {
      input,
      output,
      maximumInFlight: 1,
    });

    input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 11, method: "ping" })}\n`);
    await firstStarted;
    input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 12, method: "ping" })}\n`);
    await busyWritten;
    input.end();
    releaseFirst();
    await running;

    const responses = written
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(responses).toEqual(
      expect.arrayContaining([
        { jsonrpc: "2.0", id: 11, result: {} },
        {
          jsonrpc: "2.0",
          id: 12,
          error: {
            code: MCP_SERVER_BUSY_CODE,
            message: "CommerceGate is busy. The request was not processed; retry later.",
          },
        },
      ]),
    );
    expect(handler).toHaveBeenCalledOnce();
  });
});
