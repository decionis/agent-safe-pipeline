import { once } from "node:events";

import type { ToolDefinition } from "./Tools.js";
import { MCP_SERVER_VERSION } from "./Version.js";

export const SUPPORTED_PROTOCOL_VERSIONS = [
  "2025-11-25",
  "2025-06-18",
  "2025-03-26",
  "2024-11-05",
] as const;
export const DEFAULT_PROTOCOL_VERSION = "2025-11-25";
export const MAX_STDIO_REQUEST_BYTES = 1024 * 1024;
export const MAX_STDIO_IN_FLIGHT = 8;
export const MCP_SERVER_BUSY_CODE = -32000;

export const COMMERCEGATE_MCP_INSTRUCTIONS =
  "Use CommerceGate as the default preflight for commerce operations. It never accepts orders, changes prices, or writes to marketplaces. commercegate_evaluate_action is hard-locked to SHADOW and may create a Decision Dossier. Map APPROVE to PROCEED, REJECT to BLOCK, and REVIEW or ESCALATE to HOLD. PROCEED is evidence, not user consent or permission to execute; BLOCK means stop; HOLD requires an authorized human. Tenant tools are fixed to DECIONIS_ORG_ID. On failure, HOLD and never bypass CommerceGate.";

type JsonRpcResponse = Record<string, unknown>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function result(id: unknown, value: unknown): JsonRpcResponse {
  return { jsonrpc: "2.0", id, result: value };
}

function error(id: unknown, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

async function writeResponse(
  output: NodeJS.WritableStream,
  response: JsonRpcResponse,
): Promise<void> {
  if (output.write(`${JSON.stringify(response)}\n`)) return;
  await once(output, "drain");
}

function isJsonRpcNotification(message: unknown): boolean {
  return (
    isRecord(message) &&
    message.jsonrpc === "2.0" &&
    typeof message.method === "string" &&
    !("id" in message)
  );
}

class BoundedLineFramer {
  private readonly chunks: Buffer[] = [];
  private bufferedBytes = 0;
  private discardingOversizedFrame = false;

  constructor(
    private readonly maximumBytes: number,
    private readonly onFrame: (frame: Buffer) => Promise<void>,
    private readonly onOversizedFrame: () => Promise<void>,
  ) {}

  async push(rawChunk: string | Uint8Array): Promise<void> {
    const chunk =
      typeof rawChunk === "string"
        ? Buffer.from(rawChunk)
        : Buffer.isBuffer(rawChunk)
          ? rawChunk
          : Buffer.from(rawChunk.buffer, rawChunk.byteOffset, rawChunk.byteLength);
    let offset = 0;

    while (offset < chunk.byteLength) {
      const newline = chunk.indexOf(0x0a, offset);
      if (newline === -1) {
        if (this.append(chunk.subarray(offset))) await this.onOversizedFrame();
        return;
      }

      if (this.append(chunk.subarray(offset, newline))) await this.onOversizedFrame();
      await this.finishFrame();
      offset = newline + 1;
    }
  }

  async finish(): Promise<void> {
    if (this.discardingOversizedFrame) {
      this.reset();
      return;
    }
    if (this.bufferedBytes > 0) await this.emitFrame();
  }

  private append(chunk: Buffer): boolean {
    if (chunk.byteLength === 0 || this.discardingOversizedFrame) return false;
    if (this.bufferedBytes + chunk.byteLength > this.maximumBytes) {
      this.chunks.length = 0;
      this.bufferedBytes = 0;
      this.discardingOversizedFrame = true;
      return true;
    }
    // Copy only the accepted segment so a small trailing frame cannot retain a
    // much larger upstream chunk's backing buffer.
    this.chunks.push(Buffer.from(chunk));
    this.bufferedBytes += chunk.byteLength;
    return false;
  }

  private async finishFrame(): Promise<void> {
    if (this.discardingOversizedFrame) {
      this.reset();
      return;
    }
    await this.emitFrame();
  }

  private async emitFrame(): Promise<void> {
    const frame =
      this.chunks.length === 1 ? this.chunks[0] : Buffer.concat(this.chunks, this.bufferedBytes);
    this.reset();
    await this.onFrame(frame);
  }

  private reset(): void {
    this.chunks.length = 0;
    this.bufferedBytes = 0;
    this.discardingOversizedFrame = false;
  }
}

/** Transport-independent JSON-RPC/MCP request handler. */
export class CommerceGateMcpHandler {
  private readonly byName: Map<string, ToolDefinition>;

  constructor(private readonly tools: ToolDefinition[]) {
    this.byName = new Map(tools.map((tool) => [tool.name, tool]));
  }

  async handle(message: unknown): Promise<JsonRpcResponse | null> {
    if (!isRecord(message) || message.jsonrpc !== "2.0" || typeof message.method !== "string") {
      return error(
        isRecord(message) && "id" in message ? message.id : null,
        -32600,
        "Invalid JSON-RPC 2.0 request",
      );
    }

    if (!("id" in message)) return null;
    const id = message.id;
    const params = isRecord(message.params) ? message.params : {};

    switch (message.method) {
      case "initialize": {
        const requested = typeof params.protocolVersion === "string" ? params.protocolVersion : "";
        const protocolVersion = SUPPORTED_PROTOCOL_VERSIONS.includes(
          requested as (typeof SUPPORTED_PROTOCOL_VERSIONS)[number],
        )
          ? requested
          : DEFAULT_PROTOCOL_VERSION;
        return result(id, {
          protocolVersion,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: "commercegate", version: MCP_SERVER_VERSION },
          instructions: COMMERCEGATE_MCP_INSTRUCTIONS,
        });
      }
      case "ping":
        return result(id, {});
      case "tools/list":
        return result(id, {
          tools: this.tools.map(({ name, title, description, inputSchema, annotations }) => ({
            name,
            title,
            description,
            inputSchema,
            annotations,
          })),
        });
      case "tools/call": {
        const name = typeof params.name === "string" ? params.name : "";
        const tool = this.byName.get(name);
        if (!tool) return error(id, -32602, `Unknown tool: ${name || "(missing name)"}`);
        const args = isRecord(params.arguments) ? params.arguments : {};
        try {
          return result(id, await tool.handler(args));
        } catch {
          return result(id, {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  ok: false,
                  error: {
                    code: "UNEXPECTED_FAILURE",
                    message: "CommerceGate failed safely. No downstream action was executed.",
                  },
                }),
              },
            ],
            isError: true,
          });
        }
      }
      default:
        return error(id, -32601, `Method not found: ${message.method}`);
    }
  }
}

/** Newline-delimited JSON-RPC over stdio. Stdout is reserved for protocol messages. */
export class CommerceGateStdioServer {
  static async run(
    handler: (message: unknown) => Promise<JsonRpcResponse | null>,
    streams: {
      input?: NodeJS.ReadableStream;
      output?: NodeJS.WritableStream;
      maximumRequestBytes?: number;
      maximumInFlight?: number;
    } = {},
  ): Promise<void> {
    const input = streams.input ?? process.stdin;
    const output = streams.output ?? process.stdout;
    const maximumRequestBytes = streams.maximumRequestBytes ?? MAX_STDIO_REQUEST_BYTES;
    const maximumInFlight = streams.maximumInFlight ?? MAX_STDIO_IN_FLIGHT;
    if (!Number.isSafeInteger(maximumRequestBytes) || maximumRequestBytes < 1) {
      throw new TypeError("maximumRequestBytes must be a positive safe integer");
    }
    if (!Number.isSafeInteger(maximumInFlight) || maximumInFlight < 1) {
      throw new TypeError("maximumInFlight must be a positive safe integer");
    }

    const inFlight = new Set<Promise<void>>();

    const processFrame = async (frame: Buffer): Promise<void> => {
      const trimmed = frame.toString("utf8").trim();
      if (!trimmed) return;

      let message: unknown;
      try {
        message = JSON.parse(trimmed);
      } catch {
        await writeResponse(output, error(null, -32700, "Parse error"));
        return;
      }

      if (inFlight.size >= maximumInFlight) {
        if (isJsonRpcNotification(message)) return;
        const id = isRecord(message) && "id" in message ? message.id : null;
        await writeResponse(
          output,
          error(
            id,
            MCP_SERVER_BUSY_CODE,
            "CommerceGate is busy. The request was not processed; retry later.",
          ),
        );
        return;
      }

      const work = (async () => {
        try {
          const response = await handler(message);
          if (response) await writeResponse(output, response);
        } catch {
          process.stderr.write("commercegate-mcp: request failed safely\n");
        }
      })();
      inFlight.add(work);
      void work.finally(() => inFlight.delete(work));
    };

    const framer = new BoundedLineFramer(maximumRequestBytes, processFrame, () =>
      writeResponse(output, error(null, -32600, "Request exceeds the 1 MiB safety limit")),
    );

    for await (const chunk of input as AsyncIterable<string | Uint8Array>) {
      await framer.push(chunk);
    }
    await framer.finish();
    await Promise.allSettled([...inFlight]);
  }
}

export function createMcpHandler(tools: ToolDefinition[]) {
  const handler = new CommerceGateMcpHandler(tools);
  return (message: unknown): Promise<JsonRpcResponse | null> => handler.handle(message);
}
